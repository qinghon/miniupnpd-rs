use crate::asyncsendto::{scheduled_send, sendto_or_schedule};
use crate::options::{Options, RtOptions};
use crate::upnpglobalvars::*;
use crate::upnppermissions::check_upnp_rule_against_permissions;
use crate::upnpredirect::{_upnp_delete_redir, upnp_redirect};
use crate::upnputils::{proto_itoa, upnp_time};
use crate::warp::recv_from_if;
use crate::*;
use socket2::Socket;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::rc::Rc;

pub const NATPMP_PORT: u16 = 5351;
pub const NATPMP_NOTIF_PORT: u16 = 5350;
pub const NATPMP_NOTIF_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);

pub fn OpenAndConfNATPMPSocket(addr: Ipv4Addr) -> io::Result<Socket> {
	let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;

	sock.set_reuse_address(true)?;
	sock.set_nonblocking(true)?;
	sock.bind(&SocketAddr::new(addr.into(), NATPMP_PORT).into())?;
	Ok(sock)
}

pub fn OpenAndConfNATPMPSockets(v: &Options) -> io::Result<Vec<Socket>> {
	let mut socks = Vec::with_capacity(v.listening_ip.len());
	for addr in v.listening_ip.iter() {
		socks.push(OpenAndConfNATPMPSocket(addr.addr)?);
	}
	Ok(socks)
}
#[cfg(not(feature = "multiple_ext_ip"))]
fn FillPublicAddressResponse(resp: &mut [u8], _senderaddr: Ipv4Addr) {
	use crate::getifaddr::{addr_is_reserved, getifaddr};
	let v = global_option.get().unwrap();
	if let Some(use_ext_ip) = v.ext_ip.as_ref() {
		resp[8..12].copy_from_slice(use_ext_ip.as_octets())
	} else {
		if v.ext_ifname.is_empty() {
			resp[3] = 3;
		}
		let mut ip = Ipv4Addr::UNSPECIFIED;
		if getifaddr(&v.ext_ifname, &mut ip, None) == 0 {
			if addr_is_reserved(&ip) && !GETFLAG!(v.runtime_flags, IGNOREPRIVATEIPMASK) {
				resp[3] = 3;
				return;
			}
			resp[8..12].copy_from_slice(ip.as_octets());
		} else {
			error!("Failed to get IP for interface {}", v.ext_ifname);
			resp[3] = 3;
		}
	}
}
#[cfg(feature = "multiple_ext_ip")]
fn FillPublicAddressResponse(resp: &mut [u8], senderaddr: Ipv4Addr) {
	let op = global_option.get().unwrap();
	if senderaddr.is_unspecified() {
		return;
	}
	for lan in &op.listening_ip {
		if senderaddr & lan.mask == lan.addr & lan.mask {
			resp[8..12].copy_from_slice(lan.ext_ip_addr.as_octets());
			return;
		}
	}
}

pub fn ReceiveNATPMPOrPCPPacket(
	s: &impl AsRawFd,
	senderaddr: &mut SocketAddr,
	receiveraddr: Option<&mut SocketAddrV6>,
	msg_buff: &mut [u8],
) -> Result<usize, io::Error> {
	let (raddr, laddr, ifindex, l) = recv_from_if(s, msg_buff)?;
	senderaddr.set_ip(raddr.ip());
	senderaddr.set_port(raddr.port());
	if let Some(recvaddr) = receiveraddr {
		if let Some(laddr) = laddr {
			recvaddr.set_scope_id(ifindex);
			match laddr {
				IpAddr::V4(_) => {}
				IpAddr::V6(v6addr) => {
					recvaddr.set_ip(v6addr);
				}
			}
		}
	}
	Ok(l)
}

pub fn ProcessIncomingNATPMPPacket(
	v: &Options,
	rt: &mut RtOptions,
	send_list: &mut Vec<scheduled_send>,
	s: &Rc<Socket>,
	msg_buff: &[u8],
	senderaddr: SocketAddrV4,
) {
	let req = msg_buff;
	let n = msg_buff.len();
	let mut resp = [0u8; 32];
	let mut _resp_len;
	info!("NAT-PMP request received from {} {} bytes", senderaddr, msg_buff.len());

	if n < 2 || ((req[1] != 0) && n < 12) {
		warn!("discarding NAT-PMP request (too short) {}Bytes", n);
		return;
	}
	if req[1] & 128 != 0 {
		// discarding NAT-PMP responses silently
		return;
	}
	_resp_len = 8;
	resp[1] = 128 + req[1];
	if rt.epoch_origin.is_zero() {
		rt.epoch_origin = *startup_time.get().unwrap();
	}
	resp[4..8].copy_from_slice(&((upnp_time() - rt.epoch_origin).as_secs() as u32).to_be_bytes());

	'send: {
		if req[0] > 0 {
			warn!("unsupported NAT-PMP version : {}", req[0]);
			resp[3] = 1;
			break 'send;
		}
		if !matches!(req[1], 0..=2) {
			// Unsupported OPCODE
			resp[3] = 5;
			break 'send;
		}
		// Public address request
		if req[1] == 0 {
			info!("NAT-PMP public address request");
			FillPublicAddressResponse(&mut resp, *senderaddr.ip());
			_resp_len = 12;
			break 'send;
		}

		// udp and tcp
		let iport = u16::from_be_bytes([req[4], req[5]]);
		let eport = u16::from_be_bytes([req[6], req[7]]);
		let lifetime = u32::from_be_bytes([req[8], req[9], req[10], req[11]]);
		let proto = if req[1] == 1 { UDP } else { TCP };
		let proto_str = proto_itoa(proto);
		info!(
			"NAT-PMP port mapping request : {}=>{}:{} {} lifetime={}",
			eport,
			senderaddr.ip(),
			iport,
			proto_str,
			lifetime
		);
		if lifetime == 0 {
			while let Some(entry) = rt.nat_impl.get_redirect_rule(|x| {
				x.daddr.as_octets() == senderaddr.ip().as_octets()
					&& x.desc.as_ref().map(|x| x.as_str()).unwrap_or_default().starts_with("NAT-PMP")
			}) {
				if entry.dport == 0 || ((iport == entry.dport) && (proto == entry.proto)) {
					let r = _upnp_delete_redir(rt, eport, proto);
					if r < 0 {
						error!("Failed to remove NAT-PMP mapping eport {}, protocol {}", eport, proto);
						//  Not Authorized/Refused
						resp[3] = 2;
					} else {
						info!("NAT-PMP {} port {} mapping removed", proto_str, eport);
					}
				}
			}
		} else if iport == 0 {
			resp[3] = 2; /* Not Authorized/Refused */
		} else {
			let mut eport = iport;
			let mut eport_first = 0;
			let mut any_eport_allowed = false;
			#[cfg(feature = "portinuse")]
			let op = global_option.get().unwrap();
			while resp[3] == 0 {
				if eport_first == 0 {
					// first time in loop
					eport_first = eport;
				} else if eport == eport_first {
					//  no eport available
					if !any_eport_allowed {
						error!(
							"No allowed eport for NAT-PMP {} {}->{}:{}",
							eport,
							proto_str,
							senderaddr.ip(),
							iport
						);
						resp[3] = 2; /* Not Authorized/Refused */
					} else {
						error!(
							"Failed to find available eport for NAT-PMP {} {}->{}:{}",
							eport,
							proto_str,
							senderaddr.ip(),
							iport
						);
						resp[3] = 4; /* Out of resources */
					}
					break;
				}
				if !check_upnp_rule_against_permissions(&v.upnpperms, eport, *senderaddr.ip(), iport, "NAT-PMP") {
					eport += 1;
					if eport == 0 {
						/* skip port zero */
						eport += 1
					}
					continue;
				}
				any_eport_allowed = true;
				#[cfg(feature = "portinuse")]
				{
					if rt.os.port_in_use(&rt.nat_impl, &op.ext_ifname, eport, proto, senderaddr.ip(), iport) > 0 {
						info!("port {} protocol {} already in use", eport, proto_itoa(proto));
						eport += 1;
						if eport == 0 {
							eport += 1
						}
						continue;
					}
				}

				if let Some(entry) = rt.nat_impl.get_redirect_rule(|x| x.sport == eport && x.proto == proto) {
					if entry.daddr.octets() == senderaddr.ip().octets() && iport == entry.dport {
						info!(
							"port {} {} already redirected to {}:{}, replacing",
							eport, proto_str, entry.daddr, entry.dport
						);
						if _upnp_delete_redir(rt, eport, proto) < 0 {
							error!("failed to remove port mapping");
							break;
						}
					} else {
						eport += 1;
						if eport == 0 {
							eport += 1
						}
						continue;
					}
				}

				// do the redirection
				let timestamp = upnp_time().as_secs() + lifetime as u64;
				let desc = format!("NAT-PMP {} {}", eport, proto_str);
				if upnp_redirect(
					rt,
					None,
					*senderaddr.ip(),
					eport,
					iport,
					proto,
					Some(desc.as_str()),
					timestamp as _,
				) < 0
				{
					error!(
						"Failed to add NAT-PMP {} {}->{}:{} '{}'",
						eport,
						proto_str,
						senderaddr.ip(),
						iport,
						desc
					);
					resp[3] = 3;
				}
				break;
			}
		}
		resp[8..10].copy_from_slice(iport.to_be_bytes().as_ref());
		resp[10..12].copy_from_slice(eport.to_be_bytes().as_ref());
		resp[12..16].copy_from_slice(lifetime.to_be_bytes().as_ref());
		_resp_len = 16;
	}
	match sendto_or_schedule(send_list, s, &resp, 0, senderaddr.into()) {
		Ok(n) => {
			if n < _resp_len {
				error!("sendto(natpmp): sent only {} bytes out of {}", n, _resp_len);
			}
		}
		Err(_) => {
			error!("sendto(natpmp): %m");
		}
	}
}

pub fn SendNATPMPPublicAddressChangeNotification(
	send_list: &mut Vec<scheduled_send>,
	rt: &mut RtOptions,
	sockets: &[Rc<Socket>],
) {
	let mut notif: [u8; 12] = [0; 12];

	notif[1] = 128; // op code
	if rt.epoch_origin == Default::default() {
		rt.epoch_origin = *startup_time.get().unwrap();
	}
	notif[4..8].copy_from_slice(((upnp_time() - rt.epoch_origin).as_secs() as u32).to_be_bytes().as_ref());
	FillPublicAddressResponse(&mut notif, Ipv4Addr::UNSPECIFIED);
	if notif[3] != 0 {
		warn!("SendNATPMPPublicAddressChangeNotification: cannot get public IP address, stopping");
		return;
	}
	let send_name = SocketAddrV4::new(NATPMP_NOTIF_ADDR, NATPMP_PORT);
	let send_name2 = SocketAddrV4::new(NATPMP_NOTIF_ADDR, NATPMP_NOTIF_PORT);
	for socket in sockets {
		if let Err(e) = sendto_or_schedule(send_list, socket, &notif, 0, send_name.into()) {
			error!(
				"SendNATPMPPublicAddressChangeNotification: sendto(s_udp={}, port={}): {}",
				socket.as_raw_fd(),
				NATPMP_PORT,
				e
			);
			return;
		}

		if let Err(e) = sendto_or_schedule(send_list, socket, &notif, 0, send_name2.into()) {
			error!(
				"SendNATPMPPublicAddressChangeNotification: sendto(s_udp={}, port={}): {}",
				socket.as_raw_fd(),
				NATPMP_NOTIF_PORT,
				e
			);
			return;
		}
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_natpmp_packet_parse() {}
}
