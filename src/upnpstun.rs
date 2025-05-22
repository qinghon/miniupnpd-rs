use crate::warp::{FdSet, IfName, make_timeval, select};
use crate::{Backend, MapEntry, UDP, debug, error, info, nat_impl, notice, warn};
pub use libc::IPPROTO_UDP;
use socket2::Socket;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::random::random;
use std::rc::Rc;
use std::time::Duration;
use std::{io, mem};

fn generate_transaction_id(transaction_id: &mut [u8]) {
	let id1: u32 = random();
	let id2: u32 = random();
	let id3: u32 = random();
	transaction_id[0..4].copy_from_slice(&id1.to_ne_bytes());
	transaction_id[4..8].copy_from_slice(&id2.to_ne_bytes());
	transaction_id[8..12].copy_from_slice(&id3.to_ne_bytes());
}
fn fill_request(buffer: &mut [u8; 28], change_ip: bool, change_port: bool) {
	// Type: Binding Request
	buffer[0] = 0;
	buffer[1] = 0x1;
	// Length: One 8-byte attribute
	buffer[2] = 0;
	buffer[3] = 0x8;
	// RFC5389 Magic Cookie: 0x2120A442
	buffer[4] = 0x21;
	buffer[5] = 0x12;
	buffer[6] = 0xa4;
	buffer[7] = 0x42;
	// Transaction Id
	generate_transaction_id(&mut buffer[8..20]);
	// Attribute Type: Change Request
	buffer[20] = 0;
	buffer[21] = 0x3;
	// Attribute Length: 4 bytes
	buffer[22] = 0;
	buffer[23] = 0x4;

	buffer[24] = 0;
	buffer[25] = 0;
	buffer[26] = 0;
	buffer[27] = 0;

	buffer[27] |= if change_ip { 0x4 } else { 0 };
	buffer[27] |= if change_port { 0x2 } else { 0 };
}
pub fn resolve_stun_host(stun_host: &str, stun_port: u16) -> io::Result<SocketAddrV4> {
	let stun_port = if stun_port != 0 { stun_port } else { 3478 };

	let mut addrs = (stun_host, stun_port).to_socket_addrs()?;

	if let Some(SocketAddrV4) = addrs.find_map(|addr| if let SocketAddr::V4(v4) = addr { Some(v4) } else { None }) {
		Ok(SocketAddrV4)
	} else {
		Err(io::ErrorKind::AddrNotAvailable.into())
	}
}
/// Create a new UDP socket for STUN connection and return file descriptor and local UDP port
pub fn stun_socket() -> io::Result<(UdpSocket, u16)> {
	let socket = Socket::new(
		socket2::Domain::IPV4,
		socket2::Type::DGRAM,
		Some(socket2::Protocol::UDP),
	)?;

	let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
	socket.bind(&addr.into())?;

	let local_addr: SocketAddrV4 = socket.local_addr()?.as_socket_ipv4().unwrap();
	let local_port = local_addr.port();

	Ok((socket.into(), local_port))
}

fn receive_stun_response(
	fd: &UdpSocket,
	buffer: &mut [u8],
	transaction_id: &[u8],
	peer_addr: &mut SocketAddrV4,
) -> usize {
	match fd.recv_from(buffer) {
		Ok((len, addr)) => {
			if len < 20 {
				warn!("receive_stun_response: response too short : {}", len);
				return 0;
			}
			if !addr.is_ipv4() {
				error!("receive_stun_response: recvfrom(): peer_addr_len mismatch");
				return 0;
			}
			if buffer[0] != 1 || buffer[1] & 0xEF != 1 {
				warn!(
					"receive_stun_response: STUN message type is 0x{:02x}{:02x}",
					buffer[0], buffer[1]
				);
				return 0;
			}
			if buffer[8..20] != transaction_id[0..12] {
				warn!("receive_stun_response: transaction_id mismatch");
				return 0;
			}
			*peer_addr = match addr {
				SocketAddr::V4(addr) => addr,
				SocketAddr::V6(_) => unreachable!(),
			};
			len
		}
		Err(e) => {
			error!("receive_stun_response: recv_from(): {}", e);
			0
		}
	}
}
fn wait_for_stun_responses(
	fds: &[UdpSocket; 4],
	transaction_ids: &[&[u8]; 4],
	buffers: &mut [[u8; 1024]; 4],
	peer_addrs: &mut [SocketAddrV4; 4],
	lens: &mut [usize; 4],
) -> i32 {
	let mut timeout = make_timeval(Duration::from_secs(3));
	let mut raw_fds: [RawFd; 4] = [-1; 4];
	for i in 0..fds.len() {
		raw_fds[i] = fds[i].as_raw_fd();
	}

	while timeout.tv_sec > 0 || timeout.tv_usec > 0 {
		let mut fdset = FdSet::default();
		for sock in raw_fds {
			fdset.set(sock);
		}
		debug!(
			"wait_for_stun_responses: waiting {} secs and {} usecs",
			timeout.tv_sec, timeout.tv_usec
		);
		match select(
			*(raw_fds.iter().max().unwrap()) as _,
			Some(&mut fdset),
			None,
			None,
			Some(&mut timeout),
		) {
			Err(e) => {
				if e.kind() == io::ErrorKind::Interrupted {
					continue;
				} else {
					error!("wait_for_stun_responses: select failed: {}", e);
					return -1;
				}
			}
			Ok(0) => {
				debug!("wait_for_stun_responses: select(): no more responses");
				return 0;
			}
			Ok(_) => {
				for i in 0..4 {
					if fdset.is_set(raw_fds[i]) {
						lens[i] =
							receive_stun_response(&fds[i], &mut buffers[i], transaction_ids[i], &mut peer_addrs[i])
					}
				}
				debug!(
					"wait_for_stun_responses: received response: {}",
					lens.iter().map(|x| (*x != 0) as u8).sum::<u8>()
				);
				if lens.iter().all(|x| *x != 0) {
					return 0;
				}
			}
		}
	}
	0
}

pub fn parse_stun_response(buffer: &[u8]) -> Option<SocketAddrV4> {
	if buffer.len() < 20 {
		return None;
	}

	let message_type = u16::from_be_bytes([buffer[0], buffer[1]]);
	let message_length = u16::from_be_bytes([buffer[2], buffer[3]]);
	let magic_cookie = &buffer[4..8];

	debug!(
		"parse_stun_response: Type 0x{:04x}, Length {}, Magic Cookie {:02x}{:02x}{:02x}{:02x}",
		message_type, message_length, magic_cookie[0], magic_cookie[1], magic_cookie[2], magic_cookie[3]
	);

	if buffer[0] != 0x01 || (buffer[1] & 0xEF) != 0x01 {
		return None;
	}

	if (message_length as usize) + 20 > buffer.len() {
		error!("parse_stun_response: truncated STUN response");
		return None;
	}

	// let mut have_address = false;
	let mut have_xor_mapped_address = false;
	let mut mapped_addr = None;

	let mut ptr = &buffer[20..];
	// let end = &buffer[buffer.len()..]; // buffer end

	while ptr.len() >= 4 {
		let attr_type = u16::from_be_bytes(ptr[0..2].try_into().unwrap());
		let attr_len = u16::from_be_bytes(ptr[2..4].try_into().unwrap());
		ptr = &ptr[4..]; // skip past the header

		if ptr.len() < attr_len as usize {
			warn!("parse_stun_response: truncated attribute");
			break;
		}

		match attr_type {
			0x0001 | 0x0020 | 0x8020 => {
				if attr_len == 8 && ptr[1] == 1 {
					let mut addr_bytes = [ptr[4], ptr[5], ptr[6], ptr[7]];
					let mut port_bytes = [ptr[2], ptr[3]];

					if (attr_type & 0x7fff) == 0x0020 {
						port_bytes[0] ^= buffer[4];
						port_bytes[1] ^= buffer[5];
						addr_bytes[0] ^= buffer[4];
						addr_bytes[1] ^= buffer[5];
						addr_bytes[2] ^= buffer[6];
						addr_bytes[3] ^= buffer[7];
					}
					if !have_xor_mapped_address {
						let port = u16::from_be_bytes(port_bytes);
						let ip = Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);
						mapped_addr = Some(SocketAddrV4::new(ip, port));
					}

					if (attr_type & 0x7fff) == 0x0020 {
						have_xor_mapped_address = true;
					}
					// have_address = true;
				}
			}
			0x0009 => {
				if attr_len >= 4 {
					warn!(
						"parse_stun_response: ERROR-CODE {}",
						ptr[2] as u32 * 100 + ptr[3] as u32
					);
				}
			}
			0x0004 | 0x0005 | 0x802b | 0x802c => {
				if attr_len == 8 && ptr[1] == 1 {
					debug!(
						"parse_stun_response: {} {}.{}.{}.{} {}",
						match attr_type {
							0x0004 => "SOURCE-ADDRESS",
							0x0005 => "CHANGED-ADDRESS",
							0x802b => "RESPONSE-ORIGIN",
							0x802c => "OTHER-ADDRESS",
							_ => "Unknown",
						},
						ptr[4],
						ptr[5],
						ptr[6],
						ptr[7],
						u16::from_be_bytes([ptr[2], ptr[3]]),
					)
				}
			}
			_ => {
				warn!(
					"parse_stun_response: unknown attribute type 0x{:04x} (len={})",
					attr_type, attr_len
				);
			}
		}
		ptr = &ptr[attr_len as usize..];
	}

	mapped_addr
}
/// Perform main STUN operation, return external IP address and check
/// if host is behind restrictive, symmetric NAT or behind firewall.
///
/// Restrictive NAT means any NAT which do some filtering and
/// which is not static full-cone NAT 1:1, basically NAT which is not usable
/// for port forwarding
pub fn perform_stun(
	nat_backend: &mut nat_impl,
	if_name: &IfName,
	if_addr: Ipv4Addr,
	stun_host: &str,
	stun_port: u16,
	restrictive_nat: &mut i32,
) -> io::Result<Ipv4Addr> {
	let fds: [UdpSocket; 4];
	let mut responses_lens: [usize; 4] = [0; 4];
	let mut responses_bufs: [[u8; 1024]; 4] = [[0; 1024]; 4];

	// let mut responses_sizes: [usize; 4] = [0; 4];
	let mut requests: [[u8; 28]; 4] = [[0; 28]; 4];

	let mut have_mapped_addr;
	let mut mapped_addrs_count;
	let remote_addr;
	let mut peer_addrs: [SocketAddrV4; 4] = [SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0); 4];
	let mut mapped_addrs: [SocketAddrV4; 4] = [SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0); 4];

	let mut local_ports: [u16; 4] = [0; 4];
	// let mut have_ext_addr: i32 = 0;

	remote_addr = resolve_stun_host(stun_host, stun_port)?;
	let mut _fds: [MaybeUninit<UdpSocket>; 4] = [const { MaybeUninit::uninit() }; 4];
	for i in 0..4 {
		let (sock, local_port) = stun_socket()?;
		_fds[i] = MaybeUninit::new(sock);
		local_ports[i] = local_port;
		fill_request(&mut requests[i], i / 2 != 0, i % 2 != 0);
	}

	fds = unsafe { mem::transmute::<[MaybeUninit<UdpSocket>; 4], [UdpSocket; 4]>(_fds) };
	info!(
		"perform_stun: local ports {} {} {} {}",
		local_ports[0], local_ports[1], local_ports[2], local_ports[3]
	);

	let mut entry = MapEntry { iaddr: if_addr, proto: UDP, desc: Some(Rc::from("stun test")), ..Default::default() };
	for i in 0..4 {
		entry.eport = local_ports[i];
		entry.iport = local_ports[i];
		if nat_backend.add_filter_rule(if_name, &entry) < 0 {
			error!("perform_stun:  add_filter_rule2(..., {}, ...) FAILED", local_ports[i]);
		}
	}
	let transaction_ids: [&[u8]; 4] = [
		&requests[0][8..20],
		&requests[1][8..20],
		&requests[2][8..20],
		&requests[3][8..20],
	];

	for _ in 0..3 {
		for i in 0..4 {
			if responses_lens[i] != 0 {
				continue;
			}
			if fds[i].send_to(&requests[i], remote_addr).unwrap_or_default() != 28 {
				error!("perform_stun: send_to(): %m");
				break;
			}
		}
		if wait_for_stun_responses(
			&fds,
			&transaction_ids,
			&mut responses_bufs,
			&mut peer_addrs,
			&mut responses_lens,
		) != 0
		{
			break;
		}
		if responses_lens.iter().all(|x| *x != 0) {
			break;
		}
	}
	for i in 0..4 {
		nat_backend.delete_filter_rule(if_name, local_ports[i], IPPROTO_UDP as u8);
	}
	drop(fds);

	let mut have_ext_addr = false;
	have_mapped_addr = 0;
	mapped_addrs_count = 0;
	let mut ext_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
	for i in 0..4 {
		if let Some(addr) = parse_stun_response(&responses_bufs[i][0..responses_lens[i]]) {
			mapped_addrs_count += 1;
			have_mapped_addr |= 1 << i;
			mapped_addrs[i] = addr;
			if !have_ext_addr {
				ext_addr = addr;
				have_ext_addr = true;
			}
		}
	}
	if !have_ext_addr {
		return Err(io::Error::new(io::ErrorKind::Other, "perform_stun: no ext addr"));
	}
	if mapped_addrs_count < 4 {
		notice!("perform_stun: {} response out of 4 received", mapped_addrs_count);
		*restrictive_nat = 1;
	}
	if remote_addr != peer_addrs[0] {
		/* We received STUN response from different address
		 * even we did not asked for it, so some strange NAT is active */
		notice!("perform_stun: address changed");
		*restrictive_nat = 1;
	}
	for i in 0..4 {
		if have_mapped_addr & (1 << i) == 0 {
			continue;
		}
		if mapped_addrs[i].port() != local_ports[i] || mapped_addrs[i].ip() != ext_addr.ip() {
			notice!(
				"perform_stun: #{} external address or port changed: {} => {}",
				i,
				mapped_addrs[i],
				local_ports[i]
			);
			*restrictive_nat = 1;
		}
	}

	Ok(*ext_addr.ip())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;
	#[test]
	fn test_stun_parse() {
		// capture from real world
		let buf = b"\x01\x01\x00\x30\x21\x12\xa4\x42\x89\x79\xbd\xf0\xe0\x22\x20\xa0\xce\x16\xb7\x13\x00\x01\x00\x08\x00\x01\x4b\x1c\xdd\xd8\x93\x46\x80\x2b\x00\x08\x00\x01\x0d\x96\x6f\xce\xae\x03\x80\x2c\x00\x08\x00\x01\x0d\x97\x6f\xce\xae\x02\x00\x20\x00\x08\x00\x01\x6a\x0e\xfc\xca\x37\x04";
		assert_eq!(
			parse_stun_response(buf),
			Some(SocketAddrV4::from_str("221.216.147.70:19228").unwrap())
		);
	}
}
