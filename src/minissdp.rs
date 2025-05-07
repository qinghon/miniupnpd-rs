use crate::asyncsendto::{scheduled_send, sendto_or_schedule, sendto_schedule2};
use crate::getifaddr::IfaddrIter;
use crate::linux::getroute::get_src_for_route_to;
use crate::log;
use crate::miniupnpdpath::ROOTDESC_PATH;
use crate::options::{DEFAULT_MINISSDP_DSOCKET_PATH, Options};
use crate::upnpglobalvars::*;
use crate::upnphttp::MINIUPNPD_SERVER_STRING;
use crate::upnputils::get_lan_for_peer;
use crate::uuid::UUID;
use crate::warp::{ip_is_ipv4_mapped, recv_from_if};
use crate::{GETFLAG, error, warn};
use once_cell::sync::OnceCell;
use socket2::Socket;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::random::random;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::atomic::Ordering::Relaxed;
use std::{io, mem};

const VERSION_STR_MAP: [&str; 3] = ["", "1", "2"];
const SSDP_PORT: u16 = 1900;
const SSDP_MCAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

const LL_SSDP_MCAST_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xc);
const SL_SSDP_MCAST_ADDR: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0xc);
const GL_SSDP_MCAST_ADDR: Ipv6Addr = Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0xc);

const mcast_addrs: &[Ipv6Addr] = &[LL_SSDP_MCAST_ADDR, SL_SSDP_MCAST_ADDR, GL_SSDP_MCAST_ADDR];

fn AddMulticastMembership(lan: &lan_addr_s, socket: &Socket) -> io::Result<()> {
	let interface = if lan.index != 0 {
		socket2::InterfaceIndexOrAddress::Index(lan.index)
	} else {
		socket2::InterfaceIndexOrAddress::Address(lan.addr)
	};
	socket.join_multicast_v4_n(&SSDP_MCAST_ADDR, &interface)
}
fn AddMulticastMembershipIPv6(socket: &Socket, ifindex: u32) -> io::Result<()> {
	socket.join_multicast_v6(&LL_SSDP_MCAST_ADDR, ifindex)?;
	socket.join_multicast_v6(&SL_SSDP_MCAST_ADDR, ifindex)?;
	socket.join_multicast_v6(&GL_SSDP_MCAST_ADDR, ifindex)?;
	Ok(())
}

#[cfg(all(feature = "strict", feature = "ipv6"))]
fn get_link_local_addr(scope_id: u32) -> Ipv6Addr {
	if let Some(iter) = IfaddrIter::new() {
		for iface in iter {
			if unsafe { libc::if_nametoindex(iface.name.as_ptr()) } != scope_id || !iface.addr.is_ipv6() {
				continue;
			}
			match iface.addr {
				IpAddr::V4(_) => unreachable!(),
				IpAddr::V6(v6) => {
					if !v6.is_unicast_link_local() {
						continue;
					}
					return v6;
				}
			}
		}
	}
	Ipv6Addr::UNSPECIFIED
}

pub fn OpenAndConfSSDPReceiveSocket(v: &Options, ipv6: bool) -> io::Result<Socket> {
	let socket = if ipv6 {
		socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?
	} else {
		socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?
	};
	let bind_addr = if ipv6 {
		SocketAddrV6::new(ipv6_bind_addr, SSDP_PORT, 0, 0).into()
	} else {
		SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SSDP_PORT).into()
	};
	let _ = socket.set_reuse_address(true);
	let _ = socket.set_reuse_port(true);
	socket.bind(&bind_addr)?;
	#[cfg(target_os = "freebsd")]
	if !ipv6 {
		let on = 1;
		unsafe {
			libc::setsockopt(
				socket.as_raw_fd(),
				libc::IPPROTO_IP,
				libc::IP_RECVIF,
				&on as *const _ as *const libc::c_void,
				mem::size_of_val(&on) as libc::socklen_t,
			);
		}
	}
	#[cfg(target_os = "linux")]
	if !ipv6 {
		let on = 1;
		unsafe {
			libc::setsockopt(
				socket.as_raw_fd(),
				libc::IPPROTO_IP,
				libc::IP_PKTINFO,
				&on as *const _ as *const libc::c_void,
				mem::size_of_val(&on) as libc::socklen_t,
			);
		}
	}

	if ipv6 {
		let on = 1;
		unsafe {
			libc::setsockopt(
				socket.as_raw_fd(),
				libc::IPPROTO_IPV6,
				libc::IPV6_RECVPKTINFO,
				&on as *const _ as *const libc::c_void,
				mem::size_of_val(&on) as libc::socklen_t,
			);
		}
	}

	let _ = socket.set_nonblocking(false);

	if v.listening_ip.len() == 1 && !v.listening_ip[0].ifname.is_empty() {
		let _ = socket.bind_device(Some(v.listening_ip[0].ifname.as_bytes()));
	}

	if ipv6 {
		// lan_addr = lan_addrs.lh_first;
		// while !lan_addr.is_null() {
		//     if AddMulticastMembershipIPv6(s, (*lan_addr).index) < 0 as i32 {
		//         syslog(
		//             4 as i32,
		//             b"Failed to add IPv6 multicast membership for interface {}\0"
		//                 as *const u8 as *const libc::c_char,
		//             if strlen(((*lan_addr).str_0).as_mut_ptr()) != 0 {
		//                 ((*lan_addr).str_0).as_mut_ptr() as *const libc::c_char
		//             } else {
		//                 b"NULL\0" as *const u8 as *const libc::c_char
		//             },
		//         );
		//     }
		//     lan_addr = (*lan_addr).list.le_next;
		// }

		if let Err(e) = AddMulticastMembershipIPv6(&socket, v.listening_ip[0].index) {
			warn!(
				"Failed to add IPv6 multicast membership for interface {}: {}",
				v.listening_ip[0].ifname, e
			);
		}
	} else {
		// lan_addr = lan_addrs.lh_first;
		// while !lan_addr.is_null() {
		//     if AddMulticastMembership(s, lan_addr) < 0 as i32 {
		//         syslog(
		//             4 as i32,
		//             b"Failed to add multicast membership for interface {}\0" as *const u8
		//                 as *const libc::c_char,
		//             if strlen(((*lan_addr).str_0).as_mut_ptr()) != 0 {
		//                 ((*lan_addr).str_0).as_mut_ptr() as *const libc::c_char
		//             } else {
		//                 b"NULL\0" as *const u8 as *const libc::c_char
		//             },
		//         );
		//     }
		//     lan_addr = (*lan_addr).list.le_next;
		// }
		for lan in v.listening_ip.iter() {
			if let Err(e) = AddMulticastMembership(lan, &socket) {
				warn!(
					"Failed to add multicast membership for interface {}: {}",
					v.listening_ip[0].ifname, e
				);
			}
		}
	}
	Ok(socket)
}
fn OpenAndConfSSDPNotifySocket(lan_addr_s: &lan_addr_s) -> io::Result<Socket> {
	let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;

	socket.set_multicast_loop_v4(false)?;
	socket.set_multicast_if_v4(&lan_addr_s.addr)?;

	// UDA v1.1 says :
	// 	The TTL for the IP packet SHOULD default to 2 and
	// 	SHOULD be configurable.
	if let Err(e) = socket.set_ttl(2) {
		warn!("setsockopt(udp_notify, IP_MULTICAST_TTL,): {}", e);
	}
	if let Err(e) = socket.set_broadcast(true) {
		warn!("setsockopt(udp_notify, SO_BROADCAST): {}", e);
		return Err(e);
	}
	if !lan_addr_s.ifname.is_empty() {
		if let Err(e) = socket.bind_device(Some(lan_addr_s.ifname.as_bytes())) {
			warn!("setsockopt(udp6, SO_BINDTODEVICE, {}) : {}", socket.as_raw_fd(), e);
		}
	}

	socket.bind(&socket2::SockAddr::from(SocketAddr::from((lan_addr_s.addr, 0))))?;

	Ok(socket)
}
fn OpenAndConfSSDPNotifySocketIPv6(lan_addr: &lan_addr_s) -> io::Result<socket2::Socket> {
	let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;

	socket.set_multicast_if_v6(lan_addr.index)?;
	socket.set_multicast_loop_v6(false)?;

	// UDA 2.0 : The hop limit of each IP packet for a Site-Local scope
	// multicast message SHALL be configurable and SHOULD default to 10
	if let Err(e) = socket.set_multicast_hops_v6(10) {
		warn!("setsockopt(udp_notify, IP_MULTICAST_TTL,): {}", e);
	}
	if let Err(e) = socket.set_broadcast(true) {
		warn!("setsockopt(udp_notify, SO_BROADCAST): {}", e);
		return Err(e);
	}
	#[cfg(all(any(
		target_os = "ios",
		target_os = "visionos",
		target_os = "macos",
		target_os = "tvos",
		target_os = "watchos",
		target_os = "linux"
	)))]
	if !lan_addr.ifname.is_empty() {
		if let Err(e) = socket.bind_device(Some(lan_addr.ifname.as_bytes())) {
			warn!(
				"OpenAndConfSSDPNotifySocketIPv6: setsockopt(udp6, SO_BINDTODEVICE, {}) : {}",
				lan_addr.ifname, e
			);
		}
	}

	socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0).into())?;

	Ok(socket)
}

pub fn OpenAndConfSSDPNotifySockets(v: &Options, runtime_flags: u32) -> io::Result<Vec<socket2::Socket>> {
	let mut socks = Vec::with_capacity(
		v.listening_ip.len()
			+ if !GETFLAG!(runtime_flags, IPV6DISABLEDMASK) {
				v.listening_ip.len()
			} else {
				0
			},
	);

	for addr in v.listening_ip.iter() {
		socks.push(OpenAndConfSSDPNotifySocket(addr)?);
		#[cfg(feature = "ipv6")]
		if !GETFLAG!(runtime_flags, IPV6DISABLEDMASK) {
			// let interface = addr.index;
			socks.push(OpenAndConfSSDPNotifySocketIPv6(addr)?)
		}
	}

	Ok(socks)
}
fn SendSSDPResponse(
	send_list: &mut Vec<scheduled_send>,
	s: &Rc<Socket>,
	addr: SocketAddr,
	st: &str,
	suffix: &str,
	host: &IpAddr,
	http_port: u16,
	uuidvalue: &UUID,
	delay: u32,
) {
	#[cfg(any(feature = "https", feature = "randomurl"))]
	let op = global_option.get().unwrap();

	let booid = upnp_bootid.load(Relaxed);
	let server_version = MINIUPNPD_SERVER_STRING.get().unwrap();
	#[cfg(all(feature = "https", feature = "randomurl"))]
	let https = format!(
		"SECURELOCATION.UPNP.ORG: https://{}:{}/{}{}\r\n",
		host,
		op.https_port,
		random_url.get().unwrap().as_str(),
		ROOTDESC_PATH
	);
	#[cfg(all(feature = "https", not(feature = "randomurl")))]
	let https = format!(
		"SECURELOCATION.UPNP.ORG: https://{}:{}{}\r\n",
		host, op.https_port, ROOTDESC_PATH
	);
	#[cfg(not(feature = "https"))]
	let https = "";
	#[cfg(feature = "randomurl")]
	let localtion_path = format!("{}{}", random_url.get().unwrap().as_str(), ROOTDESC_PATH);
	#[cfg(not(feature = "randomurl"))]
	let localtion_path = ROOTDESC_PATH;

	let st_is_uuid = st.len() == 36;

	let bufr = format!(
		"HTTP/1.1 200 OK\r\n\
		CACHE-CONTROL: max-age=1800\r\n\
		ST: {st}{suffix}\r\n\
		USN: uuid:{uuidvalue}{}{st}{suffix}\r\n\
		EXT:\r\n\
		SERVER: {server_version}\r\n\
		LOCATION: http://{host}:{http_port}{localtion_path}\r\n\
		{https}\
		OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n\
		01-NLS: {booid}\r\n\
		BOOTID.UPNP.ORG: {booid}\r\n\
		CONFIGID.UPNP.ORG: {upnp_configid}\r\n", /* UDA v1.1 */
		if st_is_uuid { "" } else { "::" }
	);
	let r = sendto_schedule2(send_list, s, bufr.as_bytes(), 0, addr, None, delay);
	debug!(
		"SendSSDPResponse(): {} bytes to {} ST: {}",
		bufr.len(),
		addr,
		bufr.as_str()
	);
	if let Err(e) = r {
		error!("SendSSDPResponse(): sendto(udp): {}", e);
	}
}

pub struct server_type {
	pub s: &'static str,
	pub version: u8,
	pub uuid: &'static OnceCell<UUID>,
}
static known_service_types: &[server_type] = &[
	server_type { s: "upnp:rootdevice", version: 0, uuid: &uuidvalue_igd },
	#[cfg(feature = "igd2")]
	server_type { s: "urn:schemas-upnp-org:device:InternetGatewayDevice:", version: 2, uuid: &uuidvalue_igd },
	#[cfg(feature = "igd2")]
	server_type { s: "urn:schemas-upnp-org:device:WANConnectionDevice:", version: 2, uuid: &uuidvalue_wcd },
	#[cfg(feature = "igd2")]
	server_type { s: "urn:schemas-upnp-org:device:WANDevice:", version: 2, uuid: &uuidvalue_wan },
	#[cfg(feature = "igd2")]
	server_type { s: "urn:schemas-upnp-org:service:WANIPConnection:", version: 2, uuid: &uuidvalue_wcd },
	#[cfg(feature = "_dp_service")]
	server_type { s: "urn:schemas-upnp-org:device:DeviceProtection:", version: 1, uuid: &uuidvalue_igd },
	#[cfg(feature = "ipv6")]
	server_type { s: "urn:schemas-upnp-org:service:WANIPv6FirewallControl:", version: 1, uuid: &uuidvalue_wcd },
	#[cfg(not(feature = "igd2"))]
	server_type { s: "urn:schemas-upnp-org:device:InternetGatewayDevice:", version: 1, uuid: &uuidvalue_igd },
	#[cfg(not(feature = "igd2"))]
	server_type { s: "urn:schemas-upnp-org:device:WANConnectionDevice:", version: 1, uuid: &uuidvalue_wcd },
	#[cfg(not(feature = "igd2"))]
	server_type { s: "urn:schemas-upnp-org:device:WANDevice:", version: 1, uuid: &uuidvalue_wan },
	#[cfg(not(feature = "igd2"))]
	server_type { s: "urn:schemas-upnp-org:service:WANIPConnection:", version: 1, uuid: &uuidvalue_wcd },
	server_type { s: "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:", version: 1, uuid: &uuidvalue_wan },
	/* We use WAN IP Connection, not PPP connection,
	 * but buggy control points may try to use WanPPPConnection
	 * anyway */
	#[cfg(not(feature = "strict"))]
	server_type { s: "urn:schemas-upnp-org:service:WANPPPConnection:", version: 1, uuid: &uuidvalue_wcd },
	server_type { s: "urn:schemas-upnp-org:service:Layer3Forwarding:", version: 1, uuid: &uuidvalue_igd },
];

pub fn SendSSDPNotify(
	send_list: &mut Vec<scheduled_send>,
	s: &Rc<Socket>,
	dest: SocketAddr,
	dest_ip: &IpAddr,
	host: &IpAddr,
	http_port: u16,
	nt: &str,
	suffix: &str,
	usn1: &str,
	usn2: &str,
	usn3: &str,
	lifetime: u32,
) {
	let booid = upnp_bootid.load(Relaxed);
	let server_version = MINIUPNPD_SERVER_STRING.get().unwrap();
	#[cfg(all(feature = "https", feature = "randomurl"))]
	let https = format!(
		"SECURELOCATION.UPNP.ORG: https://{}:{}/{}{}",
		host,
		global_option.get().unwrap().https_port,
		random_url.get().unwrap().as_str(),
		ROOTDESC_PATH
	);
	#[cfg(all(feature = "https", not(feature = "randomurl")))]
	let https = format!(
		"SECURELOCATION.UPNP.ORG: https://{}:{}{}",
		host,
		global_option.get().unwrap().https_port,
		ROOTDESC_PATH
	);
	#[cfg(not(feature = "https"))]
	let https = "";
	#[cfg(feature = "randomurl")]
	let localtion_path = format!("{}{}", random_url.get().unwrap().as_str(), ROOTDESC_PATH);
	#[cfg(not(feature = "randomurl"))]
	let localtion_path = ROOTDESC_PATH;

	let bufr = format!(
		"NOTIFY * HTTP/1.1\r\n\
		HOST: {}:{}\r\n \
		CACHE-CONTROL: max-age={}\r\n\
		LOCATION: http://{}:{}{localtion_path}\r\n\
		{https} \
		SERVER: {server_version}\r\n\
		NT: {nt}{suffix}\r\n\
		USN: {usn1}{usn2}{usn3}{suffix}\r\n\
		NTS: ssdp:alive\r\n\
		OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n\
		01-NLS: {booid}\r\n\
		BOOTID.UPNP.ORG: {booid}\r\n\
		CONFIGID.UPNP.ORG: {upnp_configid}\r\n", /* UDA v1.1 */
		dest_ip, SSDP_PORT, lifetime, host, http_port,
	);
	match sendto_or_schedule(send_list, s, bufr.as_bytes(), 0, dest.into()) {
		Ok(l) => {
			if l != bufr.as_bytes().len() {
				notice!("sendto() sent {} out of {} bytes", bufr.as_bytes().len(), l)
			}
		}
		Err(e) => {
			error!("sendto(udp_notify={}, {}): {}", s.as_raw_fd(), host, e);
		}
	}
	if let Err(e) = sendto_schedule2(send_list, s, bufr.as_bytes(), 0, dest, None, 250) {
		error!("sendto(udp_notify={}, {}): {}", s.as_raw_fd(), host, e);
	}
}
fn SendSSDPNotifies(
	send_list: &mut Vec<scheduled_send>,
	s: &Rc<Socket>,
	host: &IpAddr,
	http_port: u16,
	lifetime: u32,
	ipv6: bool,
) {


	for addr in mcast_addrs {
		let dest = if ipv6 {
			SocketAddrV6::new(addr.clone().into(), SSDP_PORT, 0, 0).into()
		} else {
			SocketAddrV4::new(SSDP_MCAST_ADDR, SSDP_PORT).into()
		};

		for st in known_service_types {
			let uuid_str = format!("uuid:{}", st.uuid.get().unwrap());
			let v_str = VERSION_STR_MAP[st.version as usize];
			SendSSDPNotify(
				send_list,
				s,
				dest,
				&dest.ip(),
				host,
				http_port,
				st.s,
				v_str,
				uuid_str.as_str(),
				"::",
				st.s,
				lifetime,
			);

			if st.s.starts_with("urn:schemas-upnp-org:device") {
				SendSSDPNotify(
					send_list,
					s,
					dest,
					&dest.ip(),
					host,
					http_port,
					uuid_str.as_str(),
					"",
					uuid_str.as_str(),
					"",
					"",
					lifetime,
				);
			}
		}
	}
}

pub fn SendSSDPNotifies2(send_list: &mut Vec<scheduled_send>, sockets: &[Rc<Socket>], http_port: u16, lifetime: u32) {
	let op = global_option.get().unwrap();

	for (i, lan_addr) in op.listening_ip.iter().enumerate() {
		SendSSDPNotifies(
			send_list,
			&sockets[i],
			&lan_addr.addr.into(),
			http_port,
			lifetime,
			false,
		);
		SendSSDPNotifies(
			send_list,
			&sockets[i],
			&(IpAddr::V6(*ipv6_addr_for_http_with_brackets.get().unwrap())),
			http_port,
			lifetime,
			false,
		);
	}
}

pub fn ProcessSSDPRequest(send_list: &mut Vec<scheduled_send>, s: &Rc<Socket>, http_port: u16) {
	let mut buf = [0u8; 1500];
	match recv_from_if(s, &mut buf) {
		Ok((sk, _, ifindex, len)) => ProcessSSDPData(send_list, s, &buf[0..len], sk, ifindex, http_port),
		Err(e) => {
			error!("recv() failed: {}", e);
		}
	}
}

pub fn ProcessSSDPData(
	send_list: &mut Vec<scheduled_send>,
	s: &Rc<Socket>,
	bufr: &[u8],
	sender: SocketAddr,
	source_if: u32,
	http_port: u16,
) {
	let op = global_option.get().unwrap();
	let mut lan_addr = get_lan_for_peer(op, &sender);

	if source_if > 0 {
		if let Some(lan) = lan_addr {
			if lan.index != source_if && lan.index != 0 && (lan.add_indexes & (1 << (source_if - 1)) as u64) == 0 {
				warn!("interface index not matching {} != {}", lan.index, source_if);
			}
		} else {
			lan_addr = op.listening_ip.iter().find(|x| x.index == source_if);
		}
	}
	if lan_addr.is_none() {
		warn!(
			"SSDP packet sender {} (if_index={}) not from a LAN, ignoring",
			sender, source_if
		);
		return;
	}
	if !bufr.is_ascii() {
		debug!("recv ssdp not ascii");
		return;
	}
	if bufr.starts_with(b"NOTIFY") {
		/* ignore NOTIFY packets. We could log the sender and device type */
		return;
	}
	if !bufr.starts_with(b"M-SEARCH") {
		notice!("Unknown udp packet received from {}", sender);
		return;
	}

	let buf = unsafe { str::from_utf8_unchecked(bufr) };

	let mut st_ver = 0;
	let mut mx_value = -1;
	let mut st = None;
	for line in buf.split(&['\r', '\n']) {
		if line.is_empty() {
			continue;
		}
		// ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n
		if line[0..3].eq_ignore_ascii_case("st:") {
			let st_ver_s = line.split(':').last();
			if let Some(st_ver_) = st_ver_s {
				st_ver = st_ver_.parse::<u32>().unwrap_or(0);
			}
			st = Some(line[3..].trim_start());
			debug!("ST: {} (ver={})", &line[3..], st_ver);
		} else {
			#[cfg(feature = "strict")]
			if line[0..3].eq_ignore_ascii_case("mx:") {
				// MX: 3\r\n
				let mx_s = line.split_ascii_whitespace().last();
				if let Some(mx_) = mx_s {
					mx_value = mx_.parse::<i32>().unwrap_or(mx_value);
				}

				debug!("MX: {} (ver={})", &line[3..], st_ver);
			} else if line[0..4].eq_ignore_ascii_case("man:") {
				// MAN: "ssdp:discover"\r\n
				let man_s = line.split_ascii_whitespace().last();
				if man_s != Some("\"ssdp:discover\"") {
					info!("ignoring SSDP packet MAN empty or invalid header");
					return;
				}
			}
		}
	}
	#[cfg(feature = "strict")]
	if mx_value < 0 {
		info!("ignoring SSDP packet missing MX: header");
		return;
	}
	#[cfg(not(feature = "strict"))]
	if mx_value < 0 {
		mx_value = 1;
	}

	if mx_value > 5 {
		// If the MX header field specifies a field value greater
		// than 5, the device SHOULD assume that it contained the
		// value 5 or less.
		mx_value = 5;
	}
	if st.is_none() || st.unwrap().is_empty() {
		info!("Invalid SSDP M-SEARCH from {}", sender);
		return;
	}
	let st = st.unwrap();
	info!("SSDP M-SEARCH from {} ST: {}", sender, st);

	let mut announced_host = None;
	let sender_ip = sender.ip();

	if sender_ip.is_ipv4() || sender_ip.is_ipv6() && ip_is_ipv4_mapped(&sender_ip) {
		if lan_addr.is_none() {
			error!("Can't find IPv4 or IPv6 address for IP {}", sender_ip);
			return;
		}
		announced_host = Some(lan_addr.unwrap().addr.into());
	} else if cfg!(feature = "ipv6") && sender_ip.is_ipv6() {
		#[cfg(feature = "strict")]
		{
			let sock6 = match sender {
				SocketAddr::V4(_) => unreachable!(),
				SocketAddr::V6(v6) => v6,
			};
			let ip6 = match &sender_ip {
				IpAddr::V6(ip) => ip,
				_ => unreachable!(),
			};
			let mut addr6 = Ipv6Addr::UNSPECIFIED;
			if ip6.is_unicast_link_local() {
				addr6 = get_link_local_addr(sock6.scope_id());
			} else {
				let mut addr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
				let index = get_src_for_route_to(&sender_ip, Some(&mut addr));
				if index < 0 {
					warn!(
						"get_src_for_route_to() failed, using {}",
						ipv6_addr_for_http_with_brackets.get().unwrap()
					);
					announced_host = Some(IpAddr::V6(*ipv6_addr_for_http_with_brackets.get().unwrap()));
				}
			}
			if announced_host.is_none() {
				if addr6 == Ipv6Addr::UNSPECIFIED {
					announced_host = Some(IpAddr::V6(*ipv6_addr_for_http_with_brackets.get().unwrap()));
				} else {
					announced_host = Some(IpAddr::V6(addr6));
				}
			}
		}
		#[cfg(not(feature = "strict"))]
		{
			announced_host = Some(IpAddr::V6(
				*crate::upnpglobalvars::ipv6_addr_for_http_with_brackets.get().unwrap(),
			));
		}
	} else {
		error!("Unknown address  for client {}", sender_ip);
		return;
	}
	// Non-zero default delay to prevent flooding
	// UPnP Device Architecture v1.1.  1.3.3 Search response :
	// Devices responding to a multicast M-SEARCH SHOULD wait a random period
	// of time between 0 seconds and the number of seconds specified in the
	// MX field value of the search request before responding, in order to
	// avoid flooding the requesting control point with search responses
	// from multiple devices. If the search request results in the need for
	// a multiple part response from the device, those multiple part
	// responses SHOULD be spread at random intervals through the time period
	// from 0 to the number of seconds specified in the MX header field.

	let mut delay = 50;

	for kst in known_service_types {
		if kst.s.len() > st.len()
			|| !kst.s.starts_with(st.as_str())
			|| (cfg!(feature = "strict") && st_ver > kst.version as u32)
		{
			continue;
		}
		debug!("Single search found: {}", kst.s);

		#[cfg(feature = "strict")]
		{
			delay = random::<u32>() / (1 + (u32::MAX) / (1000 * mx_value as u32));
			trace!("mx={} delay={}", mx_value, delay);
		}

		SendSSDPResponse(
			send_list,
			s,
			sender,
			st,
			"",
			&announced_host.unwrap(),
			http_port,
			kst.uuid.get().unwrap(),
			delay,
		);
		break;
	}
	if st.len() == 8 && st == "ssdp:all" {
		let delay_increment = (mx_value as u32 * 1000) / 15;

		debug!("ssdp:all found");
		for (idx, kst) in known_service_types.iter().enumerate() {
			delay += delay_increment;

			let version = if idx == 0 { 0 } else { kst.version as usize };
			SendSSDPResponse(
				send_list,
				s,
				sender,
				kst.s,
				VERSION_STR_MAP[version],
				&announced_host.unwrap(),
				http_port,
				kst.uuid.get().unwrap(),
				delay,
			);
		}

		#[cfg(feature = "strict")]
		{
			delay += delay_increment;
		}
		SendSSDPResponse(
			send_list,
			s,
			sender,
			uuidvalue_igd.get().unwrap().to_string().as_str(),
			"",
			&announced_host.unwrap(),
			http_port,
			uuidvalue_igd.get().unwrap(),
			delay,
		);

		#[cfg(feature = "strict")]
		{
			delay += delay_increment;
		}
		SendSSDPResponse(
			send_list,
			s,
			sender,
			uuidvalue_wan.get().unwrap().to_string().as_str(),
			"",
			&announced_host.unwrap(),
			http_port,
			uuidvalue_wan.get().unwrap(),
			delay,
		);

		#[cfg(feature = "strict")]
		{
			delay += delay_increment;
		}
		SendSSDPResponse(
			send_list,
			s,
			sender,
			uuidvalue_wcd.get().unwrap().to_string().as_str(),
			"",
			&announced_host.unwrap(),
			http_port,
			uuidvalue_wcd.get().unwrap(),
			delay,
		);
	}

	if st.len() == 41 {
		// uuid with prefix length eg: uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
		#[cfg(feature = "strict")]
		{
			delay = random::<u32>() / (1 + (i32::MAX as u32) / (1000 * mx_value as u32));
		}
		if let Ok(st_uuid) = UUID::from_str(st) {
			if &st_uuid == uuidvalue_igd.get().unwrap()
				|| &st_uuid == uuidvalue_wan.get().unwrap()
				|| &st_uuid == uuidvalue_wcd.get().unwrap()
			{
				debug!("ssdp:uuid (IGD/WAN/WCD) found");
				SendSSDPResponse(
					send_list,
					s,
					sender,
					st,
					"",
					&announced_host.unwrap(),
					http_port,
					&st_uuid,
					delay,
				);
			}
		}
	}
}

fn SendSSDPbyebye(
	send_list: &mut Vec<scheduled_send>,
	s: &Rc<Socket>,
	dest: SocketAddr,
	nt: &str,
	suffix: &str,
	usn1: &str,
	usn2: &str,
	usn3: &str,
) -> io::Result<usize> {
	let bootid = upnp_bootid.load(Relaxed);
	let data = format!(
		"NOTIFY * HTTP/1.1\r\n\
		HOST: {dest}:{SSDP_PORT}\r\n\
		NT: {nt}{suffix}\r\n\
		USN: {usn1}{usn2}{usn3}{suffix}\r\n\
		OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n\
		01-NLS: {bootid}\r\n\
		BOOTID.UPNP.ORG: {bootid}\r\n\
		CONFIGID.UPNP.ORG: {upnp_configid}\r\n\r\n"
	);
	match sendto_or_schedule(
		send_list,
		s,
		data.as_bytes(),
		0,
		dest,
	) {
		Ok(l) => {
			if l != data.len() {
				notice!("sendto() sent {} out of {} bytes", l, data.len());
			}
			Ok(l)
		},
		Err(e) => {
			error!("sendto(udp_shutdown={}) to {}: %m", s.as_raw_fd(), dest);
			Err(e)
		}
	}
}

pub fn SendSSDPGoodbye(
	send_list: &mut Vec<scheduled_send>,
	sockets: &[Rc<Socket>],
) -> io::Result<i32> {
	let mut ok_cnt = 0;

	let mut send_by_socket = |s:&Rc<Socket>, sockaddr: SocketAddr| {
		for st in known_service_types {
			let version_str = VERSION_STR_MAP[st.version as usize];
			let uuid_str = format!("uuid:{}", st.uuid.get().unwrap());

			if let Ok(_) = SendSSDPbyebye(
				send_list,
				s,
				sockaddr,
				st.s,
				version_str,
				uuid_str.as_str(),
				"::",
				st.s,
			) {
				ok_cnt += 1;
			}

			if st.s.starts_with("urn:schemas-upnp-org:device") {
				if let Ok(_) = SendSSDPbyebye(
					send_list,
					s,
					sockaddr,
					uuid_str.as_str(),
					"",
					uuid_str.as_str(),
					"",
					"",
				) {
					ok_cnt += 1;
				}
			}
		}
	};

	for j in 0..sockets.len() {
		if j & 1 != 0 {
			for ip in mcast_addrs {
				let addr = SocketAddrV6::new(*ip, SSDP_PORT, 0, 0).into();
				send_by_socket(&sockets[j], addr);
			}
		} else {
			send_by_socket(&sockets[j], SocketAddrV4::new(SSDP_MCAST_ADDR, SSDP_PORT).into());
		};
	}
	Ok(ok_cnt)
}

pub fn SubmitServicesToMiniSSDPD(v: &Options, host: Ipv4Addr, port: u16) -> io::Result<()> {
	let mut s = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;

	s.connect(&socket2::SockAddr::unix(
		v.minissdpdsocket.as_deref().unwrap_or(DEFAULT_MINISSDP_DSOCKET_PATH),
	)?)?;

	let mut buf: Vec<u8> = Vec::with_capacity(2048);
	for (idx, st) in known_service_types.iter().enumerate() {
		buf.push(4);
		buf.extend_from_slice(st.s.as_bytes());
		if idx != 0 {
			buf.extend_from_slice(VERSION_STR_MAP[st.version as usize].as_bytes());
		}
		buf.write_fmt(format_args!("uuid:{}::{}{}", st.uuid.get().unwrap(), st.s, st.version)).unwrap();
		buf.extend_from_slice(os_version.get().unwrap().as_bytes());
		buf.write_fmt(format_args!("http://{}:{}{}", host, port, ROOTDESC_PATH)).unwrap();
		if let Err(e) = s.write(&buf) {
			if e.kind() == io::ErrorKind::Interrupted {
				continue;
			}
			error!("write to minissdpd failed: {}", e);
			return Err(e);
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {}
