use crate::getifaddr::getifaddr;
use crate::{Backend, IfName, TCP, nat_impl};

use std::ffi::CStr;
const tcpfile: &CStr = c"/proc/net/tcp";
const udpfile: &CStr = c"/proc/net/udp";
use std::net::Ipv4Addr;

pub(super) fn port_in_use(
	nat: &nat_impl,
	if_name: &IfName,
	eport: u16,
	proto: u8,
	iaddr: &Ipv4Addr,
	iport: u16,
) -> i32 {
	let mut ip_addr = Ipv4Addr::UNSPECIFIED;

	getifaddr(if_name, &mut ip_addr, None);

	let file = if proto == TCP { tcpfile } else { udpfile };
	let f = unsafe { libc::fopen(file.as_ptr(), c"r".as_ptr()) };
	if f.is_null() {
		error!("cannot open {}", file.to_str().unwrap());
		return -1;
	}

	let mut line = [0u8; 256];
	// let mut count = 0;
	let mut found = 0;
	while !unsafe { libc::fgets(line.as_mut_ptr() as _, 255, f) }.is_null() {
		let mut eaddr = [0u8; 68];
		let mut tmp_port = 0u16;
		// count += 1;
		if unsafe {
			libc::sscanf(
				line.as_ptr() as _,
				c"%*d: %64[0-9A-Fa-f]:%x %*x:%*x %*x %*x:%*x %*x:%*x %*x %*d %*d %*u".as_ptr(),
				eaddr.as_mut_ptr(),
				&mut tmp_port,
			)
		} != 2
		{
			continue;
		}
		if tmp_port != eport {
			continue;
		}
		let mut addr0 = 0u8;
		let mut addr1 = 0u8;
		let mut addr2 = 0u8;
		let mut addr3 = 0u8;

		if unsafe {
			libc::sscanf(
				eaddr.as_ptr() as _,
				c"%2hhx%2hhx%2hhx%2hhx".as_ptr(),
				&mut addr0,
				&mut addr1,
				&mut addr2,
				&mut addr3,
			)
		} != 4
		{
			continue;
		}

		let ipaddr = Ipv4Addr::new(addr3, addr2, addr1, addr0);
		if ipaddr.is_unspecified() || ipaddr == *iaddr {
			found += 1;
			break;
		}
	}
	unsafe { libc::fclose(f) };
	if found == 0 {
		if let Some(x) = nat.get_redirect_rule(|x| x.proto == proto && x.eport == eport) {
			debug!(
				"port_in_use check port {} on nat chain {} redirected to {} port {}",
				eport,
				nat.get_redir_chain_name(),
				x.iaddr,
				x.iport
			);

			if !(iaddr == &x.iaddr && x.iport == iport) {
				found += 1;
			}
		}
	}

	found
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{Backend, UDP};
	use std::str::FromStr;
	#[test]
	fn test_port_in_use() {
		let nat = nat_impl::init();
		let if_name = IfName::from_str("lo").unwrap();
		let eport = 1388u16;
		let iport = 1388u16;
		let iaddr = Ipv4Addr::UNSPECIFIED;
		assert_eq!(port_in_use(&nat, &if_name, eport, UDP, &iaddr, iport), 0);
	}
}
