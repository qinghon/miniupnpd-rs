#![allow(dead_code)]

use crate::warp::IfName;
use libc::{AF_INET, AF_INET6, ifaddrs, sockaddr_in};
use std::ffi::CStr;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{mem, ptr};

pub(crate) const GETIFADDR_OK: i8 = 0;
pub(crate) const GETIFADDR_BAD_ARGS: i8 = -1;
pub(crate) const GETIFADDR_SOCKET_ERROR: i8 = -2;
pub(crate) const GETIFADDR_DEVICE_NOT_CONFIGURED: i8 = -3;
pub(crate) const GETIFADDR_IOCTL_ERROR: i8 = -4;
pub(crate) const GETIFADDR_IF_DOWN: i8 = -5;
pub(crate) const GETIFADDR_NO_ADDRESS: i8 = -6;
pub(crate) const GETIFADDR_INET_NTOP_ERROR: i8 = -7;
pub(crate) const GETIFADDR_GETIFADDRS_ERROR: i8 = -8;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ReservedAddr {
	pub addr: Ipv4Addr,
	pub rmask: u32,
}
#[cfg(not(use_getifaddrs))]
pub fn getifaddr(ifname: &IfName, addr: &mut Ipv4Addr, mask: Option<&mut Ipv4Addr>) -> i32 {
	use libc::{SIOCGIFFLAGS, SIOCGIFNETMASK, ifreq, ioctl, sockaddr, sockaddr_in, socket, strncpy};
	if ifname.is_empty() {
		return -1;
	}
	unsafe {
		let s = socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
		if s < 0 {
			error!("socket(PF_INET, SOCK_DGRAM): %m");
			return -1;
		}
		let ret = 'free: {
			let mut ifr: ifreq = mem::zeroed();

			strncpy(ifr.ifr_name.as_mut_ptr(), ifname.as_ptr(), libc::IFNAMSIZ - 1);

			if ioctl(s, SIOCGIFFLAGS as _, (&mut ifr) as *mut _, size_of::<ifreq>()) < 0 {
				debug!("ioctl(s, SIOCGIFFLAGS, ...): %m");
				break 'free -1;
			}
			if ifr.ifr_ifru.ifru_flags as i32 & libc::IFF_UP == 0 {
				debug!("network interface {} is down", ifname);
				break 'free -1;
			}
			strncpy(ifr.ifr_name.as_mut_ptr(), ifname.as_ptr(), libc::IFNAMSIZ - 1);
			if ioctl(s, libc::SIOCGIFADDR as _, &mut ifr as *mut _, size_of::<libc::ifreq>()) < 0 {
				error!("ioctl(s, SIOCGIFADDR, ...): %m");
				break 'free -1;
			}
			let ifaddr = &*((&ifr.ifr_ifru.ifru_addr) as *const sockaddr as *const sockaddr_in);
			*addr = Ipv4Addr::from(ifaddr.sin_addr.s_addr.to_ne_bytes());
			if let Some(mask) = mask {
				strncpy(ifr.ifr_name.as_mut_ptr(), ifname.as_ptr(), libc::IFNAMSIZ - 1);
				if ioctl(s, SIOCGIFNETMASK as _, &mut ifr as *mut _, size_of::<ifreq>()) < 0 {
					error!("ioctl(s, SIOCGIFNETMASK, ...): %m");
					break 'free -1;
				}
				let ifmask = &*((&ifr.ifr_ifru.ifru_netmask) as *const sockaddr as *const sockaddr_in);
				*mask = Ipv4Addr::from(ifmask.sin_addr.s_addr.to_ne_bytes());
			}

			0
		};
		libc::close(s);
		ret
	}
}

#[derive(Debug)]
pub(crate) struct Iface<'a> {
	pub(crate) name: &'a CStr,
	pub(crate) flags: u32,
	pub(crate) addr: IpAddr,
	pub(crate) mask: IpAddr,
}

pub(crate) struct IfaddrIter<'a> {
	ifap: *mut ifaddrs,
	ife: *mut ifaddrs,
	_mark: PhantomData<&'a ()>,
}
impl Drop for IfaddrIter<'_> {
	fn drop(&mut self) {
		unsafe { libc::freeifaddrs(self.ifap) }
	}
}
impl IfaddrIter<'_> {
	pub(crate) fn new<'a>() -> Option<IfaddrIter<'a>> {
		let mut ifap: *mut libc::ifaddrs = ptr::null_mut();
		if unsafe { libc::getifaddrs(&mut ifap) } < 0 {
			error!("getifaddrs: %m");
			return None;
		}
		if ifap.is_null() {
			return None;
		}
		Some(IfaddrIter { ifap, ife: ifap, _mark: Default::default() })
	}
}
impl<'a> Iterator for IfaddrIter<'a> {
	type Item = Iface<'a>;
	fn next(&mut self) -> Option<Self::Item> {
		if self.ife.is_null() {
			return None;
		}
		let mut ife = unsafe { &*self.ife };
		while ife.ifa_addr.is_null()
			|| (unsafe { &*ife.ifa_addr }.sa_family != AF_INET as u16
				&& unsafe { &*ife.ifa_addr }.sa_family != AF_INET6 as u16)
		{
			self.ife = ife.ifa_next;
			if self.ife.is_null() {
				return None;
			}
			ife = unsafe { &*self.ife };
		}

		let (addr, mask): (IpAddr, IpAddr) = match unsafe { &*ife.ifa_addr }.sa_family as _ {
			libc::AF_INET => {
				let addr = unsafe { &*(ife.ifa_addr as *const sockaddr_in) };
				let mask = unsafe { &*(ife.ifa_netmask as *const sockaddr_in) };
				(
					Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()).into(),
					Ipv4Addr::from(mask.sin_addr.s_addr.to_ne_bytes()).into(),
				)
			}
			#[cfg(feature = "ipv6")]
			libc::AF_INET6 => {
				let addr = unsafe { &*(ife.ifa_addr as *const libc::sockaddr_in6) };
				let mask = unsafe { &*(ife.ifa_netmask as *const libc::sockaddr_in6) };

				(
					Ipv6Addr::from(addr.sin6_addr.s6_addr).into(),
					Ipv6Addr::from(mask.sin6_addr.s6_addr).into(),
				)
			}
			_ => unreachable!(),
		};
		let name = unsafe { CStr::from_ptr(ife.ifa_name) };

		let flags = ife.ifa_flags;
		self.ife = ife.ifa_next;
		Some(Iface { name, flags, addr, mask })
	}
}

#[cfg(use_getifaddrs)]
pub fn getifaddr(ifname: &IfName, addr: &mut Ipv4Addr, mask: Option<&mut Ipv4Addr>) -> i32 {
	if let Some(iter) = IfaddrIter::new() {
		for ifaddr in iter {
			if ifaddr.name != ifname.as_cstr() || ifaddr.addr.is_ipv6() {
				continue;
			}
			let iaddr = match ifaddr.addr {
				IpAddr::V4(addr) => addr,
				_ => unreachable!(),
			};
			if addr_is_reserved(&iaddr) {
				continue;
			}
			*addr = iaddr;

			if let Some(emask) = mask {
				let imask = match ifaddr.mask {
					IpAddr::V4(mask) => mask,
					_ => unreachable!(),
				};
				*emask = imask;
			}
			return 0;
		}
	}
	-1
}
#[cfg(feature = "pcp")]
pub fn getifaddr_in6(ifname: &IfName, ipv6: bool) -> Option<Ipv6Addr> {
	let iter = IfaddrIter::new()?;

	for ifaddr in iter {
		if ifaddr.name != ifname.as_cstr() {
			continue;
		}
		if ipv6 != ifaddr.addr.is_ipv6() {
			continue;
		}
		match ifaddr.addr {
			#[cfg(feature = "ipv6")]
			IpAddr::V6(addr) => {
				if !addr.is_loopback() && !addr.is_unicast_link_local() {
					return Some(addr);
				}
			}

			IpAddr::V4(addr) => return Some(addr.to_ipv6_mapped()),
		}
	}

	None
}

#[cfg(feature = "ipv6")]
pub fn find_ipv6_addr(ifname: &IfName) -> Option<Ipv6Addr> {
	let mut addr = None;
	let iter = IfaddrIter::new()?;
	for intf in iter {
		if intf.name != ifname.as_cstr() || !intf.addr.is_ipv6() {
			continue;
		}
		match intf.addr {
			IpAddr::V4(_) => unreachable!(),
			IpAddr::V6(v6) => {
				if v6.is_loopback() || v6.is_unicast_link_local() {
					continue;
				}
				if v6.as_octets()[0] & 0xfe != 0xfc && addr.is_none() {
					addr.replace(v6);
					continue;
				}
				addr.replace(v6);
				break;
			}
		}
	}
	addr
}
const reserved: &[ReservedAddr] = &[
	// RFC1122 "This host on this network"
	ReservedAddr { addr: Ipv4Addr::new(0, 0, 0, 0), rmask: 24 },
];

pub fn addr_is_reserved(addr: &Ipv4Addr) -> bool {
	if addr.is_loopback()
		|| addr.is_unspecified()
		|| addr.is_documentation()
		|| addr.is_multicast()
		|| addr.is_private()
		|| addr.is_link_local()
		|| addr.is_shared()
	{
		return true;
	}
	for rev in reserved.iter() {
		if (addr.to_bits() >> rev.rmask) == (rev.addr.to_bits() >> rev.rmask) {
			return true;
		}
	}
	false
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;
	#[test]
	fn test_getifaddrs_iter() {
		let iter = IfaddrIter::new().unwrap();

		for addr in iter {
			println!("{:?}", addr)
		}
	}
	#[test]
	#[cfg(not(use_getifaddrs))]
	fn test_getifaddr() {
		let mut addr = Ipv4Addr::new(0, 0, 0, 0);
		assert_eq!(getifaddr(&IfName::from_str("lo").unwrap(), &mut addr, None), 0);
		assert_eq!(addr, Ipv4Addr::LOCALHOST);
	}
	#[test]
	#[cfg(feature = "ipv6")]
	fn test_getifaddr_in6() {
		assert_eq!(find_ipv6_addr(&IfName::from_str("lo").unwrap()), None);
	}
	#[test]
	fn test_addr_is_reserved() {
		assert_eq!(Ipv4Addr::LOCALHOST.to_bits() >> 24, 127);
	}
}
