use crate::error;
use crate::{debug, warn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{io, mem, ptr};

use libc::c_int;
use libc::msghdr;
use libc::nlmsghdr;
use libc::sockaddr_nl;

use libc::nlmsgerr;

mod rtnetlink {
	#![allow(unsafe_op_in_unsafe_fn)]
	#![allow(dead_code, non_camel_case_types, non_snake_case, non_upper_case_globals)]
	include!(concat!(env!("OUT_DIR"), "/rtnetlink.rs"));
}
use rtnetlink::*;

#[derive(Copy, Clone)]
#[repr(C)]
struct C2RustUnnamed_2 {
	pub(super) n: nlmsghdr,
	pub(super) r: rtmsg,
	pub(super) buf: [u8; 1024],
}
impl Default for C2RustUnnamed_2 {
	fn default() -> Self {
		Self {
			n: nlmsghdr { nlmsg_len: 0, nlmsg_type: 0, nlmsg_flags: 0, nlmsg_seq: 0, nlmsg_pid: 0 },
			r: Default::default(),
			buf: [0; 1024],
		}
	}
}

const NLMSG_ALIGNTO: u32 = 4;
#[inline]
pub(super) const fn NLMSG_ALIGN(len: u32) -> u32 {
	(len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}
#[inline]
pub(super) const fn NLMSG_HDRLEN() -> u32 {
	NLMSG_ALIGN(size_of::<nlmsghdr>() as u32)
}
pub(super) const fn NLMSG_LENGTH(len: u32) -> u32 {
	len + NLMSG_HDRLEN()
}
// pub(super) const fn NLMSG_SPACE(len: u32) -> u32 {
// 	NLMSG_ALIGN(NLMSG_LENGTH(len))
// }
pub(super) const fn RTA_LENGTH(len: u32) -> u32 {
	NLMSG_ALIGN(size_of::<rtattr>() as u32 + len)
}
pub(super) const fn NLMSG_OK(nlh: &nlmsghdr, len: u32) -> bool {
	len >= size_of::<nlmsghdr>() as u32 && nlh.nlmsg_len >= size_of::<nlmsghdr>() as u32 && nlh.nlmsg_len <= len
}

pub fn get_src_for_route_to(dst: &IpAddr, mut src: Option<&mut IpAddr>) -> i32 {
	let mut h: *mut nlmsghdr;
	let mut req: C2RustUnnamed_2 = Default::default();
	let mut index: i32 = -1;
	let mut nladdr: sockaddr_nl = unsafe { mem::zeroed() };
	let mut iov = libc::iovec { iov_base: &mut req.n as *mut nlmsghdr as *mut libc::c_void, iov_len: 0 };

	let mut msg: msghdr = unsafe { mem::zeroed() };
	msg.msg_name = &mut nladdr as *mut sockaddr_nl as *mut libc::c_void;
	msg.msg_namelen = size_of::<sockaddr_nl>() as libc::socklen_t;
	msg.msg_iov = &mut iov;
	msg.msg_iovlen = 1;
	msg.msg_control = std::ptr::null_mut::<libc::c_void>();
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	req.n.nlmsg_len = NLMSG_LENGTH(size_of::<rtmsg>() as u32);
	req.n.nlmsg_flags = libc::NLM_F_REQUEST as u16;
	req.n.nlmsg_type = libc::RTM_GETROUTE;
	req.r.rtm_family = if dst.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 } as u8;

	debug!("get_src_for_route_to ({})", dst);
	unsafe {
		let rta =
			((&mut req) as *mut C2RustUnnamed_2 as *mut u8).add(NLMSG_ALIGN(req.n.nlmsg_len) as usize) as *mut rtattr;

		(*rta).rta_type = libc::RTA_DST;
		match dst {
			IpAddr::V4(v4addr) => {
				(*rta).rta_len = NLMSG_ALIGN(RTA_LENGTH(size_of::<Ipv4Addr>() as u32)) as u16;
				let data_addr = rta.byte_add(RTA_LENGTH(0) as usize) as *mut Ipv4Addr;
				ptr::copy(v4addr as *const Ipv4Addr, data_addr, 4);
				// *data_addr = v4addr.to_bits();
				req.r.rtm_dst_len = 32;
			}
			IpAddr::V6(v6addr) => {
				(*rta).rta_len = NLMSG_ALIGN(RTA_LENGTH(size_of::<Ipv6Addr>() as u32)) as u16;
				let data_addr = rta.byte_add(RTA_LENGTH(0) as usize) as *mut Ipv6Addr;
				ptr::copy(v6addr as *const Ipv6Addr, data_addr, 16);
				// *data_addr = *v6addr;
				req.r.rtm_dst_len = 128;
			}
		}

		req.n.nlmsg_len += (*rta).rta_len as u32;
		let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
		if fd < 0 {
			error!("socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) : %m");
			return -1;
		}

		nladdr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
		req.n.nlmsg_seq = 1;
		iov.iov_len = req.n.nlmsg_len as usize;
		let status = libc::sendmsg(fd, &msg, 0) as i32;
		if status < 0 {
			error!("sendmsg(rtnetlink) : %m");
			if fd > 0 {
				libc::close(fd);
			}
			return -1;
		}
		req = Default::default();

		's_165: loop {
			iov.iov_len = size_of::<C2RustUnnamed_2>() as libc::size_t;
			let mut status = libc::recvmsg(fd, &mut msg, 0);
			if status < 0 {
				let errno = io::Error::last_os_error().kind();
				if errno == io::ErrorKind::Interrupted || errno == io::ErrorKind::WouldBlock {
					continue;
				}
				error!("recvmsg(rtnetlink) %m");
				break;
			} else if status == 0 {
				error!("recvmsg(rtnetlink) EOF");
				break;
			} else {
				h = &mut req.n as *mut nlmsghdr;
				while status >= size_of::<nlmsghdr>() as isize {
					let len = (*h).nlmsg_len;
					let l = (len - size_of::<nlmsghdr>() as u32) as i32;
					if l < 0 || len as i32 > status as i32 {
						if msg.msg_flags & libc::MSG_TRUNC != 0 {
							error!("Truncated message");
						}
						error!("malformed message: len={}", len);
						break 's_165;
					}
					if nladdr.nl_pid != 0 || (*h).nlmsg_seq != 1 {
						error!("wrong seq = {}", (*h).nlmsg_seq);
						status -= NLMSG_ALIGN(len) as libc::ssize_t;
						h = h.byte_add(NLMSG_ALIGN(len) as usize);
						continue;
					}
					if (*h).nlmsg_type == libc::NLMSG_ERROR as u16 {
						let err: *mut nlmsgerr = (h as *mut u8)
							.add(libc::NLA_ALIGN(size_of::<nlmsghdr>() as c_int) as usize)
							as *mut nlmsgerr;
						error!("NLMSG_ERROR {}", (*err).error);
						break 's_165;
					}
					if (*h).nlmsg_type == libc::RTM_NEWROUTE {
						let mut len_0 = (*h).nlmsg_len - NLMSG_LENGTH(size_of::<rtmsg>() as u32);

						let mut rta_0 =
							h.byte_add(NLMSG_HDRLEN() as usize)
								.byte_add(NLMSG_ALIGN(size_of::<rtmsg>() as u32) as usize) as *mut rtattr;
						while len_0 >= size_of::<rtattr>() as u32
							&& (*rta_0).rta_len >= size_of::<rtattr>() as u16
							&& (*rta_0).rta_len <= len_0 as u16
						{
							let data = rta_0.byte_add(NLMSG_ALIGN(size_of::<rtattr>() as u32) as usize) as *mut u8;

							if (*rta_0).rta_type == libc::RTA_PREFSRC {
								if let Some(ref mut srcaddr) = src {
									let payload_len = (*rta_0).rta_len - RTA_LENGTH(0) as u16;
									if (srcaddr.is_ipv4() && payload_len != 4)
										|| (srcaddr.is_ipv6() && payload_len != 16)
									{
										warn!(
											"cannot copy src: is_ipv4: {} payload len: {}",
											srcaddr.is_ipv4(),
											payload_len
										);
										if fd >= 0 {
											libc::close(fd);
										}
										return -1;
									}
									**srcaddr = match payload_len {
										4 => {
											let mut v4 = Ipv4Addr::UNSPECIFIED;

											ptr::copy_nonoverlapping(
												data,
												(&mut v4) as *mut Ipv4Addr as *mut u8,
												size_of::<Ipv4Addr>(),
											);
											v4.into()
										}
										6 => {
											let mut v6 = Ipv6Addr::UNSPECIFIED;
											ptr::copy_nonoverlapping(
												data,
												(&mut v6) as *mut Ipv6Addr as *mut u8,
												size_of::<Ipv6Addr>(),
											);
											v6.into()
										}
										_ => Ipv4Addr::UNSPECIFIED.into(),
									}
								}
							} else if (*rta_0).rta_type == libc::RTA_OIF {
								ptr::copy_nonoverlapping(data, (&mut index) as *mut i32 as *mut u8, size_of::<c_int>());
							}
							len_0 -= NLMSG_ALIGN((*rta).rta_len as u32);
							rta_0 = rta_0.byte_add(NLMSG_ALIGN((*rta).rta_len as u32) as usize);
						}
						libc::close(fd);
						return index;
					}
					status -= NLMSG_ALIGN(len) as libc::ssize_t;
					h = h.byte_add(NLMSG_ALIGN(len) as usize);
				}
			}
		}
		if fd >= 0 {
			libc::close(fd);
		}
	}

	-1
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn test_getroute() {
		let mut ipv = Ipv4Addr::UNSPECIFIED.into();
		let index = get_src_for_route_to(&Ipv4Addr::LOCALHOST.into(), Some(&mut ipv));

		assert_eq!(ipv, IpAddr::V4(Ipv4Addr::LOCALHOST));
		assert_ne!(index, -1);
	}
}
