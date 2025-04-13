use super::getifstats::ifaddrmsg;
use super::getroute::{NLMSG_ALIGN, NLMSG_HDRLEN, NLMSG_OK};
use super::os_impl::linux;
use crate::IfName;
use libc::{c_int, sockaddr_nl};
use std::mem;
use std::mem::MaybeUninit;
use std::os::fd::RawFd;

impl linux {
	pub(super) fn OpenAndConfInterfaceWatchSocket_(&self) -> Option<RawFd> {
		let mut addr: sockaddr_nl = unsafe { mem::zeroed() };
		addr.nl_family = libc::AF_NETLINK as _;
		addr.nl_groups = (libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR) as u32;

		let s = unsafe { libc::socket(libc::PF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
		if s < 0 {
			error!("socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE): %m");
			return None;
		}

		if unsafe {
			libc::bind(
				s,
				&addr as *const sockaddr_nl as *const libc::sockaddr,
				size_of_val(&addr) as _,
			)
		} < 0
		{
			error!("bind(netlink): %m");
			unsafe { libc::close(s) };
			return None;
		}
		Some(RawFd::from(s))
	}
	pub(super) fn ProcessInterfaceWatchNotify_(&self, ext_ifname: &IfName, fd: RawFd, need_change: &mut bool) {
		let mut buf: [MaybeUninit<u8>; 4096] = [MaybeUninit::uninit(); 4096];

		unsafe {
			let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: 4096 };

			let mut hdr: libc::msghdr = mem::zeroed();
			hdr.msg_iov = &mut iov;
			hdr.msg_iovlen = 1;

			let mut len = libc::recvmsg(fd, &mut hdr, 0) as isize;
			if len < 0 {
				error!("recvmsg(fd): %m");
				return;
			}

			let ext_if_index = libc::if_nametoindex(ext_ifname.as_ptr() as *const _);
			if ext_if_index == 0 {
				return;
			}
			let buffer = buf.assume_init_ref();

			let mut nlhdrp = buffer.as_ptr() as *const libc::nlmsghdr;
			let mut nlhdr = &*nlhdrp;
			while !nlhdrp.is_null() && NLMSG_OK(nlhdr, len as _) {
				if nlhdr.nlmsg_type as c_int == libc::NLMSG_DONE {
					break;
				}

				match nlhdr.nlmsg_type {
					libc::RTM_NEWLINK => {}
					libc::RTM_DELLINK | libc::RTM_DELADDR | libc::RTM_NEWADDR => {
						let is_del = nlhdr.nlmsg_type == libc::RTM_NEWLINK || nlhdr.nlmsg_type == libc::RTM_DELADDR;
						let ifap = nlhdrp.byte_add(NLMSG_HDRLEN() as _) as *const ifaddrmsg;
						let ifa = &*ifap;
						debug!(
							"{} {} index={} fam={}",
							"ProcessInterfaceWatchNotify",
							if is_del { "RTM_DELADDR" } else { "RTM_NEWADDR" },
							ifa.ifa_index,
							ifa.ifa_family
						);

						if ifa.ifa_index == ext_if_index {
							*need_change = true;
						}
					}

					_ => {
						debug!("{} type {} ignored", "ProcessInterfaceWatchNotify", nlhdr.nlmsg_type);
					}
				}

				len -= NLMSG_ALIGN(nlhdr.nlmsg_len) as isize;

				nlhdrp = nlhdrp.byte_add(NLMSG_ALIGN(nlhdr.nlmsg_len) as _);
				nlhdr = &*nlhdrp;
			}
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::linux::os_impl::linux;
	use std::process::Command;
	use std::str::FromStr;

	#[test]
	fn test_process_interface_notify() {
		let l = linux {};
		let fd = l.OpenAndConfInterfaceWatchSocket_().unwrap();
		let mut changed = false;

		let output = Command::new("sh")
			.arg("-c")
			.arg("ip a add 127.0.0.2/8 dev lo ")
			.output()
			.expect("Failed to add test ip ");
		eprintln!("{:?}", output);
		assert!(output.status.success());
		l.ProcessInterfaceWatchNotify_(&IfName::from_str("lo").unwrap(), fd, &mut changed);
		assert!(changed);
		// t.join().unwrap();
		let _ = Command::new("sh")
			.arg("-c")
			.arg("ip addr del 127.0.0.2/8 dev lo")
			.output()
			.expect("Failed to remove test ip");
	}
}
