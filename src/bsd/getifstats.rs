#![allow(
	dead_code,
	mutable_transmutes,
	non_camel_case_types,
	non_snake_case,
	non_upper_case_globals,
	unused_assignments,
	unused_mut
)]

use crate::getifstats::ifdata;
use std::ffi::CStr;
use std::mem;
use std::mem::MaybeUninit;
use std::os::raw::c_char;

pub struct bsd;

#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]

pub extern "C" fn getifstats(ifname: &str, data: &mut ifdata) -> i32 {
	data.ibytes = 0;
	data.obytes = 0;
	data.ipackets = 0;
	data.opackets = 0;
	data.baudrate = 4200000;

	let mut addrs: MaybeUninit<*mut libc::ifaddrs> = MaybeUninit::uninit();
	if unsafe { libc::getifaddrs(addrs.as_mut_ptr()) } != 0 {
		return -1;
	}
	let addrs = unsafe { addrs.assume_init() };

	let mut addr = addrs;
	while !addr.is_null() {
		let addr_ref: &libc::ifaddrs = unsafe { &*addr };
		let c_str = addr_ref.ifa_name as *const c_char;
		let name = unsafe { CStr::from_ptr(c_str).to_str().unwrap() };
		if name == ifname {
			unsafe {
				if !addr_ref.ifa_data.is_null() {
					let ifa_data = mem::transmute::<*mut libc::c_void, &libc::if_data>(addr_ref.ifa_data);
					data.ibytes = ifa_data.ifi_ibytes;
					data.obytes = ifa_data.ifi_obytes;
					data.ipackets = ifa_data.ifi_ipackets;
					data.opackets = ifa_data.ifi_opackets;
					data.baudrate = ifa_data.ifi_baudrate;
				}
			}
		}
		addr = addr_ref.ifa_next;
	}
	if !addrs.is_null() {
		unsafe {
			libc::freeifaddrs(addrs);
		}
	}
	0
}
