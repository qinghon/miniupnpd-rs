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
use libc::{
	AF_INET, CTL_NET, NET_RT_IFLIST, PF_ROUTE, RTM_IFINFO, c_int, c_uint, if_msghdr, if_nametoindex, size_t, sysctl,
};
use std::ffi::CString;
use std::ptr;

pub struct macos;

pub fn getifstats(ifname: &str, data: &mut ifdata) -> i32 {
	let ifindex = unsafe { if_nametoindex(CString::new(ifname).unwrap().as_ptr()) };
	if ifindex == 0 {
		return -1;
	}
	data.ibytes = 0;
	data.obytes = 0;
	data.ipackets = 0;
	data.opackets = 0;
	data.baudrate = 4200000;

	let mut mib: [c_int; 6] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_IFLIST, ifindex as c_int];
	let mut needed: size_t = 0;

	if unsafe {
		sysctl(
			mib.as_mut_ptr(),
			mib.len() as c_uint,
			ptr::null_mut(),
			&mut needed,
			ptr::null_mut(),
			0,
		)
	} == -1
	{
		return -1;
	}

	let mut buf = vec![0u8; needed];
	if unsafe {
		sysctl(
			mib.as_mut_ptr(),
			mib.len() as c_uint,
			buf.as_mut_ptr() as *mut _,
			&mut needed,
			ptr::null_mut(),
			0,
		)
	} == -1
	{
		return -1;
	}

	let mut p = buf.as_ptr();
	let end = unsafe { p.add(needed) };

	while p < end {
		let ifm = unsafe { &*(p as *const if_msghdr) };
		if ifm.ifm_type == RTM_IFINFO as u8 {
			let ifdata = unsafe { &ifm.ifm_data };

			data.baudrate = ifdata.ifi_baudrate as u64;
			data.opackets = ifdata.ifi_opackets as u64;
			data.ipackets = ifdata.ifi_ipackets as u64;
			data.obytes = ifdata.ifi_obytes as u64;
			data.ibytes = ifdata.ifi_ibytes as u64;
			return 0;
		}
		p = unsafe { p.add(ifm.ifm_msglen as usize) };
	}
	-1
}
