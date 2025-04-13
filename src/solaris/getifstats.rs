#![allow(
	dead_code,
	mutable_transmutes,
	non_camel_case_types,
	non_snake_case,
	non_upper_case_globals,
	unused_assignments,
	unused_mut
)]

use crate::OS;
use crate::getifstats::ifdata;
use libc::c_long;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;
use std::time::Instant;

unsafe extern "C" {
	fn kstat_open() -> *mut c_void;
	fn kstat_close(kc: *mut c_void);
	fn kstat_lookup(kc: *mut c_void, module: *const c_char, instance: c_int, name: *const c_char) -> *mut c_void;
	fn kstat_read(kc: *mut c_void, ksp: *mut c_void, data: *mut c_void) -> c_int;
	fn kstat_data_lookup(ksp: *mut c_void, name: *const c_char) -> *mut KStatNamed;
}
#[repr(C)]
struct KStatNamed {
	data_type: u8,
	value: KStatValue,
}

#[repr(C)]
union KStatValue {
	i32: i32,
	i64: i64,
}

pub extern "C" fn getifstats(ifname: &str, data: &mut ifdata) -> c_int {
	let pos = ifname.chars().rev().position(|x| !x.is_digit(10)).unwrap();
	let instance = ifname[pos..].parse::<i32>().unwrap();
	let mut buffer = [0u8; 64];
	buffer[..pos + 1].copy_from_slice(ifname.as_bytes());
	let ifname_str = CString::new(ifname).unwrap().as_ptr();
	unsafe {
		let kc = kstat_open();
		if kc.is_null() {
			error!("kstat_open() failed");
			return -1;
		}

		let ksp = kstat_lookup(kc, buffer.as_ptr() as *const c_char, instance, ifname_str);
		if !ksp.is_null() && kstat_read(kc, ksp, ptr::null_mut()) != -1 {
			let is_64bit = std::mem::size_of::<c_long>() == 8;

			let mut lookup_and_set = |name: &str, field: &mut u64| {
				let cname = CString::new(name).unwrap();
				let kn = kstat_data_lookup(ksp, cname.as_ptr());
				if !kn.is_null() {
					*field = if is_64bit {
						(*kn).value.i64 as u64
					} else {
						(*kn).value.i32 as u64
					};
				}
			};
			lookup_and_set("rbytes64", &mut (*data).ibytes);
			lookup_and_set("ipackets64", &mut (*data).ipackets);
			lookup_and_set("obytes64", &mut (*data).obytes);
			lookup_and_set("opackets64", &mut data.opackets);
			lookup_and_set("rbytes", &mut (*data).ibytes);
			lookup_and_set("ipackets", &mut (*data).ipackets);
			lookup_and_set("obytes", &mut (*data).obytes);
			lookup_and_set("opackets", &mut (*data).opackets);

			let cname = CString::new("ifspeed").unwrap();
			let kn = kstat_data_lookup(ksp, cname.as_ptr());
			if !kn.is_null() {
				(*data).baudrate = (*kn).value.i32 as u64;
			}

			kstat_close(kc);
			return 0;
		}

		error!("kstat_lookup/read() failed");
		kstat_close(kc);
	}

	-1
}

