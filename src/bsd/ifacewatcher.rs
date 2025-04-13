#![allow(
	dead_code,
	mutable_transmutes,
	non_camel_case_types,
	non_snake_case,
	non_upper_case_globals,
	unused_assignments,
	unused_mut
)]
#![feature(extern_types)]
extern "C" {
	pub type rt_msghdr;
	pub type ifa_msghdr;
	pub type if_msghdr;
}

pub unsafe extern "C" fn OpenAndConfInterfaceWatchSocket() -> i32 {
	let mut s: i32 = 0;
	s = socket(16 as i32, SOCK_RAW as i32, 0 as i32);
	if s < 0 as i32 {
		error!("OpenAndConfInterfaceWatchSocket socket: %m\0" as *const u8 as *const libc::c_char,);
	}
	return s;
}
