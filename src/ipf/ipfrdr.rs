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

use crate::Backend;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct rdr_desc {
	pub next: *mut rdr_desc,
	pub eport: u16,
	pub proto: i32,
	pub timestamp: u32,
	pub str_0: [libc::c_char; 0],
}
static mut group_name: [libc::c_char; 10] =
	unsafe { *::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"miniupnpd\0") };
static mut dev: i32 = -(1 as i32);
static mut dev_ipl: i32 = -(1 as i32);
static mut rdr_desc_list: *mut rdr_desc = 0 as *const rdr_desc as *mut rdr_desc;

struct ipf {}

impl Backend for ipf {}
