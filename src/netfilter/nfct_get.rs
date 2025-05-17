#![allow(
	dead_code,
	mutable_transmutes,
	non_camel_case_types,
	non_snake_case,
	non_upper_case_globals,
	unused_assignments,
	unused_mut
)]

use std::net::SocketAddr;

pub(super) fn get_nat_ext_addr(src: Option<SocketAddr>, dst: Option<SocketAddr>, proto: u8) -> Option<SocketAddr> {
	crate::linux::os_impl::get_nat_ext_addr(src, dst, proto)
}
