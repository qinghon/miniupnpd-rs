#![allow(
	dead_code,
	mutable_transmutes,
	non_camel_case_types,
	non_snake_case,
	non_upper_case_globals,
	unused_assignments,
	unused_mut
)]

use core::ffi;
use std::net::Ipv4Addr;
#[derive(Copy, Clone)]
#[repr(C)]
pub(super) union nf_conntrack_man_proto {
	all: u16,
	tcp_port: u16,
	udp_port: u16,
	icmp_id: u16,
	dccp_port: u16,
	sctp_port: u16,
	gre_key: u16,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub(super) struct nf_nat_range {
	flags: ffi::c_uint,
	min_ip: Ipv4Addr,
	max_ip: Ipv4Addr,
	min: nf_conntrack_man_proto,
	max: nf_conntrack_man_proto,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub(super) struct nf_nat_multi_range_compat {
	rangesize: ffi::c_uint,
	range: [nf_nat_range; 1],
}
