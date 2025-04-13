#![allow(dead_code)]

use core::ffi;
use std::net::Ipv4Addr;
#[derive(Copy, Clone)]
#[repr(C)]
pub(super) union nf_conntrack_man_proto {
	pub(super) all: u16,
	pub(super) tcp_port: u16,
	pub(super) udp_port: u16,
	pub(super) icmp_id: u16,
	pub(super) dccp_port: u16,
	pub(super) sctp_port: u16,
	pub(super) gre_key: u16,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub(super) struct nf_nat_range {
	pub(super) flags: ffi::c_uint,
	pub(super) min_ip: Ipv4Addr,
	pub(super) max_ip: Ipv4Addr,
	pub(super) min: nf_conntrack_man_proto,
	pub(super) max: nf_conntrack_man_proto,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub(super) struct nf_nat_multi_range_compat {
	pub(super) rangesize: ffi::c_uint,
	pub(super) range: [nf_nat_range; 1],
}
pub(super) const IP_NAT_RANGE_MAP_IPS: u8 = 1;
pub(super) const IP_NAT_RANGE_PROTO_SPECIFIED: u8 = 2;
pub(super) const IP_NAT_RANGE_PROTO_RANDOM: u8 = 4;
pub(super) const IP_NAT_RANGE_PERSISTENT: u8 = 8;
