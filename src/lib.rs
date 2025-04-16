#![feature(random)]
#![feature(extern_types)]
#![feature(const_format_args)]
#![feature(ip)]
#![feature(str_as_str)]
#![feature(ip_as_octets)]
#![feature(maybe_uninit_slice)]
#![feature(let_chains)]
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
use std::rc::Rc;
use std::time::Duration;
#[macro_use]
pub mod log;
#[macro_use]
pub mod upnpglobalvars;

pub mod asyncsendto;
pub mod daemonize;
pub mod getifaddr;
pub mod getifstats;

pub mod minixml;
pub mod natpmp;
pub mod options;
pub mod pcp_msg_struct;
pub mod pcpserver;

pub mod upnpdescgen;
#[cfg(feature = "events")]
pub mod upnpevents;

mod getconnstatus;
pub mod minissdp;
pub mod upnpdescstrings;
pub mod upnphttp;
pub mod upnppermissions;
pub mod upnppinhole;
pub mod upnpredirect;
pub mod upnpreplyparse;
pub mod upnpsoap;
pub mod upnpstun;
pub mod upnpurns;
pub mod upnputils;

pub mod miniupnpdpath;
pub mod uuid;
pub mod warp;

pub const TCP: u8 = libc::IPPROTO_TCP as u8;
pub const UDP: u8 = libc::IPPROTO_UDP as u8;
pub const ICMP: u8 = libc::IPPROTO_ICMP as u8;

// pub const SCTP: u8 = libc::IPPROTO_SCTP as u8;
// pub const UDPLITE: u8 = libc::IPPROTO_UDPLITE as u8;

pub const SCTP: u8 = 132;
pub const UDPLITE: u8 = 132;

pub use warp::IfName;

/// os implement
#[cfg(target_os = "solaris")]
pub mod solaris {
	mod getifstats;
	mod os_impl;
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux {
	mod getifstats;
	pub mod getroute;
	mod ifacewatcher;
	mod os_impl;
	#[cfg(feature = "portinuse")]
	mod portinuse;
	pub use os_impl::linux as os;
}
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub mod bsd {
	pub mod getifstats;
	pub mod ifacewatcher;
	pub use getifstats::bsd as os;
	mod port_in_use;
}
#[cfg(target_os = "macos")]
pub mod mac {
	pub mod getifstats;
	pub use getifstats::macos as os;
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub use bsd::os;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::os;
#[cfg(target_os = "macos")]
pub use mac::os;
#[cfg(target_os = "windows")]
pub use os::windows::os;
#[cfg(target_os = "solaris")]
use solaris::getifstats::solaris as os;

pub trait OS {
	fn os_type(&self) -> &'static str;
	fn os_version(&self) -> &'static str;
	fn uptime(&self) -> Duration;
	fn OpenAndConfInterfaceWatchSocket(&self) -> Option<RawFd>;
	fn ProcessInterfaceWatchNotify(&self, ifname: &IfName, fd: RawFd, need_change: &mut bool);

	fn getifstats(&self, if_name: &IfName, data: &mut ifdata) -> i32;
	#[cfg(feature = "portinuse")]
	fn port_in_use(&self, nat: &nat_impl, if_name: &IfName, eport: u16, proto: u8, iaddr: &Ipv4Addr, iport: u16)
	-> i32;
	#[cfg(not(feature = "portinuse"))]
	fn port_in_use(&self, _nat: &nat_impl, _if_name: &IfName, _eport: u16, _proto: u8, _iaddr: &Ipv4Addr, _iport: u16) -> i32 {
		0
	}
}

/// nat implement
#[cfg(fw = "pf")]
pub mod pf {
	pub mod obsdrdr;
	pub mod pfpinhole;
	pub mod rtickets;
}
#[cfg(fw = "nftables")]
pub mod netfilter_nft {
	pub mod nfct_get;
	pub mod nftnlrdr;
	pub mod nftnlrdr_misc;
	pub mod nftpinhole;
	pub mod tiny_nf_nat;
	pub use nftnlrdr::nftable as nat;
}
#[cfg(fw = "iptables")]
pub mod netfilter {
	pub mod iptcrdr;
	pub mod iptpinhole;
	pub mod nfct_get;
	pub mod tiny_nf_nat;
	pub use iptcrdr::iptable as nat;
}
#[cfg(fw = "ipf")]
pub mod ipf {
	pub mod ipfrdr;
	pub use ipfrdr::ipf;
}
#[cfg(fw = "ipfw")]
pub mod ipfw {
	pub mod ipfwaux;
	pub mod ipfwrdr;
	pub use ipfwaux::ipfw;
}
#[repr(u8)]
pub enum rdr_name_type {
	RDR_TABLE_NAME = 0,
	RDR_NAT_TABLE_NAME = 1,
	RDR_NAT_PREROUTING_CHAIN_NAME = 2,
	RDR_NAT_POSTROUTING_CHAIN_NAME = 3,
	RDR_FORWARD_CHAIN_NAME = 4,
	RDR_FAMILY_SPLIT = 5,
}
impl Into<u8> for rdr_name_type {
	#[inline]
	fn into(self) -> u8 {
		match self {
			rdr_name_type::RDR_TABLE_NAME => 0,
			rdr_name_type::RDR_NAT_TABLE_NAME => 1,
			rdr_name_type::RDR_NAT_PREROUTING_CHAIN_NAME => 2,
			rdr_name_type::RDR_NAT_POSTROUTING_CHAIN_NAME => 3,
			rdr_name_type::RDR_FORWARD_CHAIN_NAME => 4,
			rdr_name_type::RDR_FAMILY_SPLIT => 5,
		}
	}
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct FilterEntry {
	pub index: u32,
	/// redirect: eaddr
	/// filter: unused
	pub saddr: Ipv4Addr,
	/// redirect: iaddr
	/// filter: iaddr
	pub daddr: Ipv4Addr,
	/// redirect: eport
	/// filter: eport
	pub sport: u16,
	/// redirect: iport
	/// filter: iport
	pub dport: u16,
	#[cfg(feature = "pcp_peer")]
	pub raddr: Ipv4Addr,
	#[cfg(feature = "pcp_peer")]
	pub rport: u16,
	pub proto: u8,

	pub packets: u64,
	pub bytes: u64,

	pub desc: Option<Rc<str>>,
	pub timestamp: u64,
}
impl FilterEntry {
	const fn default() -> Self {
		Self {
			index: 0,
			proto: 0,
			sport: 0,
			dport: 0,
			saddr: Ipv4Addr::UNSPECIFIED,
			daddr: Ipv4Addr::UNSPECIFIED,
			desc: None,
			#[cfg(feature = "pcp_peer")]
			rport: 0,
			packets: 0,
			bytes: 0,
			timestamp: 0,
			#[cfg(feature = "pcp_peer")]
			raddr: Ipv4Addr::UNSPECIFIED,
		}
	}
}

impl Default for FilterEntry {
	fn default() -> Self {
		Self::default()
	}
}

#[derive(Clone)]
#[repr(C)]
pub struct PinholeEntry {
	pub index: u32,
	pub iport: u16,
	pub eport: u16,
	pub proto: u8,
	pub iaddr: Ipv6Addr,
	pub eaddr: Ipv6Addr,
	pub desc: Option<Rc<str>>,
	pub packets: u64,
	pub bytes: u64,
	pub timestamp: u64,
}
impl Default for PinholeEntry {
	fn default() -> Self {
		Self {
			index: 0,
			proto: 0,
			iport: 0,
			eport: 0,
			iaddr: Ipv6Addr::UNSPECIFIED,
			eaddr: Ipv6Addr::UNSPECIFIED,
			desc: None,
			packets: 0,
			bytes: 0,
			timestamp: 0,
		}
	}
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum RuleTable {
	Redirect = 0,
	Filter,
}

pub trait Backend {
	fn init() -> Self;
	fn init_redirect(&mut self) -> i32;
	fn init_iptpinhole(&mut self);
	fn shutdown_redirect(&mut self);
	fn get_redirect_rule_count(&self, ifname: &IfName) -> i32;
	// fn get_redirect_rule(&self, ifname:&str, eport: u16, proto: isize) ;
	// fn get_redirect_rule_by_index(&self, index: u32, ifname: &str) -> Option<FilterEntry>;
	fn get_redirect_rule<P>(&self, filter: P) -> Option<FilterEntry>
	where
		P: Fn(&FilterEntry) -> bool;
	fn get_iter<'a>(
		&'a self,
		ifname: &IfName,
		table: RuleTable,
	) -> Option<Box<dyn Iterator<Item = &'a FilterEntry> + 'a>>;

	fn delete_redirect(&mut self, ifname: &IfName, redirect_index: u32) -> i32;
	fn get_portmappings_in_range(&self, start: u16, end: u16, proto: u8) -> Vec<u16>;
	fn update_portmapping(
		&mut self,
		ifname: &IfName,
		eport: u16,
		proto: u8,
		iport: u16,
		desc: &str,
		timestamp: u32,
	) -> i32;
	fn update_portmapping_desc_timestamp(
		&mut self,
		ifname: &IfName,
		eport: u16,
		proto: u8,
		desc: &str,
		timestamp: u32,
	) -> i32;
	fn set_rdr_name(&mut self, param: rdr_name_type, name: &str) -> i32;

	fn get_redir_chain_name(&self) -> &str;

	fn add_redirect_rule2(
		&mut self,
		ifname: &IfName,
		rhost: Option<Ipv4Addr>,
		iaddr: Ipv4Addr,
		eport: u16,
		iport: u16,
		proto: u8,
		desc: Option<&str>,
		timestamp: u32,
	) -> i32;
	fn add_filter_rule2(
		&mut self,
		ifname: &IfName,
		rhost: Option<Ipv4Addr>,
		iaddr: Ipv4Addr,
		eport: u16,
		iport: u16,
		proto: u8,
		desc: Option<&str>,
	) -> i32;

	fn delete_filter_rule(&mut self, ifname: &IfName, lport: u16, proto: u8) -> i32;
	fn delete_filter(&mut self, ifname: &IfName, index: u32) -> i32;
	fn delete_redirect_and_filter_rules(&mut self, ifname: &IfName, eport: u16, proto: u8) -> i32;

	fn get_pinhole_iter<'a>(&'a mut self) -> Option<Box<dyn Iterator<Item = &'a mut PinholeEntry> + 'a>>;
	fn add_pinhole(&mut self, ifname: &IfName, entry: &PinholeEntry) -> i32;
	fn update_pinhole(&mut self, uid: u16, timestamp: u32) -> i32;
	fn delete_pinhole(&mut self, uid: u16) -> i32;
	fn clean_pinhole_list(&mut self, next_timestamp: &mut u32) -> i32;
}

use crate::getifstats::ifdata;
#[cfg(fw = "iptables")]
pub use netfilter::nat as nat_impl;
#[cfg(fw = "nftables")]
pub use netfilter_nft::nat as nat_impl;
#[cfg(fw = "pf")]
pub use pf::pf as nat_impl;
