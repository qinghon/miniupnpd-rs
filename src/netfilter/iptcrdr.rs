#![allow(
	dead_code,
	mutable_transmutes,
	non_camel_case_types,
	non_snake_case,
	non_upper_case_globals,
	unused_assignments,
	unused_mut,
	unused_variables,
	improper_ctypes
)]

pub(super) mod iptc {
	#![allow(unsafe_op_in_unsafe_fn)]
	include!(concat!(env!("OUT_DIR"), "/iptc.rs"));
}
use crate::warp;
use iptc::*;

#[derive(Copy, Clone)]
#[repr(C)]
pub(super) struct xt_DSCP_info {
	pub(super) dscp: u8,
}

#[derive(Clone, PartialEq)]
#[repr(C)]
#[derive(Debug)]
pub(super) struct rdr_desc {
	pub(super) proto: u8,
	pub(super) eport: u16,
	pub(super) timestamp: u64,
	pub(super) desc: Box<str>,
}

use super::iptpinhole::*;
use super::tiny_nf_nat::*;
use crate::rdr_name_type::{self};
use crate::upnputils::upnp_time;
use crate::{Backend, FilterEntry, error};
use crate::{PinholeEntry, log};
use crate::{RuleTable, TCP};
use core::ffi;
use libc::{__errno_location, c_char, c_int, c_uint};
use std::ffi::{CStr, CString};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::{mem, ptr};

const def_miniupnpd_nat_chain: &CStr = c"MINIUPNPD";
const def_miniupnpd_nat_postrouting_chain: &CStr = c"MINIUPNPD-POSTROUTING";
const def_miniupnpd_forward_chain: &CStr = c"MINIUPNPD";

type FillFn = fn(&iptable, &mut FilterEntry, &ipt_entry, &xt_entry_match, &xt_entry_target);

pub struct iptable {
	rdr_desc: Vec<rdr_desc>,
	pinhole_list: Vec<pinhole_t>,
	nat_chain: CString,
	nat_postrouting_chain: CString,
	forward_chain: CString,
	uid: u16,
}
struct IptableIter<'a> {
	handle: *mut xtc_handle,
	chain: CString,
	cur: *const ipt_entry,
	entry: FilterEntry,
	backend: &'a iptable,
	index: u32,
	filler: FillFn,
}

impl IptableIter<'_> {
	pub(super) fn new<'a>(ipt: &'a iptable, table: &CStr, chain: &CStr, f: FillFn) -> Option<IptableIter<'a>> {
		let h = unsafe { iptc_init(table.as_ptr()) };
		if h.is_null() {
			return None;
		}
		if unsafe { iptc_is_chain(chain.as_ptr(), h) } == 0 {
			unsafe { iptc_free(h) };
			return None;
		}
		let ch = chain.to_owned();
		Some(IptableIter {
			handle: h,
			chain: ch,
			entry: FilterEntry::default(),
			cur: ptr::null_mut(),
			backend: ipt,
			index: 0,
			filler: f,
		})
	}
}
impl<'a> Iterator for IptableIter<'a> {
	type Item = &'a FilterEntry;

	fn next(&mut self) -> Option<&'a FilterEntry> {
		if self.handle.is_null() {
			return None;
		}
		unsafe {
			let mut e = if self.index == 0 {
				iptc_first_rule(self.chain.as_ptr(), self.handle)
			} else {
				iptc_next_rule(self.cur, self.handle)
			};

			if e.is_null() {
				return None;
			}
			self.entry = Default::default();
			let entry_ref = &*e;
			self.entry.proto = entry_ref.ip.proto as _;
			// let proto = entry_ref.ip.proto as u8;
			let match_ = e.add(1) as *const xt_entry_match;
			let match_ref = &*match_;

			// let eport = if match_ref.u.user.name[0..4] == *b"tcp\0" {
			// 	let info = &*(match_.add(1) as *const xt_tcp);
			// 	info.dpts[0]
			// } else {
			// 	let info = &*(match_.add(1) as *const xt_udp);
			// 	info.dpts[0]
			// };
			let target = &*(e.byte_add(entry_ref.target_offset as usize) as *const xt_entry_target);
			let filler = self.filler;
			self.cur = e;
			self.entry.index = self.index;
			filler(self.backend, &mut self.entry, entry_ref, match_ref, target);
			// let mr = target.add(1) as *const nf_nat_multi_range_compat;
			// let mr_ref = &*mr;
			// let iaddr = mr_ref.range[0].min_ip;
			// let iport = u16::from_be(mr_ref.range[0].min.all);

			// self.entry = FilterEntry {
			// 	index: self.index,
			// 	proto,
			// 	sport: iport,
			// 	dport: eport,
			// 	saddr: entry_ref.ip.src,
			// 	daddr: entry_ref.ip.dst,
			// 	desc: String::new(),
			// 	packets: entry_ref.counters.pcnt,
			// 	bytes: entry_ref.counters.bcnt,
			// 	timestamp: 0,
			// 	..Default::default()
			// };
			// if let Some(desc) = self.backend.get_redirect_desc(eport, proto) {
			// 	self.entry.desc.clear();
			// 	self.entry.desc.push_str(desc.desc.as_str());
			// 	self.entry.timestamp = desc.timestamp;
			// }
			self.index += 1;
			Some(&*((&self.entry) as *const FilterEntry))
		}
	}
	fn count(self) -> usize
	where
		Self: Sized,
	{
		let mut count = 0;
		let mut e = unsafe { iptc_first_rule(self.chain.as_ptr(), self.handle) };
		while !e.is_null() {
			count += 1;
			e = unsafe { iptc_next_rule(self.cur, self.handle) };
		}
		count
	}
}
impl Drop for IptableIter<'_> {
	fn drop(&mut self) {
		if !self.handle.is_null() {
			unsafe { iptc_free(self.handle) };
		}
	}
}

pub(super) enum Target {
	Snat,
	Dnat,
	Masquerade,
	Accept,
}
use crate::warp::{IfName, Ip4Addr};
use Target::*;

impl iptable {
	pub(super) fn get_redirect_desc(&self, eport: u16, proto: u8) -> Option<&rdr_desc> {
		self.rdr_desc.iter().find(|r| r.proto == proto && r.eport == eport)
	}

	pub(super) fn get_entrys<P>(&self, table: &CStr, chain: &CStr, f: FillFn, filter: P) -> Vec<FilterEntry>
	where
		P: Fn(&FilterEntry) -> bool,
	{
		let mut entries: Vec<FilterEntry> = Vec::new();
		let mut iter = IptableIter::new(self, table, chain, f);
		if iter.is_none() {
			return entries;
		}
		for entry in iter.unwrap() {
			if filter(&entry) {
				entries.push(entry.clone());
			}
		}
		entries
	}

	fn get_entry<P>(&self, table: &CStr, chain: &CStr, f: FillFn, filter: P) -> Option<FilterEntry>
	where
		P: Fn(&FilterEntry) -> bool,
	{
		let mut iter = IptableIter::new(self, table, chain, f)?;
		let entry = iter.find(|x| filter(x))?;
		Some(entry.clone())
	}
	fn delete_entry(&self, table: &CStr, chain: &CStr, index: u32) -> i32 {
		unsafe {
			let h = iptc_init(table.as_ptr());
			if h.is_null() {
				error!("iptc_init() failed : {} ", last_iptc_error());
				return -1;
			}
			let chain_c = chain.as_ptr();
			let errno = 'free: {
				if iptc_is_chain(chain_c, h) == 0 {
					iptc_free(h);
					break 'free 2;
				}
				if iptc_delete_num_entry(chain_c, index as c_uint, h) == 0 {
					error!("iptc_delete_num_entry({}): {}", index as c_uint, last_iptc_error());
					break 'free *__errno_location();
				} else if iptc_commit(h) == 0 {
					error!("iptc_commit(h): {}", last_iptc_error());
					break 'free *__errno_location();
				}
				0
			};

			iptc_free(h);
			errno as i32
		}
	}
	#[inline]
	fn add_redirect_desc(&mut self, rdr_desc: rdr_desc) {
		self.rdr_desc.push(rdr_desc);
	}
	pub(super) fn add_entry<P>(
		&self,
		table: &CStr,
		chain: &CStr,
		entry: &FilterEntry,
		target: Target,
		caller: &'static str,
		mut f: P,
	) -> i32
	where
		P: FnMut(&mut ipt_entry),
	{
		iptc_add_entry(table, chain, entry, target, caller, f)
	}
	pub(super) fn add_entry6<P>(
		&self,
		table: &CStr,
		chain: &CStr,
		entry: &PinholeEntry,
		target: Target,
		mut f: P,
	) -> i32
	where
		P: FnMut(&mut ip6t_entry),
	{
		ip6tc_add_entry(table, chain, entry, target, f)
	}

	fn get_pinhole(&self, uid: u16) -> Option<&pinhole_t> {
		self.pinhole_list.iter().find(|x| x.uid == uid)
	}
}

impl Backend for iptable {
	fn init() -> Self {
		Self {
			rdr_desc: Vec::new(),
			pinhole_list: Vec::new(),
			nat_chain: def_miniupnpd_nat_chain.into(),
			nat_postrouting_chain: def_miniupnpd_nat_postrouting_chain.into(),
			forward_chain: def_miniupnpd_forward_chain.into(),
			uid: 0,
		}
	}

	fn init_redirect(&mut self) -> i32 {
		let h = unsafe { iptc_init(c"nat".as_ptr()) };
		if h.is_null() {
			error!("iptc_init() failed : {} ", last_iptc_error());
			return -1;
		}
		unsafe { iptc_free(h) };
		0
	}

	fn init_iptpinhole(&mut self) {}

	fn shutdown_redirect(&mut self) {}

	fn get_redirect_rule_count(&self, ifname: &IfName) -> i32 {
		if let Some(iter) = IptableIter::new(self, c"nat", &self.nat_chain, fill_from_redirect) {
			return iter.count() as i32;
		}
		-1
	}

	fn get_redirect_rule<P>(&self, filter: P) -> Option<FilterEntry>
	where
		P: Fn(&FilterEntry) -> bool,
	{
		self.get_entry(c"nat", &self.nat_chain, fill_from_redirect, filter)
	}

	fn get_iter<'a>(
		&'a self,
		_ifname: &IfName,
		table: RuleTable,
	) -> Option<Box<dyn Iterator<Item = &'a FilterEntry> + 'a>> {
		let tb = match table {
			RuleTable::Redirect => c"nat",
			RuleTable::Filter => c"filter",
		};

		Some(Box::new(IptableIter::new(
			self,
			&tb,
			&self.nat_chain,
			match table {
				RuleTable::Redirect => fill_from_redirect,
				RuleTable::Filter => fill_from_filter,
			},
		)?))
	}

	fn delete_redirect(&mut self, _if_name: &IfName, redirect_index: u32) -> i32 {
		self.delete_entry(c"nat", &self.nat_chain, redirect_index)
	}

	fn get_portmappings_in_range(&self, start: u16, end: u16, proto: u8) -> Vec<u16> {
		Self::get_entrys(self, c"nat", &self.nat_chain, fill_from_redirect, |x| {
			x.proto == proto && start <= x.dport && x.dport <= end
		})
		.iter()
		.map(|x| x.dport)
		.collect::<Vec<u16>>()
	}

	fn update_portmapping(
		&mut self,
		_ifname: &IfName,
		eport: u16,
		proto: u8,
		iport: u16,
		desc: &str,
		timestamp: u32,
	) -> i32 {
		if let Some(index) = self.rdr_desc.iter().position(|x| x.proto == proto && x.eport == eport) {
			self.rdr_desc.swap_remove(index);
		}
		self.add_redirect_desc(rdr_desc { timestamp: timestamp as _, eport, proto, desc: Box::from(desc) });
		0
	}

	fn update_portmapping_desc_timestamp(
		&mut self,
		ifname: &warp::IfName,
		eport: u16,
		proto: u8,
		desc: &str,
		timestamp: u32,
	) -> i32 {
		for (index, rdr) in self.rdr_desc.iter().enumerate() {
			if rdr.proto == proto && rdr.eport == eport {
				debug!("timestamp entry removed ({}, {}, {})", eport, proto, rdr.timestamp);
				self.rdr_desc.swap_remove(index);
				break;
			}
		}

		self.add_redirect_desc(rdr_desc { timestamp: timestamp as _, eport, proto, desc: Box::from(desc) });

		0
	}

	fn set_rdr_name(&mut self, param: rdr_name_type, name: &str) -> i32 {
		match param {
			rdr_name_type::RDR_NAT_PREROUTING_CHAIN_NAME => {
				self.nat_chain = CString::from_str(name).unwrap();
			}
			rdr_name_type::RDR_NAT_POSTROUTING_CHAIN_NAME => {
				self.nat_postrouting_chain = CString::from_str(name).unwrap();
			}
			rdr_name_type::RDR_FORWARD_CHAIN_NAME => {
				self.forward_chain = CString::from_str(name).unwrap();
			}
			_ => {
				error!("set_rdr_name(): tried to set invalid string parameter: {}", param as u8);
				return -1;
			}
		}
		0
	}

	fn get_redir_chain_name(&self) -> &str {
		self.nat_chain.to_str().unwrap()
	}

	fn add_redirect_rule2(
		&mut self,
		_ifname: &IfName,
		rhost: Option<Ipv4Addr>,
		iaddr: Ipv4Addr,
		eport: u16,
		iport: u16,
		proto: u8,
		desc: Option<&str>,
		timestamp: u32,
	) -> i32 {
		let entry = FilterEntry { proto, dport: eport, saddr: iaddr, sport: iport, desc: None, ..Default::default() };
		let mut r = 0;
		r = self.add_entry(c"nat", &self.nat_chain, &entry, Dnat, "addnatrule", |e| {
			if let Some(rhost) = rhost {
				e.ip.src = Ip4Addr::from(rhost).into();
				e.ip.smsk.s_addr = u32::MAX;
			}
		});
		if r >= 0 {
			self.add_redirect_desc(rdr_desc {
				timestamp: timestamp as u64,
				eport,
				proto,
				desc: Box::from(desc.unwrap_or_default()),
			});

			r = self.add_entry(
				c"nat",
				&self.nat_postrouting_chain,
				&entry,
				Masquerade,
				"addmasqueraderule",
				|e| {
					if let Some(rhost) = rhost {
						e.ip.dst = Ip4Addr::from(rhost).into();
						e.ip.dmsk.s_addr = u32::MAX;
					}
				},
			);
			if r < 0 {
				notice!("add_redirect_rule2(): addmasqueraderule returned {}", r);
			}
		}
		r
	}

	fn add_filter_rule2(
		&mut self,
		ifname: &IfName,
		rhost: Option<Ipv4Addr>,
		iaddr: Ipv4Addr,
		eport: u16,
		iport: u16,
		proto: u8,
		desc: Option<&str>,
	) -> i32 {
		let entry = FilterEntry { proto, saddr: iaddr, sport: iport, ..Default::default() };
		self.add_entry(c"filter", &self.forward_chain, &entry, Accept, "add_filter_rule", |e| {
			if let Some(rhost) = rhost {
				e.ip.dst = Ip4Addr::from(entry.saddr).into();
				e.ip.dmsk.s_addr = u32::MAX;
				e.ip.src = Ip4Addr::from(rhost).into();
				e.ip.smsk.s_addr = u32::MAX;
			}
		})
	}

	fn delete_filter_rule(&mut self, ifname: &IfName, lport: u16, proto: u8) -> i32 {
		if let Some(e) = self.get_entry(c"filter", &self.forward_chain, fill_from_filter, |x| {
			x.dport == lport && x.proto == proto
		}) {
			self.delete_filter(ifname, e.index)
		} else {
			0
		}
	}

	fn delete_filter(&mut self, _if_name: &IfName, index: u32) -> i32 {
		self.delete_entry(c"filter", &self.forward_chain, index)
	}

	fn delete_redirect_and_filter_rules(&mut self, ifname: &IfName, eport: u16, proto: u8) -> i32 {
		let redir_entry = self.get_redirect_rule(|x| x.dport == eport && x.proto == proto);
		let r = if let Some(entry) = redir_entry {
			let errno = self.delete_redirect(ifname, entry.index);
			if errno != 0 {
				return errno;
			}
			if let Some(forward_entry) = self.get_entry(c"filter", &self.forward_chain, fill_from_filter, |x| {
				entry.saddr == x.saddr && entry.sport == x.sport && x.proto == proto
			}) {
				self.delete_entry(c"filter", &self.forward_chain, forward_entry.index)
			} else {
				0
			}
		} else {
			0
		};
		let r2 = if let Some(entry) = self.get_entry(
			c"nat",
			&self.nat_postrouting_chain,
			fill_from_redirect_masquerade,
			|x| x.proto == proto && x.dport == eport,
		) {
			let errno = self.delete_entry(c"nat", &self.nat_postrouting_chain, entry.index);
			if errno != 0 {
				return errno;
			} else if let Some(mangle_entry) =
				self.get_entry(c"mangle", &self.nat_chain, fill_from_redirect_masquerade, |x| {
					x.proto == proto && x.sport == entry.sport && x.saddr == entry.saddr
				}) {
				self.delete_entry(c"mangle", &self.nat_chain, mangle_entry.index)
			} else {
				0
			}
		} else {
			0
		};

		self.rdr_desc.retain(|x| x.eport != eport && x.proto != proto);

		r * r2
	}

	fn get_pinhole_iter<'a>(&'a mut self) -> Option<Box<dyn Iterator<Item = &'a mut PinholeEntry> + 'a>> {
		let iter = Ip6tableIter::new(self, c"filter", &self.forward_chain)?;
		Some(Box::new(iter))
	}

	fn add_pinhole(&mut self, ifname: &warp::IfName, entry: &PinholeEntry) -> i32 {
		let r = ip6tc_add_entry(c"filter", &self.forward_chain, entry, Accept, |e| {
			e.ipv6.flags |= IP6T_F_PROTO;
			if !ifname.is_empty() && ifname.as_bytes().len() < 16 {
				e.ipv6.iniface[0..ifname.as_bytes().len()]
					.copy_from_slice(unsafe { mem::transmute::<&[u8], &[c_char]>(ifname.as_bytes()) });
			}
			if entry.eaddr != Ipv6Addr::UNSPECIFIED {
				e.ipv6.src = libc::in6_addr { s6_addr: entry.eaddr.octets() };
				e.ipv6.smsk = libc::in6_addr { s6_addr: [0xff; 16] };
			}
		});
		if r != 0 {
			return r;
		}
		self.pinhole_list.push(pinhole_t {
			saddr: entry.eaddr,
			daddr: entry.iaddr,
			timestamp: entry.timestamp as _,
			sport: entry.eport,
			dport: entry.iport,
			uid: self.uid,
			proto: entry.proto,
			desc: entry.desc.clone().unwrap_or_default(),
		});
		if self.uid == 65535 {
			self.uid = 0;
		} else {
			self.uid += 1;
		}
		0
	}

	fn update_pinhole(&mut self, uid: u16, timestamp: u32) -> i32 {
		if let Some(p) = self.pinhole_list.iter_mut().find(|x| x.uid == uid) {
			p.timestamp = timestamp;
			return 0;
		}
		-2
	}

	fn delete_pinhole(&mut self, uid: u16) -> i32 {
		let p = self.get_pinhole(uid);
		if p.is_none() {
			return -2;
		}
		let p = p.unwrap();

		let ip6_iter = Ip6tableIter::new(self, c"filter", &self.forward_chain);
		if ip6_iter.is_none() {
			return -1;
		}
		let ip6_iter = ip6_iter.unwrap();
		let handle = ip6_iter.get_handle();
		for entry in ip6_iter {
			if entry.proto == p.proto
				&& entry.iaddr == p.saddr
				&& entry.eaddr == p.daddr
				&& entry.iport == p.sport
				&& entry.eport == p.dport
			{
				if handle.delete_num_entry(&self.forward_chain, entry.index as _) == 0 {
					error!(
						"ip6tc_delete_num_entry({},{},...): {}",
						self.forward_chain.to_str().unwrap(),
						entry.index,
						last_ip6tc_error()
					);
					return -1;
				}
				if handle.commit() == 0 {
					error!("ip6tc_commit(): {}", last_ip6tc_error());
					return -1;
				}
				return 0;
			}
		}
		warn!("delete_pinhole() rule with PID={} not found", uid);
		self.pinhole_list.retain(|x| x.uid != uid);
		-2 // not found
	}

	fn clean_pinhole_list(&mut self, next_timestamp: &mut u32) -> i32 {
		let mut idx = 0;
		let mut del_num = 0;
		let mut min_ts = u32::MAX;
		let cur_time = upnp_time().as_secs() as u32;
		while idx < self.pinhole_list.len() {
			if self.pinhole_list[idx].timestamp < cur_time {
				if self.delete_pinhole(self.pinhole_list[idx].uid) == 0 {
					del_num += 1;
				} else {
					break;
				}
			} else if self.pinhole_list[idx].timestamp < min_ts {
				min_ts = self.pinhole_list[idx].timestamp;
			}

			idx += 1;
		}
		*next_timestamp = min_ts;
		del_num
	}
}
#[inline]
fn last_iptc_error() -> &'static str {
	unsafe {
		let errno = *__errno_location();
		CStr::from_ptr(iptc_strerror(errno)).to_str().unwrap()
	}
}

/// ingress: nat table pre-routing chain
fn fill_from_redirect(
	backend: &iptable,
	entry: &mut FilterEntry,
	e: &ipt_entry,
	xt_match: &xt_entry_match,
	target: &xt_entry_target,
) {
	// from dnat target

	let mr = unsafe { &*(target.data.as_ptr() as *const nf_nat_multi_range_compat) };
	unsafe {
		let eport = if xt_match.u.user.name[0..4] == *mem::transmute::<&[u8; 4], &[c_char; 4]>(b"tcp\0") {
			let info = &*(xt_match.data.as_ptr() as *const xt_tcp);
			info.dpts[0]
		} else {
			let info = &*(xt_match.data.as_ptr() as *const xt_udp);
			info.dpts[0]
		};
		entry.sport = eport;
	}
	entry.saddr = Ipv4Addr::from(e.ip.src.s_addr);

	entry.daddr = mr.range[0].min_ip;
	unsafe {
		entry.dport = u16::from_be(mr.range[0].min.all);
	}
	if let Some(desc) = backend.get_redirect_desc(entry.sport, entry.proto) {
		entry.desc = Some(Box::from(desc.desc.as_str()));
		entry.timestamp = desc.timestamp;
	}
}
/// egress: nat table post-routing chain
fn fill_from_redirect_masquerade(
	backend: &iptable,
	entry: &mut FilterEntry,
	e: &ipt_entry,
	xt_match: &xt_entry_match,
	target: &xt_entry_target,
) {
	// from dnat target

	let mr = unsafe { &*(target.data.as_ptr() as *const nf_nat_multi_range_compat) };
	unsafe {
		let sport = if xt_match.u.user.name[0..4] == *mem::transmute::<&[u8; 4], &[c_char; 4]>(b"tcp\0") {
			let info = &*(xt_match.data.as_ptr() as *const xt_tcp);
			info.spts[0]
		} else {
			let info = &*(xt_match.data.as_ptr() as *const xt_udp);
			info.spts[0]
		};
		entry.sport = sport;
	}
	entry.saddr = Ipv4Addr::from_bits(e.ip.src.s_addr);

	unsafe {
		entry.dport = u16::from_be(mr.range[0].min.all);
	}
}

/// ingress: filter table forward chain
fn fill_from_filter(
	_backend: &iptable,
	entry: &mut FilterEntry,
	e: &ipt_entry,
	xt_match: &xt_entry_match,
	_target: &xt_entry_target,
) {
	entry.daddr = e.ip.dst.s_addr.into();
	unsafe {
		let iport = if xt_match.u.user.name[0..4] == *mem::transmute::<&[u8; 4], &[c_char; 4]>(b"tcp\0") {
			let info = &*(xt_match.data.as_ptr() as *const xt_tcp);
			info.dpts[0]
		} else {
			let info = &*(xt_match.data.as_ptr() as *const xt_udp);
			info.dpts[0]
		};
		entry.dport = iport;
	}
}

pub(super) fn get_tcp_match(buf: &mut [u8], dport: u16, sport: u16) -> u16 {
	let match_ = unsafe { (buf.as_mut_ptr() as *mut xt_entry_match).as_mut().unwrap() };
	let tcp_info = unsafe { (match_.data.as_mut_ptr() as *mut u8 as *mut xt_tcp).as_mut().unwrap() };

	match_.u.match_size = get_tcp_match_size() as u16;
	unsafe { match_.u.user.name[0..4].clone_from_slice(mem::transmute::<&[u8; 4], &[c_char; 4]>(b"tcp\0")) };
	if sport == 0 {
		tcp_info.spts[0] = 0;
		tcp_info.spts[1] = 0xffff;
	} else {
		tcp_info.spts[0] = sport;
		tcp_info.spts[1] = sport;
	}
	if dport == 0 {
		tcp_info.dpts[0] = 0;
		tcp_info.dpts[1] = 0xffff;
	} else {
		tcp_info.dpts[0] = dport;
		tcp_info.dpts[1] = dport;
	}
	(xt_align::<xt_entry_match>() + xt_align::<xt_tcp>()) as u16
}
#[inline]
pub(super) const fn get_tcp_match_size() -> usize {
	xt_align::<xt_entry_match>() + xt_align::<xt_tcp>()
}
pub(super) fn get_udp_match(buf: &mut [u8], dport: u16, sport: u16) -> u16 {
	let match_ = unsafe { (buf.as_mut_ptr() as *mut xt_entry_match).as_mut().unwrap() };
	let udpinfo = unsafe { (buf[size_of::<xt_entry_match>()..].as_mut_ptr() as *mut xt_udp).as_mut().unwrap() };

	match_.u.match_size = (xt_align::<xt_entry_match>() + xt_align::<xt_udp>()) as u16;
	unsafe { match_.u.user.name[0..4].clone_from_slice(mem::transmute::<&[u8; 4], &[c_char; 4]>(b"udp\0")) };
	if sport == 0 {
		udpinfo.spts[0] = 0;
		udpinfo.spts[1] = 0xffff;
	} else {
		udpinfo.spts[0] = sport;
		udpinfo.spts[1] = sport;
	}
	if dport == 0 {
		udpinfo.dpts[0] = 0;
		udpinfo.dpts[1] = 0xffff;
	} else {
		udpinfo.dpts[0] = dport;
		udpinfo.dpts[1] = dport;
	}
	(xt_align::<xt_entry_match>() + xt_align::<xt_udp>()) as u16
}
#[inline]
pub(super) const fn get_udp_match_size() -> usize {
	xt_align::<xt_entry_match>() + xt_align::<xt_udp>()
}

pub(super) fn get_dnat_target(buf: &mut [u8], daddr: Ipv4Addr, dport: u16) {
	let mut target = unsafe { (buf.as_mut_ptr() as *mut xt_entry_target).as_mut().unwrap() };
	let mut mr = unsafe {
		(buf[size_of::<xt_entry_target>()..].as_mut_ptr() as *mut nf_nat_multi_range_compat)
			.as_mut()
			.unwrap()
	};

	target.u.target_size = (xt_align::<xt_entry_target>() + xt_align::<nf_nat_multi_range_compat>()) as u16;
	unsafe { target.u.user.name[0..5].copy_from_slice(mem::transmute::<&[u8; 5], &[c_char; 5]>(b"DNAT\0")) };
	mr.rangesize = 1;
	mr.range[0].min_ip = daddr;
	mr.range[0].max_ip = daddr;
	mr.range[0].min.all = dport.to_be();
	mr.range[0].max.all = dport.to_be();
	mr.range[0].flags = (IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED) as ffi::c_uint;
}
#[inline]
pub(super) const fn get_dnat_target_size() -> usize {
	xt_align::<xt_entry_target>() + xt_align::<nf_nat_multi_range_compat>()
}
pub(super) fn get_snat_target(buf: &mut [u8], saddr: Ipv4Addr, sport: u16) {
	let mut target = unsafe { (buf.as_mut_ptr() as *mut xt_entry_target).as_mut().unwrap() };
	let mut mr = unsafe {
		(buf[size_of::<xt_entry_target>()..].as_mut_ptr() as *mut nf_nat_multi_range_compat)
			.as_mut()
			.unwrap()
	};

	target.u.target_size = (xt_align::<xt_entry_target>() + xt_align::<nf_nat_multi_range_compat>()) as u16;
	unsafe { target.u.user.name[0..5].copy_from_slice(mem::transmute::<&[u8; 5], &[c_char; 5]>(b"SNAT\0")) };
	mr.rangesize = 1;
	mr.range[0].min_ip = saddr;
	mr.range[0].max_ip = saddr;
	mr.range[0].min.all = sport.to_be();
	mr.range[0].max.all = sport.to_be();
	mr.range[0].flags = (IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED) as ffi::c_uint;
}
pub(super) const fn get_snat_target_size() -> usize {
	xt_align::<xt_entry_target>() + xt_align::<nf_nat_multi_range_compat>()
}
pub(super) fn get_dscp_target(buf: &mut [u8], dscp: u8) -> u16 {
	let mut target = unsafe { (buf.as_mut_ptr() as *mut xt_entry_target).as_mut().unwrap() };
	let mut di = unsafe { (buf[size_of::<xt_entry_target>()..].as_mut_ptr() as *mut xt_DSCP_info).as_mut().unwrap() };

	target.u.target_size = (xt_align::<xt_entry_target>() + xt_align::<xt_DSCP_info>()) as u16;
	unsafe { target.u.user.name[0..5].copy_from_slice(mem::transmute::<&[u8; 5], &[c_char; 5]>(b"DSCP\0")) };
	di.dscp = dscp;
	(xt_align::<xt_entry_target>() + xt_align::<xt_DSCP_info>()) as u16
}
pub(super) const fn get_dsco_target_size() -> usize {
	xt_align::<xt_entry_target>() + xt_align::<xt_DSCP_info>()
}
pub(super) fn get_masquerade_target(buf: &mut [u8], port: u16) {
	let mut target = unsafe { (buf.as_mut_ptr() as *mut xt_entry_target).as_mut().unwrap() };
	let mut mr = unsafe {
		(buf[xt_align::<xt_entry_target>()..].as_mut_ptr() as *mut nf_nat_multi_range_compat)
			.as_mut()
			.unwrap()
	};

	target.u.target_size = get_masquerade_target_size() as _;
	unsafe { target.u.user.name[0..11].copy_from_slice(mem::transmute::<&[u8; 11], &[c_char; 11]>(b"MASQUERADE\0")) };
	mr.rangesize = 1;
	mr.range[0].min.tcp_port = port.to_be();
	mr.range[0].max.tcp_port = port.to_be();
	mr.range[0].flags = IP_NAT_RANGE_PROTO_SPECIFIED as ffi::c_uint;
}
pub(super) const fn get_masquerade_target_size() -> usize {
	xt_align::<xt_entry_target>() + xt_align::<nf_nat_multi_range_compat>()
}

pub(super) fn get_accept_target(buf: &mut [u8]) {
	let mut target = unsafe { (buf.as_mut_ptr() as *mut xt_entry_target).as_mut().unwrap() };
	target.u.target_size = get_accept_target_size() as _;
	unsafe { target.u.user.name[0..7].copy_from_slice(mem::transmute::<&[u8; 7], &[c_char; 7]>(b"ACCEPT\0")) };
}
pub(super) const fn get_accept_target_size() -> usize {
	xt_align::<xt_entry_target>() + xt_align::<c_int>()
}

pub(super) const fn align_to<A>(align: usize) -> usize
where
	A: Sized,
{
	size_of::<A>() + ((align - (size_of::<A>() & (align - 1))) & (align - 1))
}
const fn xt_align<A>() -> usize {
	align_to::<A>(align_of::<_xt_align>())
}

fn iptc_add_entry<P>(
	table: &CStr,
	chain: &CStr,
	entry: &FilterEntry,
	target: Target,
	caller: &'static str,
	mut f: P,
) -> i32
where
	P: FnMut(&mut ipt_entry),
{
	const entry_size: usize = size_of::<ipt_entry>();
	let match_size = if entry.proto == TCP {
		get_tcp_match_size()
	} else {
		get_udp_match_size()
	};
	let target_size = match target {
		Target::Snat => get_snat_target_size(),
		Target::Dnat => get_dnat_target_size(),
		Target::Masquerade => get_masquerade_target_size(),
		Target::Accept => get_accept_target_size(),
	};
	let mut buf: Vec<u8> = vec![0; entry_size + match_size + target_size];
	let e_ptr = buf.as_mut_ptr() as *mut ipt_entry;
	let e = unsafe { e_ptr.as_mut().unwrap() };
	e.ip.proto = entry.proto as u16;
	let match_set = |b: &mut Vec<u8>, dport, sport| {
		if entry.proto == TCP {
			get_tcp_match(&mut b[entry_size..], dport, sport);
		} else {
			get_udp_match(&mut b[entry_size..], dport, sport);
		}
	};
	match target {
		Target::Snat => {
			match_set(&mut buf, entry.dport, entry.sport);
			get_snat_target(&mut buf[entry_size + match_size..], entry.daddr, entry.dport)
		}
		Dnat => {
			match_set(&mut buf, entry.dport, 0);
			get_dnat_target(&mut buf[entry_size + match_size..], entry.saddr, entry.sport)
		}
		Masquerade => {
			match_set(&mut buf, 0, entry.sport);
			get_masquerade_target(&mut buf[entry_size + match_size..], entry.dport)
		}
		Accept => {
			match_set(&mut buf, entry.sport, 0);
			get_accept_target(&mut buf[entry_size + match_size..])
		}
	};

	e.target_offset = (entry_size + match_size) as _;
	e.next_offset = (entry_size + match_size + target_size) as _;

	f(e);
	iptc_init_verify_and_append(table, chain, e_ptr, caller)
}

fn iptc_init_verify_and_append(table: &CStr, chain: &CStr, entry: *const ipt_entry, caller: &'static str) -> i32 {
	let h = unsafe { iptc_init(table.as_ptr()) };
	if h.is_null() {
		println!("{}: iptc_init() error : {}", caller, last_iptc_error());
		return -1;
	}
	unsafe {
		let ret = 'free: {
			if iptc_is_chain(chain.as_ptr(), h) == 0 {
				println!("{}: chain {} not found", caller, chain.to_string_lossy());
				break 'free -1;
			}
			if iptc_append_entry(chain.as_ptr(), entry, h) == 0 {
				println!("{}: iptc_append_entry() error : {}", caller, last_iptc_error());
				break 'free -1;
			}
			if iptc_commit(h) == 0 {
				println!("{}: iptc_commit() error : {}", caller, last_iptc_error());
				break 'free -1;
			}
			0
		};
		iptc_free(h);
		ret
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::*;

	fn check_root_premison() -> bool {
		let uid = unsafe { libc::getuid() };
		if uid != 0 {
			println!("skip this test with non-root, please run as \"sudo -E\"");
			return false;
		}
		true
	}

	#[test]
	fn test_iptable_no_root() {
		let mut nat = nat_impl::init();
		// let b:Option<Box<str>> = Some(Box::from("a"));
		//
		// println!("{}", b.unwrap_or_default())
	}
	#[test]
	fn test_iptable_root() {
		if !check_root_premison() {
			return;
		}

		let mut nat = iptable::init();
		let entry = FilterEntry {
			proto: UDP,
			sport: 8568,
			dport: 8710,
			saddr: Ipv4Addr::new(192, 168, 1, 2),
			..Default::default()
		};
		let test_table = c"nat";
		let test_chain = c"POSTROUTING";
		let r = nat.add_entry(test_table, test_chain, &entry, Masquerade, "test", |e| {
			e.ip.src = Ip4Addr::from(entry.saddr).into();
			e.ip.smsk.s_addr = u32::MAX;
		});
		assert_eq!(r, 0);

		let iter = IptableIter::new(&nat, test_table, test_chain, fill_from_redirect_masquerade);
		assert!(iter.is_some());
		if let Some(iter) = iter {
			for (index, entry) in iter.enumerate() {
				println!("index {} entry: {:?}", index, entry);
			}
		}

		let entry_ = nat.get_entry(test_table, test_chain, fill_from_redirect_masquerade, |x| {
			entry.proto == x.proto && entry.saddr == x.saddr && entry.sport == x.sport
		});
		assert!(entry_.is_some());
		println!("entry: {:?}", entry_);
		assert_eq!(nat.delete_entry(test_table, test_chain, entry_.unwrap().index), 0);
	}
}
