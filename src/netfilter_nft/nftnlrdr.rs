use super::nftnlrdr_misc::{
	mnl_socket, rule_chain_type, rule_del_handle, rule_set_dnat, rule_set_filter, rule_set_filter6, rule_t,
};
use crate::*;
use crate::{Backend, FilterEntry, PinholeEntry, RuleTable};
use libc::{ENOMEM, NFPROTO_INET, NFT_MSG_DELRULE, NFT_MSG_NEWRULE, NFT_NAT_DNAT, NFT_NAT_SNAT};
use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::ptr;
use std::str::FromStr;

use libc::{NFPROTO_IPV4, NFPROTO_IPV6};

#[derive(Copy, Clone)]
#[repr(C)]
pub(super) struct timestamp_entry {
	pub(super) timestamp: u32,
	pub(super) eport: u16,
	pub(super) proto: u8,
}

const def_nft_table: &CStr = c"filter";
const def_nft_nat_table: &CStr = c"filter";
const def_nft_prerouting_chain: &CStr = c"prerouting_miniupnpd";
const def_nft_postrouting_chain: &CStr = c"postrouting_miniupnpd";
const def_nft_forward_chain: &CStr = c"miniupnpd";

pub struct nftable {
	pub(super) mnl_sock: *mut mnl_socket,
	pub(super) mnl_portid: u32,
	pub(super) mnl_seq: u32,

	pub(super) nft_table: CString,
	pub(super) nft_nat_table: CString,
	pub(super) nft_prerouting_chain: CString,
	pub(super) nft_postrouting_chain: CString,
	pub(super) nft_forward_chain: CString,

	pub(super) nft_nat_family: i32,
	pub(super) nft_ipv4_family: i32,
	pub(super) nft_ipv6_family: i32,

	pub(super) filter_rule: Vec<rule_t>,
	pub(super) redirect_rule: Vec<rule_t>,
	pub(super) peer_rule: Vec<rule_t>,
	pub(super) timestamp_list: Vec<timestamp_entry>,

	pub(super) rule_list_filter_validate: bool,
	pub(super) rule_list_redirect_validate: bool,
	pub(super) rule_list_peer_validate: bool,
	pub(super) next_uid: u32,
}
use super::nftnlrdr_misc::rule_chain_type::{RULE_CHAIN_FILTER, RULE_CHAIN_PEER, RULE_CHAIN_REDIRECT};
use crate::netfilter_nft::nftnlrdr_misc::rule_type::{RULE_FILTER, RULE_NAT};
use crate::netfilter_nft::nftpinhole::{parse_pinhole_desc, Nftable6Iter};
use crate::upnputils::upnp_time;
use rdr_name_type::*;

type FillFn = fn(&nftable, &mut FilterEntry, &rule_t);

struct NftableIter<'a> {
	rule: Box<dyn Iterator<Item = &'a rule_t> + 'a>,
	backend: &'a nftable,
	entry: FilterEntry,
	f: FillFn,
}
impl<'a> NftableIter<'a> {
	pub(super) fn new(n: &'a nftable, chain: rule_chain_type, fill_fn: FillFn) -> NftableIter<'a> {
		let iter = match chain {
			RULE_CHAIN_FILTER => Box::new(n.filter_rule.iter()),
			RULE_CHAIN_PEER => Box::new(n.peer_rule.iter()),
			RULE_CHAIN_REDIRECT => Box::new(n.redirect_rule.iter()),
		};
		Self { rule: iter, entry: Default::default(), f: fill_fn, backend: n }
	}
}
impl<'a> Iterator for NftableIter<'a> {
	type Item = &'a FilterEntry;

	fn next(&mut self) -> Option<Self::Item> {
		let rule = self.rule.next()?;
		let index = self.entry.index;
		self.entry = FilterEntry::default();
		self.entry.index = index + 1;
		self.entry.proto = rule.proto;

		let f = self.f;
		f(&self.backend, &mut self.entry, &rule);

		Some(unsafe { &*((&self.entry) as *const FilterEntry) })
	}
}

fn fill_entry_redirect(n: &nftable, entry: &mut FilterEntry, r: &rule_t) {
	entry.sport = r.dport;
	entry.daddr = r.nat_addr;
	entry.desc = Some(r.desc.clone());
	entry.dport = r.nat_port;
	if let Some(tn) = n.timestamp_list.iter().find(|t| t.eport == entry.sport && entry.proto == r.proto) {
		entry.timestamp = tn.timestamp as _;
	}
}
fn fill_entry_filter(_n: &nftable, entry: &mut FilterEntry, r: &rule_t) {
	entry.dport = r.dport;
	entry.daddr = r.daddr;
	entry.saddr = r.saddr;
	entry.sport = r.sport;
}

impl Backend for nftable {
	fn init() -> Self {
		Self {
			nft_table: def_nft_table.into(),
			nft_nat_table: def_nft_nat_table.into(),
			nft_prerouting_chain: def_nft_prerouting_chain.into(),
			nft_postrouting_chain: def_nft_postrouting_chain.into(),
			nft_forward_chain: def_nft_forward_chain.into(),
			nft_nat_family: NFPROTO_INET,
			nft_ipv4_family: NFPROTO_INET,
			nft_ipv6_family: NFPROTO_INET,
			mnl_sock: ptr::null_mut(),
			mnl_portid: 0,
			mnl_seq: 0,
			filter_rule: vec![],
			redirect_rule: vec![],
			peer_rule: vec![],
			timestamp_list: vec![],
			rule_list_filter_validate: false,
			rule_list_redirect_validate: false,
			rule_list_peer_validate: false,
			next_uid: 0,
		}
	}

	fn init_redirect(&mut self) -> i32 {
		self.nft_mnl_connect()
	}

	fn init_iptpinhole(&mut self) {}

	fn shutdown_redirect(&mut self) {
		self.nft_mnl_dissconnect()
	}

	fn get_redirect_rule_count(&self, _ifname: &IfName) -> i32 {
		self.redirect_rule.len() as _
	}

	fn get_redirect_rule<P>(&self, filter: P) -> Option<FilterEntry>
	where
		P: Fn(&FilterEntry) -> bool,
	{
		let if_name = IfName::default();
		for x in self.get_iter(&if_name, RuleTable::Redirect)? {
			if filter(x) {
				return Some(x.clone());
			}
		}
		None
	}

	fn get_iter<'a>(
		&'a self,
		_ifname: &IfName,
		table: RuleTable,
	) -> Option<Box<dyn Iterator<Item = &'a FilterEntry> + 'a>> {
		match table {
			RuleTable::Redirect => Some(Box::new(NftableIter::new(
				self,
				RULE_CHAIN_REDIRECT,
				fill_entry_redirect,
			))),
			RuleTable::Filter => Some(Box::new(NftableIter::new(self, RULE_CHAIN_FILTER, fill_entry_filter))),
		}
	}

	fn delete_redirect(&mut self, ifname: &IfName, redirect_index: u32) -> i32 {
		self.refresh_nft_cache_(RULE_CHAIN_REDIRECT);

		let rule = {
			let mut iter = self.get_iter(ifname, RuleTable::Redirect).unwrap();
			if let Some(entry) = iter.find(|entry| entry.index == redirect_index) {
				self.filter_rule
					.iter()
					.find(|r| r.dport == entry.dport && r.proto == entry.proto && r.daddr == entry.daddr)
			} else {
				None
			}
		};
		if rule.is_none() {
			warn!(
				"delete_redirect_and_filter_rules: redirect rule with index {} NOT FOUND",
				redirect_index
			);
			return -2;
		}
		if let Some(r) = rule_del_handle(rule.unwrap(), self.nft_nat_family) {
			self.nft_send_rule(r, NFT_MSG_DELRULE as _, RULE_CHAIN_FILTER)
		} else {
			-ENOMEM
		}
	}

	fn get_portmappings_in_range(&self, start: u16, end: u16, proto: u8) -> Vec<u16> {
		let mut range = vec![];

		for r in &self.redirect_rule {
			if r.proto != proto {
				continue;
			}
			if start <= r.dport && r.dport <= end {
				range.push(r.dport);
			}
		}
		range
	}

	fn update_portmapping(
		&mut self,
		ifname: &IfName,
		eport: u16,
		proto: u8,
		iport: u16,
		desc: &str,
		timestamp: u32,
	) -> i32 {
		// let iter = ;
		let entry = self.get_iter(ifname, RuleTable::Redirect).unwrap().find(|e| e.sport == eport && e.proto == proto);
		if entry.is_none() {
			return -1;
		}
		let entry = entry.unwrap();
		let iaddr = entry.daddr;
		let raddr = if entry.saddr != Ipv4Addr::UNSPECIFIED {
			Some(entry.saddr)
		} else {
			None
		};
		let _ = entry;
		self.delete_redirect_and_filter_rules(ifname, eport, proto);

		if self.add_redirect_rule2(ifname, raddr, iaddr, eport, iport, proto, Some(desc), timestamp) < 0 {
			return -1;
		}
		if self.add_filter_rule2(ifname, raddr, iaddr, eport, iport, proto, Some(desc)) < 0 {
			return -1;
		}

		0
	}

	fn update_portmapping_desc_timestamp(
		&mut self,
		_ifname: &IfName,
		eport: u16,
		proto: u8,
		_desc: &str,
		timestamp: u32,
	) -> i32 {
		self.remove_timestamp_entry(eport, proto);
		self.add_timestamp_entry(eport, proto, timestamp);
		0
	}

	fn set_rdr_name(&mut self, param: rdr_name_type, name: &str) -> i32 {
		if name.is_empty() || name.len() > 30 {
			error!("invalid string argument '{}'", name);
			return -1;
		}

		match param {
			RDR_TABLE_NAME => self.nft_table = CString::new(name).unwrap(),
			RDR_NAT_POSTROUTING_CHAIN_NAME => self.nft_postrouting_chain = CString::from_str(name).unwrap(),

			RDR_NAT_TABLE_NAME => self.nft_nat_table = CString::from_str(name).unwrap(),
			RDR_NAT_PREROUTING_CHAIN_NAME => self.nft_prerouting_chain = CString::from_str(name).unwrap(),
			RDR_FORWARD_CHAIN_NAME => self.nft_forward_chain = CString::from_str(name).unwrap(),
			RDR_FAMILY_SPLIT => {
				if name == "yes" {
					self.nft_nat_family = NFPROTO_IPV4;
					self.nft_ipv4_family = NFPROTO_IPV4;
					self.nft_ipv6_family = NFPROTO_IPV6;
					info!("using IPv4/IPv6 Table");
				}
			}
		}
		0
	}

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
	) -> i32 {
		if let Some(r) = rule_set_dnat(
			self.nft_nat_family as _,
			&self.nft_nat_table,
			&self.nft_prerouting_chain,
			&ifname.as_cstr(),
			proto,
			rhost,
			eport,
			iaddr,
			iport,
			desc,
			None,
		) {
			let ret = self.nft_send_rule(r, NFT_MSG_NEWRULE, RULE_CHAIN_REDIRECT);
			if ret >= 0 {
				self.timestamp_list.push(timestamp_entry { timestamp, eport, proto });
				self.refresh_nft_cache_(RULE_CHAIN_REDIRECT);
				0
			} else {
				ret
			}
		} else {
			-libc::ENOMEM
		}
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
		if let Some(r) = rule_set_filter(
			&self.nft_table,
			&self.nft_forward_chain,
			self.nft_nat_family as u8,
			&ifname.as_cstr(),
			proto,
			rhost,
			iaddr,
			eport,
			iport,
			0,
			desc,
			None,
		) {
			self.nft_send_rule(r, NFT_MSG_NEWRULE, RULE_CHAIN_FILTER)
		} else {
			-libc::ENOMEM
		}
	}

	fn delete_filter_rule(&mut self, ifname: &warp::IfName, lport: u16, proto: u8) -> i32 {
		self.refresh_nft_cache_(RULE_CHAIN_FILTER);

		let rule = self
			.filter_rule
			.iter()
			.enumerate()
			.find(|(_, x)| x.dport == lport && x.proto == proto && x.type_0 == RULE_FILTER);

		if rule.is_none() {
			return 0;
		}
		let idx = rule.unwrap().0 as _;
		let _ = rule;
		self.delete_filter(ifname, idx)
	}

	fn delete_filter(&mut self, _ifname: &IfName, index: u32) -> i32 {
		let entry = self.filter_rule.get_mut(index as usize);
		if entry.is_none() {
			return 0;
		}
		let entry = entry.unwrap();
		if let Some(r) = rule_del_handle(entry, self.nft_nat_family) {
			self.nft_send_rule(r, NFT_MSG_DELRULE, RULE_CHAIN_FILTER);
		}
		0
	}

	fn delete_redirect_and_filter_rules(&mut self, _ifname: &IfName, eport: u16, proto: u8) -> i32 {
		self.refresh_nft_cache_(RULE_CHAIN_REDIRECT);

		let rule = {
			self.redirect_rule.iter().find(|r| {
				r.dport == eport && r.proto == proto && r.type_0 == RULE_NAT && r.nat_type == NFT_NAT_DNAT as _
			})
		};

		let mut iaddr = Ipv4Addr::UNSPECIFIED;
		let mut iport = 0;
		if let Some(rule) = rule {
			iaddr = rule.nat_addr;
			iport = rule.nat_port;
			if let Some(r) = rule_del_handle(rule, self.nft_nat_family) {
				let _ = rule;
				self.nft_send_rule(r, NFT_MSG_DELRULE, RULE_CHAIN_REDIRECT);
			}
		}
		if iaddr != Ipv4Addr::UNSPECIFIED && iport != 0 {
			self.refresh_nft_cache_(RULE_CHAIN_FILTER);

			let rule = self
				.filter_rule
				.iter()
				.find(|r| r.dport == iport && r.daddr == iaddr && r.proto == proto && r.type_0 == RULE_FILTER);
			if let Some(r) = rule_del_handle(rule.unwrap(), self.nft_nat_family) {
				let _ = rule;
				self.nft_send_rule(r, NFT_MSG_DELRULE, RULE_CHAIN_FILTER);
			}
		} else {
			warn!(
				"{}: redirect rule with eport={} proto {} NOT FOUND",
				"delete_redirect_and_filter_rules", eport, proto
			);
		}
		iaddr = Ipv4Addr::UNSPECIFIED;
		iport = 0;

		self.refresh_nft_cache_(RULE_CHAIN_PEER);

		let rule = self.peer_rule.iter().find(|r| {
			r.nat_port == eport && r.type_0 == RULE_NAT && r.nat_type == NFT_NAT_SNAT as _ && r.proto == proto
		});
		if let Some(r) = rule {
			iaddr = r.daddr;
			iport = r.dport;
			if let Some(r) = rule_del_handle(r, self.nft_nat_family) {
				let _ = rule;
				self.nft_send_rule(r, NFT_MSG_DELRULE, RULE_CHAIN_PEER);
			}
		}
		if iaddr != Ipv4Addr::UNSPECIFIED && iport != 0 {
			self.refresh_nft_cache_(RULE_CHAIN_FILTER);

			let rule =
				self.filter_rule.iter().find(|r| r.dport == iport && r.daddr == iaddr && r.type_0 == RULE_FILTER);

			if let Some(r) = rule_del_handle(rule.unwrap(), self.nft_nat_family) {
				let _ = rule;
				self.nft_send_rule(r, NFT_MSG_DELRULE, RULE_CHAIN_FILTER);
			}
		}

		0
	}

	fn get_pinhole_iter<'a>(&'a mut self) -> Option<Box<dyn Iterator<Item = &'a mut PinholeEntry> + 'a>> {
		self.refresh_nft_cache_(RULE_CHAIN_FILTER);

		Some(Box::new(Nftable6Iter::new(self)))
	}

	fn add_pinhole(&mut self, ifname: &warp::IfName, _entry: &PinholeEntry) -> i32 {
		let uid = self.next_uid;

		let raddr = if _entry.eaddr == Ipv6Addr::UNSPECIFIED {
			None
		} else {
			Some(&_entry.eaddr)
		};
		let desc = format!(
			"pinhole-{} ts-{}: {}",
			uid,
			_entry.timestamp,
			_entry.desc.as_ref().map(|x| x.as_str()).unwrap_or_default()
		);

		if let Some(r) = rule_set_filter6(
			&self.nft_table,
			&self.nft_forward_chain,
			self.nft_ipv6_family as u8,
			&ifname.as_cstr(),
			_entry.proto,
			raddr,
			&_entry.iaddr,
			0,
			_entry.iport,
			_entry.eport,
			Some(desc.as_str()),
			None,
		) {
			if self.nft_send_rule(r, NFT_MSG_NEWRULE, RULE_CHAIN_FILTER) < 0 {
				return -1;
			}
			self.next_uid += 1;
			if self.next_uid >= 65535 {
				self.next_uid = 1;
			}
			return uid as i32;
		}
		-ENOMEM
	}

	fn update_pinhole(&mut self, uid: u16, _timestamp: u32) -> i32 {
		self.refresh_nft_cache_(RULE_CHAIN_FILTER);

		let label_start = format!("pinhole-{}", uid);

		let rule = self.filter_rule.iter().find(|x| x.type_0 == RULE_FILTER && x.desc.starts_with(&label_start));

		if let Some(r) = rule {
			if let Some(n) = rule_del_handle(r, self.nft_nat_family) {
				if self.nft_send_rule(n, NFT_MSG_DELRULE, RULE_CHAIN_FILTER) < 0 {
					return -1;
				}
			}
		}
		let rule = self
			.filter_rule
			.iter()
			.find(|x| x.type_0 == RULE_FILTER && x.desc.starts_with(&label_start))
			.unwrap();

		let comment = format!(
			"pinhole-{} ts-{}: {}",
			uid,
			_timestamp,
			rule.desc.as_str().split_ascii_whitespace().nth(2).unwrap_or_default()
		);
		let mut ifname = [0u8; libc::IF_NAMESIZE];
		unsafe { libc::if_indextoname(rule.ingress_ifidx, ifname.as_mut_ptr() as _) };

		let rhost = if rule.saddr6 == Ipv6Addr::UNSPECIFIED {
			None
		} else {
			Some(&rule.saddr6)
		};

		if let Some(r) = rule_set_filter6(
			&self.nft_table,
			&self.nft_forward_chain,
			self.nft_ipv6_family as u8,
			&unsafe { CStr::from_ptr(ifname.as_ptr() as _) },
			rule.proto,
			rhost,
			&rule.daddr6,
			0,
			rule.dport,
			rule.sport,
			Some(comment.as_str()),
			None,
		) {
			let _ = rule;
			if self.nft_send_rule(r, NFT_MSG_NEWRULE, RULE_CHAIN_FILTER) < 0 {
				return -1;
			}
			0
		} else {
			-ENOMEM
		}
	}

	fn delete_pinhole(&mut self, _uid: u16) -> i32 {
		self.refresh_nft_cache_(RULE_CHAIN_FILTER);

		let label_start = format!("pinhole-{}", _uid);

		let rule = self.filter_rule.iter().find(|x| x.type_0 == RULE_FILTER && x.desc.starts_with(&label_start));
		if rule.is_none() {
			return -2;
		}
		let rule = rule.unwrap();
		if let Some(r) = rule_del_handle(rule, self.nft_nat_family) {
			let _ = rule;
			self.nft_send_rule(r, NFT_MSG_DELRULE, RULE_CHAIN_FILTER);
			return 0;
		}
		-ENOMEM
	}

	fn clean_pinhole_list(&mut self, next_timestamp: &mut u32) -> i32 {
		let cur_time = upnp_time().as_secs();
		let mut del_cnt = 0;
		let mut min_uid = i32::MAX;
		let mut max_uid = i32::MIN;
		let mut min_ts = u32::MAX;

		self.refresh_nft_cache_(RULE_CHAIN_FILTER);
		let mut idx = 0;
		while idx < self.filter_rule.len() {
			if self.filter_rule[idx].type_0 != RULE_FILTER {
				idx += 1;
				continue;
			}
			if self.filter_rule[idx].desc.is_empty() {
				idx += 1;
				continue;
			}

			if let Some((uid, ts)) = parse_pinhole_desc(&self.filter_rule[idx].desc) {
				if ts <= cur_time as u32 {
					info!("removing expired pinhole '{}'", self.filter_rule[idx].desc);
					if let Some(r) = rule_del_handle(&self.filter_rule[idx], self.nft_nat_family) {
						self.nft_send_rule(r, NFT_MSG_DELRULE, RULE_CHAIN_FILTER);
						del_cnt += 1;
					}
				} else {
					if uid as i32 > max_uid {
						max_uid = uid as i32;
					} else if (uid as i32) < min_uid {
						min_uid = uid as i32;
					}
					if ts < min_ts {
						min_ts = ts;
					}
				}
			} else {
				debug!("rule with label '{}' is not a IGD pinhole", &self.filter_rule[idx].desc);
				idx += 1;
				continue;
			}
		}

		if min_ts != u32::MAX {
			*next_timestamp = min_ts;
		}
		if max_uid > 0 {
			if min_uid - 32000 <= self.next_uid as _ && self.next_uid <= max_uid as _ {
				self.next_uid = (max_uid + 1) as u32;
			}
			if self.next_uid >= 65535 {
				self.next_uid = 1;
			}
		}

		del_cnt
	}
	fn get_redir_chain_name(&self) -> &str {
		self.nft_prerouting_chain.to_str().unwrap()
	}
}

impl nftable {
	fn remove_timestamp_entry(&mut self, eport: u16, proto: u8) {
		let len = self.timestamp_list.len();
		self.timestamp_list.retain(|x| x.eport != eport && x.proto == proto);

		if len == self.timestamp_list.len() {
			warn!("remove_timestamp_entry({}, {}) no entry found", eport, proto);
		}
	}
	fn add_timestamp_entry(&mut self, eport: u16, proto: u8, timestamp: u32) {
		self.timestamp_list.push(timestamp_entry { timestamp, eport, proto })
	}
}

#[cfg(test)]
mod tests {}