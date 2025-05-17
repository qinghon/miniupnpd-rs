#![allow(
	dead_code,
	mutable_transmutes,
	non_camel_case_types,
	non_snake_case,
	non_upper_case_globals,
	unused_assignments,
	unused_mut
)]
#![allow(improper_ctypes)]

use super::iptcrdr::iptc::*;
use crate::netfilter::iptcrdr::*;
use crate::{PinholeEntry, TCP, UDP, UDPLITE};
use libc::{__errno_location, c_char};
use std::ffi::{CStr, CString};
use std::net::Ipv6Addr;
use std::rc::Rc;
use std::{mem, ptr};

pub(super) const IP6T_F_PROTO: u8 = 0x01;

#[derive(Copy, Clone)]
#[repr(C)]
pub(super) struct ip6t_ip6 {
	pub(super) src: Ipv6Addr,
	pub(super) dst: Ipv6Addr,
	pub(super) smsk: Ipv6Addr,
	pub(super) dmsk: Ipv6Addr,
	pub(super) iniface: [libc::c_char; 16],
	pub(super) outiface: [libc::c_char; 16],
	pub(super) iniface_mask: [u8; 16],
	pub(super) outiface_mask: [u8; 16],
	pub(super) proto: u16,
	pub(super) tos: u8,
	pub(super) flags: u8,
	pub(super) invflags: u8,
}

#[derive(Clone)]
#[repr(C)]
pub(super) struct pinhole_t {
	pub(super) saddr: Ipv6Addr,
	pub(super) daddr: Ipv6Addr,
	pub(super) timestamp: u32,
	pub(super) sport: u16,
	pub(super) dport: u16,
	pub(super) uid: u16,
	pub(super) proto: u8,
	pub(super) desc: Option<Rc<str>>,
}

pub(super) struct Ip6Handle(*mut xtc_handle);
impl Ip6Handle {
	#[inline]
	pub(super) fn delete_num_entry(&self, chain: &CStr, index: u32) -> i32 {
		if self.0.is_null() {
			return -1;
		}
		unsafe { ip6tc_delete_num_entry(chain.as_ptr(), index, self.0) }
	}
	#[inline]
	pub(super) fn commit(&self) -> i32 {
		unsafe { ip6tc_commit(self.0) }
	}
}

pub(super) struct Ip6tableIter<'a> {
	handle: *mut xtc_handle,
	chain: CString,
	cur: *const ip6t_entry,
	entry: PinholeEntry,
	backend: &'a iptable,
	index: u32,
}

impl Ip6tableIter<'_> {
	pub(super) fn new<'a>(ipt: &'a iptable, table: &CStr, chain: &CStr) -> Option<Ip6tableIter<'a>> {
		let h = unsafe { ip6tc_init(table.as_ptr()) };
		if h.is_null() {
			return None;
		}
		if unsafe { ip6tc_is_chain(chain.as_ptr(), h) } == 0 {
			unsafe { ip6tc_free(h) };
			return None;
		}
		let ch = chain.to_owned();
		Some(Ip6tableIter {
			handle: h,
			chain: ch,
			entry: PinholeEntry::default(),
			cur: ptr::null_mut(),
			backend: ipt,
			index: 0,
		})
	}
	pub(super) fn get_handle(&self) -> Ip6Handle {
		Ip6Handle(self.handle)
	}
}
impl<'a> Iterator for Ip6tableIter<'a> {
	type Item = &'a PinholeEntry;

	fn next(&mut self) -> Option<&'a PinholeEntry> {
		if self.handle.is_null() {
			return None;
		}
		unsafe {
			let mut e = if self.index == 0 {
				ip6tc_first_rule(self.chain.as_ptr(), self.handle)
			} else {
				ip6tc_next_rule(self.cur, self.handle)
			};

			if e.is_null() {
				return None;
			}
			let entry_ref = &*e;
			let proto = entry_ref.ipv6.proto as u8;
			let match_ = e.add(1) as *const xt_entry_match;
			let match_ref = &*match_;

			let (eport, iport) = if match_ref.u.user.name[0..4] == *mem::transmute::<&[u8; 4], &[c_char; 4]>(b"tcp\0") {
				let info = &*(match_.add(1) as *const xt_tcp);
				(info.dpts[0], info.spts[0])
			} else {
				let info = &*(match_.add(1) as *const xt_udp);
				(info.dpts[0], info.spts[0])
			};
			// let target = e.byte_add(entry_ref.target_offset as usize) as *const xt_entry_target;
			// let mr = target.add(1) as *const nf_nat_multi_range_compat;
			// let mr_ref = &*mr;
			let iaddr = Ipv6Addr::from(entry_ref.ipv6.src.s6_addr);
			let eaddr = Ipv6Addr::from(entry_ref.ipv6.dst.s6_addr);
			// let iport = u16::from_be(mr_ref.range[0].min.all);
			self.cur = e;
			self.entry = PinholeEntry {
				index: self.index,
				proto,
				iport,
				rport: eport,
				iaddr,
				raddr: eaddr,
				desc: None,
				packets: entry_ref.counters.pcnt,
				bytes: entry_ref.counters.bcnt,
				timestamp: 0,
			};
			// if let Some(desc) = self.backend.get_redirect_desc(eport, proto) {
			// 	self.entry.desc.clear();
			// 	self.entry.desc.push_str(desc.desc.as_str());
			// 	self.entry.timestamp = desc.timestamp;
			// }
			self.index += 1;
			Some(&*((&self.entry) as *const PinholeEntry))
		}
	}
	fn count(self) -> usize
	where
		Self: Sized,
	{
		let mut count = 0;
		let mut e = unsafe { ip6tc_first_rule(self.chain.as_ptr(), self.handle) };
		while !e.is_null() {
			count += 1;
			e = unsafe { ip6tc_next_rule(self.cur, self.handle) };
		}
		count
	}
}
impl Drop for Ip6tableIter<'_> {
	fn drop(&mut self) {
		if !self.handle.is_null() {
			unsafe { ip6tc_free(self.handle) };
		}
	}
}

pub(super) fn ip6tc_add_entry<P>(table: &CStr, chain: &CStr, entry: &PinholeEntry, target: Target, mut f: P) -> i32
where
	P: FnMut(&mut ip6t_entry),
{
	const entry_size: usize = size_of::<ip6t_entry>();
	let match_size = if entry.proto == TCP {
		get_tcp_match_size()
	} else {
		get_udp_match_size()
	};
	let target_size = match target {
		Target::Accept => get_accept_target_size(),
		// unsupported other target
		_ => return -1,
	};
	let mut buf: Vec<u8> = vec![0; entry_size + match_size + target_size];
	let e_ptr = buf.as_mut_ptr() as *mut ip6t_entry;
	let e = unsafe { e_ptr.as_mut().unwrap() };
	e.ipv6.proto = entry.proto as u16;
	match target {
		Target::Accept => {
			ip6_new_match(&mut buf[entry_size..], entry.proto, entry.rport, entry.iport);
			get_accept_target(&mut buf[entry_size + match_size..])
		}
		_ => return -1,
	};

	e.target_offset = (entry_size + match_size) as _;
	e.next_offset = (entry_size + match_size + target_size) as _;

	f(e);
	ip6tc_init_verify_and_append(table, chain, e_ptr)
}

fn ip6_new_match(buf: &mut [u8], proto: u8, dport: u16, sport: u16) {
	let match_ = unsafe { (buf.as_mut_ptr() as *mut xt_entry_match).as_mut().unwrap() };
	let tcp_info = unsafe { (match_.data.as_mut_ptr() as *mut u8 as *mut xt_tcp).as_mut().unwrap() };

	match_.u.match_size = get_tcp_match_size() as u16;
	match proto {
		TCP => unsafe { match_.u.user.name[0..4].clone_from_slice(mem::transmute::<&[u8; 4], &[c_char; 4]>(b"tcp\0")) },
		UDP => unsafe { match_.u.user.name[0..4].clone_from_slice(mem::transmute::<&[u8; 4], &[c_char; 4]>(b"udp\0")) },
		UDPLITE => unsafe {
			match_.u.user.name[0..8].clone_from_slice(mem::transmute::<&[u8; 8], &[c_char; 8]>(b"udplite\0"))
		},
		_ => {}
	}
	unsafe { match_.u.user.name[0..4].clone_from_slice(mem::transmute::<&[u8; 4], &[c_char; 4]>(b"tcp\0")) };
	if sport == 0 {
		tcp_info.spts[0] = 0;
		tcp_info.spts[1] = 0xffff;
	} else {
		tcp_info.spts[0] = sport;
		tcp_info.spts[1] = sport;
	}

	tcp_info.dpts[0] = dport;
	tcp_info.dpts[1] = dport;
}
const fn ip6_new_match_size() -> usize {
	get_tcp_match_size()
}

fn ip6tc_init_verify_and_append(table: &CStr, chain: &CStr, entry: *const ip6t_entry) -> i32 {
	let h = unsafe { ip6tc_init(table.as_ptr()) };
	if h.is_null() {
		error!("ip6tc_init() error : {}", last_ip6tc_error());
		return -1;
	}
	unsafe {
		let ret = 'free: {
			if ip6tc_is_chain(chain.as_ptr(), h) == 0 {
				error!("chain {} not found", chain.to_string_lossy());
				break 'free -1;
			}
			if ip6tc_append_entry(chain.as_ptr(), entry, h) == 0 {
				error!("ip6tc_append_entry() error : {}", last_ip6tc_error());
				break 'free -1;
			}
			if ip6tc_commit(h) == 0 {
				error!("ip6tc_commit() error : {}", last_ip6tc_error());
				break 'free -1;
			}
			0
		};
		ip6tc_free(h);
		ret
	}
}
#[inline]
pub(super) fn last_ip6tc_error() -> &'static str {
	unsafe {
		let errno = *__errno_location();
		CStr::from_ptr(ip6tc_strerror(errno)).to_str().unwrap()
	}
}
