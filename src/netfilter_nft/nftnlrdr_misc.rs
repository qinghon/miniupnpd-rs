#![allow(
	dead_code,
	mutable_transmutes,
	non_camel_case_types,
	non_snake_case,
	non_upper_case_globals,
	unused_assignments,
	unused_mut,
	improper_ctypes
)]

mod nftnl {
	include!(concat!(env!("OUT_DIR"), "/nftnl.rs"));
}
use super::nftnlrdr::nftable;
use crate::linux::os_impl::page_size;
use crate::{IfName, MapEntry, PinholeEntry, Rc};
use libc::NFPROTO_IPV4;
use libc::NFT_REG_VERDICT;
use libc::nlmsghdr;
use libc::{NF_ACCEPT, NFNL_MSG_BATCH_BEGIN, NFNL_MSG_BATCH_END, NLM_F_REQUEST};
use libc::{NFT_PAYLOAD_TRANSPORT_HEADER, c_int, c_uint};
use nftnl::*;
// pub(super) use mnl::mnl_socket;
use std::cmp::max;
use std::ffi::CString;
use std::ffi::{CStr, c_char, c_void};
use std::fmt::Debug;
use std::mem::{offset_of, size_of};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr::{NonNull, slice_from_raw_parts};
use std::{io, mem, ptr};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(super) struct IpHdr {
	pub(super) iv: u8,
	pub(super) tos: u8,
	pub(super) tot_len: u16,
	pub(super) id: u16,
	pub(super) frag_off: u16,
	pub(super) ttl: u8,
	pub(super) protocol: u8,
	pub(super) check: u16,
	pub(super) saddr: Ipv4Addr,
	pub(super) daddr: Ipv4Addr,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(super) struct Ipv6Hdr {
	pub(super) iv: u8,
	pub(super) flow_lbl: [u8; 3],
	pub(super) payload_len: u16,
	pub(super) nexthdr: u8,
	pub(super) hop_limit: u8,
	pub(super) saddr: Ipv4Addr,
	pub(super) daddr: Ipv4Addr,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(super) struct TcpHdr {
	pub(super) source: u16,
	pub(super) dest: u16,
	pub(super) seq: u32,
	pub(super) ack_seq: u32,
	pub(super) flags: u16,
	pub(super) window: u16,
	pub(super) check: u16,
	pub(super) urg_ptr: u16,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(super) struct UdpHdr {
	pub(super) source: u16,
	pub(super) dest: u16,
	pub(super) len: u16,
	pub(super) check: u16,
}

use nftnl_rule_attr::*;

#[derive(Copy, Clone)]
#[repr(C)]
pub(super) struct nfgenmsg {
	pub(super) nfgen_family: u8,
	pub(super) version: u8,
	pub(super) res_id: u16,
}
use libc::NFT_REG_1;
use libc::NFT_REG_2;

use libc::NFT_CMP_EQ;
use libc::NFT_META_IIF;
use libc::NFT_META_OIF;
use libc::NFT_MSG_GETRULE;
use libc::NFT_NAT_DNAT;
use libc::NFT_NAT_SNAT;
use libc::NFT_PAYLOAD_NETWORK_HEADER;

// pub(super)type mnl_cb_t = Option<extern "C" fn(*const nlmsghdr, *mut c_void) -> i32>;

#[derive(Copy, Clone, Eq, PartialEq, Default, Debug)]
#[repr(u8)]
pub(super) enum rule_reg_type {
	#[default]
	RULE_REG_NONE,
	RULE_REG_IIF,
	RULE_REG_OIF,
	RULE_REG_IP_SRC_ADDR,
	RULE_REG_IP_DEST_ADDR,
	RULE_REG_IP_SD_ADDR, /* source & dest */
	RULE_REG_IP6_SRC_ADDR,
	RULE_REG_IP6_DEST_ADDR,
	RULE_REG_IP6_SD_ADDR, /* source & dest */
	RULE_REG_IP_PROTO,
	RULE_REG_IP6_PROTO,
	RULE_REG_TCP_SPORT,
	RULE_REG_TCP_DPORT,
	RULE_REG_TCP_SD_PORT, /* source & dest */
	RULE_REG_IMM_VAL,     /* immediate */
	RULE_REG_MAX,
}
use rule_reg_type::*;
#[derive(Copy, Clone, PartialEq, Default, Debug)]
#[repr(u8)]
pub(super) enum rule_type {
	#[default]
	RULE_NONE = 0,
	RULE_NAT = 1,
	RULE_FILTER = 2,
	RULE_COUNTER = 3,
}
use rule_type::*;

#[derive(Copy, Clone, Default)]
#[repr(u8)]
pub(super) enum rule_chain_type {
	#[default]
	RULE_CHAIN_FILTER,
	RULE_CHAIN_PEER,
	RULE_CHAIN_REDIRECT,
}
use crate::linux::netfilter;
use crate::linux::netfilter::MnlSocket;
use crate::linux::netfilter::mnl::*;
use crate::netfilter_nft::nftnlrdr_misc::nftnl::nftnl_output_type::NFTNL_OUTPUT_DEFAULT;
use crate::upnputils::upnp_time;
use crate::warp::{Ip4Addr, copy_from_slice};
use crate::{TCP, UDP};

const RULE_CACHE_INVALID: bool = false;
const RULE_CACHE_VALID: bool = true;

#[derive(Clone, Debug)]
#[repr(C)]
pub(super) struct rule_t {
	pub(super) table: CString,
	pub(super) chain: CString,
	pub(super) handle: u64,
	pub(super) type_0: rule_type,
	pub(super) nat_type: u32,
	pub(super) family: u32,
	pub(super) ingress_ifidx: u32,
	pub(super) egress_ifidx: u32,

	pub(super) saddr: Ipv4Addr,
	pub(super) daddr: Ipv4Addr,
	pub(super) nat_addr: Ipv4Addr,

	pub(super) saddr6: Ipv6Addr,
	pub(super) daddr6: Ipv6Addr,

	pub(super) sport: u16,
	pub(super) dport: u16,
	pub(super) nat_port: u16,
	pub(super) proto: u8,

	pub(super) packets: u64,
	pub(super) bytes: u64,
	pub(super) desc: Rc<str>,
}
impl Default for rule_t {
	fn default() -> Self {
		Self {
			table: Default::default(),
			chain: Default::default(),
			handle: 0,
			type_0: Default::default(),
			nat_type: 0,
			family: 0,
			ingress_ifidx: 0,
			egress_ifidx: 0,
			saddr: Ipv4Addr::UNSPECIFIED,
			saddr6: Ipv6Addr::UNSPECIFIED,
			sport: 0,
			daddr: Ipv4Addr::UNSPECIFIED,
			daddr6: Ipv6Addr::UNSPECIFIED,
			dport: 0,
			nat_addr: Ipv4Addr::UNSPECIFIED,
			nat_port: 0,
			proto: 0,
			// reg1_type: Default::default(),
			// reg2_type: Default::default(),
			// reg1_val: 0,
			// reg2_val: 0,
			packets: 0,
			bytes: 0,
			desc: Rc::from(""),
		}
	}
}
#[derive(Clone, Debug, Default)]
struct parse_ctx {
	pub(super) reg1_type: rule_reg_type,
	pub(super) reg2_type: rule_reg_type,
	pub(super) reg1_val: u32,
	pub(super) reg2_val: u32,
}

#[repr(C)]
pub(super) struct table_cb_data<'a> {
	pub(super) table: &'a CStr,
	pub(super) chain: &'a CStr,
	pub(super) type_0: rule_type,
	pub(super) head: &'a mut Vec<rule_t>,
}
#[repr(transparent)]
pub(super) struct NftnlRule(NonNull<nftnl_rule>);

impl NftnlRule {
	pub(super) fn new() -> Option<Self> {
		let rule = unsafe { nftnl_rule_alloc() };
		if rule.is_null() {
			error!("nftnl_rule_alloc() Failed");
		}
		Some(Self(unsafe { NonNull::new_unchecked(rule) }))
	}

	#[inline]
	pub(super) fn set_u32(&mut self, attr: c_uint, value: u32) {
		unsafe { nftnl_rule_set_u32(self.0.as_ptr(), attr as _, value) }
	}
	#[inline]
	pub(super) fn set_u64(&mut self, attr: c_uint, value: u64) {
		unsafe { nftnl_rule_set_u64(self.0.as_ptr(), attr as _, value) }
	}
	#[inline]
	pub(super) fn set_str(&mut self, attr: c_uint, value: &CStr) -> i32 {
		unsafe { nftnl_rule_set_str(self.0.as_ptr(), attr as _, value.as_ptr()) }
	}
	#[inline]
	pub(super) fn set_data(&mut self, attr: c_uint, data: &[u8]) -> i32 {
		unsafe {
			nftnl_rule_set_data(
				self.0.as_ptr(),
				attr as _,
				data.as_ptr() as *const c_void,
				data.len() as u32,
			)
		}
	}
	#[inline]
	pub(super) fn is_set(&self, attr: c_uint) -> bool {
		unsafe { nftnl_rule_is_set(self.0.as_ptr(), attr as _) }
	}
	#[inline]
	pub(super) fn get_u32(&self, attr: c_uint) -> u32 {
		unsafe { nftnl_rule_get_u32(self.0.as_ptr(), attr as _) }
	}
	#[inline]
	pub(super) fn get_u64(&self, attr: c_uint) -> u64 {
		unsafe { nftnl_rule_get_u64(self.0.as_ptr(), attr as _) }
	}
	#[inline]
	pub(super) fn get_str(&self, attr: c_uint) -> *const c_char {
		unsafe { nftnl_rule_get_str(self.0.as_ptr(), attr as _) }
	}
	#[inline]
	pub(super) fn get_data(&self, attr: c_uint) -> &[u8] {
		let mut data_len = 0u32;
		let data = unsafe { nftnl_rule_get_data(self.0.as_ptr(), attr as _, &mut data_len) };
		unsafe { &*slice_from_raw_parts(data as *const u8, data_len as usize) }
	}
	#[inline]
	pub(super) fn add_expr(&mut self, expr: NftnlExpr) {
		unsafe {
			nftnl_rule_add_expr(self.0.as_ptr(), expr.0);
			mem::forget(expr);
		}
	}
	pub(super) fn nlmsg_parse(&mut self, nlmsg: *const nlmsghdr) -> i32 {
		unsafe { nftnl_rule_nlmsg_parse(nlmsg, self.0.as_ptr()) }
	}
	pub(super) fn nlmsg_build_payload(&mut self, nlmsg: *mut nlmsghdr) {
		unsafe { nftnl_rule_nlmsg_build_payload(nlmsg, self.0.as_ptr()) }
	}
	#[inline]
	pub(super) fn iter(&self) -> Option<NftnlExprIter> {
		let i = unsafe { nftnl_expr_iter_create(self.0.as_ptr()) };
		if i.is_null() {
			None
		} else {
			Some(unsafe { NonNull::new_unchecked(i).into() })
		}
	}
}

impl Debug for NftnlRule {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let mut buf = [0u8; 4096];
		let len = unsafe { nftnl_rule_snprintf(buf.as_mut_ptr() as _, 4096, self.0.as_ptr(), NFTNL_OUTPUT_DEFAULT, 0) };
		if len > 0 {
			f.write_str(unsafe { str::from_utf8_unchecked(&buf[0..len as usize]) })
		} else {
			Ok(())
		}
	}
}
impl Drop for NftnlRule {
	fn drop(&mut self) {
		unsafe { nftnl_rule_free(self.0.as_ptr()) }
	}
}
#[repr(transparent)]
pub(super) struct NftnlExprIter(pub(super) NonNull<nftnl_expr_iter>);
impl From<NonNull<nftnl_expr_iter>> for NftnlExprIter {
	#[inline]
	fn from(iter: NonNull<nftnl_expr_iter>) -> Self {
		Self(iter)
	}
}
impl Drop for NftnlExprIter {
	fn drop(&mut self) {
		unsafe { nftnl_expr_iter_destroy(self.0.as_ptr()) }
	}
}
impl Iterator for NftnlExprIter {
	type Item = NftnlExpr;
	#[inline]
	fn next(&mut self) -> Option<Self::Item> {
		let i = unsafe { nftnl_expr_iter_next(self.0.as_ptr()) };
		if i.is_null() { None } else { Some(i.into()) }
	}
}
#[repr(transparent)]
pub(super) struct NftnlExpr(*mut nftnl_expr);
impl From<*mut nftnl_expr> for NftnlExpr {
	#[inline]
	fn from(iter: *mut nftnl_expr) -> Self {
		Self(iter)
	}
}
impl NftnlExpr {
	#[inline]
	pub(super) fn new(name: &CStr) -> Option<Self> {
		let d = unsafe { nftnl_expr_alloc(name.as_ptr()) };
		if d.is_null() {
			error!("nftnl_expr_alloc(\"{}\") FAILED", name.to_str().unwrap());
			None
		} else {
			Some(Self(d))
		}
	}
	#[inline]
	pub(super) fn set_u32(&mut self, t: u16, value: u32) {
		unsafe { nftnl_expr_set_u32(self.0, t, value) }
	}
	#[inline]
	pub(super) fn set_u16(&mut self, t: u16, value: u16) {
		unsafe { nftnl_expr_set_u16(self.0, t, value) }
	}
	#[inline]
	pub(super) fn set(&mut self, t: u16, value: &[u8]) -> i32 {
		unsafe { nftnl_expr_set(self.0, t, value.as_ptr() as *const c_void, value.len() as u32) }
	}
	#[inline]
	pub(super) fn get(&self, t: u16) -> Option<&[u8]> {
		let mut data_len = 0u32;
		unsafe {
			let data = nftnl_expr_get(self.0, t, &mut data_len);
			if data.is_null() {
				None
			} else {
				Some(&*slice_from_raw_parts(data as *const u8, data_len as usize))
			}
		}
	}
	#[inline]
	pub(super) fn get_u32(&self, t: u16) -> u32 {
		unsafe { nftnl_expr_get_u32(self.0, t) }
	}
	#[inline]
	pub(super) fn get_u64(&self, t: u16) -> u64 {
		unsafe { nftnl_expr_get_u64(self.0, t) }
	}
	#[inline]
	pub(super) fn get_str(&self, t: u16) -> *const c_char {
		unsafe { nftnl_expr_get_str(self.0, t) }
	}
}

impl Debug for NftnlExpr {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let mut buf = [0u8; 4096];
		let len = unsafe { nftnl_expr_snprintf(buf.as_mut_ptr() as _, buf.len(), self.0, NFTNL_OUTPUT_DEFAULT, 0) };
		if len > 0 {
			f.write_str(unsafe { str::from_utf8_unchecked(&buf[0..len as usize]) })
		} else {
			Ok(())
		}
	}
}

// impl Drop for NftnlExpr {
// 	#[inline]
// 	fn drop(&mut self) {
// 		unsafe { nftnl_expr_free(self.0) }
// 	}
// }

impl nftable {
	pub(super) fn nft_mnl_connect(&mut self) -> i32 {
		let mnl_sock = MnlSocket::open(libc::NETLINK_NETFILTER);
		if mnl_sock.is_none() {
			error!("mnl_socket_open() FAILED: %m");
			return -1;
		}
		let mnl_sock = mnl_sock.unwrap();
		if mnl_sock.bind(0, netfilter::mnl::MNL_SOCKET_AUTOPID as _) < 0 {
			error!("mnl_socket_bind() FAILED: %m");
			return -1;
		}
		self.mnl_portid = mnl_sock.get_portid();
		self.mnl_sock = Some(mnl_sock);
		info!("mnl_socket bound, port_id={}", self.mnl_portid);

		0
	}
	pub(super) fn nft_mnl_dissconnect(&mut self) {
		let _ = self.mnl_sock.take();
	}
}

fn set_reg(ctx: &mut parse_ctx, dreg: u32, reg_type: rule_reg_type, val: u32) {
	match dreg as _ {
		NFT_REG_1 => {
			ctx.reg1_type = reg_type;
			if reg_type == RULE_REG_IMM_VAL {
				ctx.reg1_val = val;
			}
		}
		NFT_REG_2 => {
			ctx.reg2_type = reg_type;
			if reg_type == RULE_REG_IMM_VAL {
				ctx.reg2_val = val;
			}
		}
		NFT_REG_VERDICT => {}
		_ => {
			error!("unknown reg:{}", dreg);
		}
	}
}
fn parse_rule_immediate(e: &NftnlExpr, _r: &mut rule_t, ctx: &mut parse_ctx) {
	let dreg = e.get_u32(NFTNL_EXPR_IMM_DREG as _);
	let mut reg_val = 0;
	if dreg == NFT_REG_VERDICT as _ {
		reg_val = e.get_u32(NFTNL_EXPR_IMM_VERDICT as _);
	} else if let Some(p) = e.get(NFTNL_EXPR_IMM_DATA as _) {
		match p.len() {
			4 => copy_from_slice(&mut reg_val, p),
			2 => reg_val = u16::from_ne_bytes([p[0], p[1]]) as u32,
			_ => {
				error!("nftnl_expr_get() reg_len={}", p.len());
				return;
			}
		}
	} else {
		error!("nftnl_expr_get() failed for reg:{}", dreg);
		return;
	}
	set_reg(ctx, dreg, RULE_REG_IMM_VAL, reg_val);
}
fn parse_rule_counter(e: &NftnlExpr, r: &mut rule_t) {
	r.type_0 = RULE_COUNTER;
	r.bytes = e.get_u64(NFTNL_EXPR_CTR_BYTES as _);
	r.packets = e.get_u64(NFTNL_EXPR_CTR_PACKETS as _);
}
fn parse_rule_meta(e: &NftnlExpr, _r: &mut rule_t, ctx: &mut parse_ctx) {
	let key = e.get_u32(NFTNL_EXPR_META_KEY as _) as _;
	let dreg = e.get_u32(NFTNL_EXPR_META_DREG as _);

	/* ToDo: body of both cases are identical - bug? */
	match key {
		NFT_META_IIF => set_reg(ctx, dreg, RULE_REG_IIF, 0),
		NFT_META_OIF => set_reg(ctx, dreg, RULE_REG_IIF, 0),
		_ => {
			debug!("parse_rule_meta :Not support key {}", key);
		}
	}
}
fn parse_rule_nat(e: &NftnlExpr, r: &mut rule_t, ctx: &mut parse_ctx) {
	// Set rule type to NAT
	r.type_0 = RULE_NAT;

	// Get NAT type and family
	r.nat_type = e.get_u32(NFTNL_EXPR_NAT_TYPE as _);
	r.family = e.get_u32(NFTNL_EXPR_NAT_FAMILY as _);

	// Get register numbers for addresses and ports
	let addr_min_reg = e.get_u32(NFTNL_EXPR_NAT_REG_ADDR_MIN as _);
	let addr_max_reg = e.get_u32(NFTNL_EXPR_NAT_REG_ADDR_MAX as _);
	let proto_min_reg = e.get_u32(NFTNL_EXPR_NAT_REG_PROTO_MIN as _);
	let proto_max_reg = e.get_u32(NFTNL_EXPR_NAT_REG_PROTO_MAX as _);

	// Check if ranges are used (not supported)
	if addr_min_reg != addr_max_reg || proto_min_reg != proto_max_reg {
		error!("Unsupport proto/addr range for NAT");
	}

	// Get and process protocol (port) value
	let proto_min_val = match proto_min_reg as _ {
		NFT_REG_1 => u16::from_be(ctx.reg1_val as u16),
		NFT_REG_2 => u16::from_be(ctx.reg2_val as u16),
		_ => {
			error!("parse_rule_nat: invalid proto_min_reg {}", proto_min_reg);
			0
		}
	};
	debug!("parse_rule_nat: proto_min_reg {}: => {}", proto_min_reg, proto_min_val);

	// Get and process address value
	let addr = match addr_min_reg as _ {
		NFT_REG_1 => ctx.reg1_val,
		NFT_REG_2 => ctx.reg2_val,
		_ => {
			error!("parse_rule_nat: invalid addr_min_reg {}", addr_min_reg);
			0
		}
	};
	r.nat_addr = Ip4Addr::from(addr).into();
	r.nat_port = proto_min_val;

	// Reset registers
	set_reg(ctx, NFT_REG_1 as _, RULE_REG_NONE, 0);
	set_reg(ctx, NFT_REG_2 as _, RULE_REG_NONE, 0);
}
fn parse_rule_payload(e: &NftnlExpr, _r: &mut rule_t, ctx: &mut parse_ctx) {
	let dreg = e.get_u32(NFTNL_EXPR_PAYLOAD_DREG as _);
	let base = e.get_u32(NFTNL_EXPR_PAYLOAD_BASE as _) as _;
	let offset = e.get_u32(NFTNL_EXPR_PAYLOAD_OFFSET as _);
	let len = e.get_u32(NFTNL_EXPR_PAYLOAD_LEN as _);

	if !matches!(dreg as _, NFT_REG_1 | NFT_REG_2) {
		error!("parse_rule_payload: unsupported dreg {}", dreg);
		return;
	}
	let mut reg_type = RULE_REG_NONE;

	match base {
		NFT_PAYLOAD_NETWORK_HEADER => {
			// IPv4 header offsets
			const IPHDR_DADDR_OFF: u8 = offset_of!(IpHdr, daddr) as _;
			const IPHDR_SADDR_OFF: u8 = offset_of!(IpHdr, saddr) as _;
			const IPHDR_PROTO_OFF: u8 = offset_of!(IpHdr, protocol) as _;

			// IPv6 header offsets
			const IPV6HDR_NEXTHDR_OFF: u8 = offset_of!(Ipv6Hdr, nexthdr) as _;
			const IPV6HDR_SADDR_OFF: u8 = offset_of!(Ipv6Hdr, saddr) as _;
			const IPV6HDR_DADDR_OFF: u8 = offset_of!(Ipv6Hdr, daddr) as _;

			match (offset as _, len) {
				(IPHDR_DADDR_OFF, 4) => {
					reg_type = RULE_REG_IP_DEST_ADDR;
				}
				(IPHDR_SADDR_OFF, 4) => {
					reg_type = RULE_REG_IP_SRC_ADDR;
				}
				(IPHDR_SADDR_OFF, 8) => {
					reg_type = RULE_REG_IP_SD_ADDR;
				}
				(IPHDR_PROTO_OFF, 1) => {
					reg_type = RULE_REG_IP_PROTO;
				}
				(IPV6HDR_NEXTHDR_OFF, 1) => {
					reg_type = RULE_REG_IP6_PROTO;
				}
				(IPV6HDR_DADDR_OFF, 16) => {
					reg_type = RULE_REG_IP6_DEST_ADDR;
				}
				(IPV6HDR_SADDR_OFF, 16) => {
					reg_type = RULE_REG_IP6_SRC_ADDR;
				}
				(IPV6HDR_SADDR_OFF, 32) => {
					reg_type = RULE_REG_IP6_SD_ADDR;
				}
				_ => {
					error!(
						"Unsupported payload: (dreg:{}, base:NETWORK_HEADER, offset:{}, len:{})",
						dreg, offset, len
					);
				}
			}
		}
		NFT_PAYLOAD_TRANSPORT_HEADER => {
			// TCP/UDP header offsets
			const TCPHDR_DEST_OFF: u32 = offset_of!(TcpHdr, dest) as _; // offsetof(struct TcpHdr, dest)
			const TCPHDR_SOURCE_OFF: u32 = offset_of!(TcpHdr, source) as _; // offsetof(struct TcpHdr, source)

			match (offset, len) {
				(o, l) if o == TCPHDR_DEST_OFF && l == 2 => {
					reg_type = RULE_REG_TCP_DPORT;
				}
				(o, l) if o == TCPHDR_SOURCE_OFF && l == 2 => {
					reg_type = RULE_REG_TCP_SPORT;
				}
				(o, l) if o == TCPHDR_SOURCE_OFF && l == 4 => {
					reg_type = RULE_REG_TCP_SD_PORT;
				}
				_ => {
					error!(
						"Unsupported payload: (dreg:{}, base:TRANSPORT_HEADER, offset:{}, len:{})",
						dreg, offset, len
					);
				}
			}
		}
		_ => {
			error!(
				"Unsupported payload: (dreg:{}, base:{}, offset:{}, len:{})",
				dreg, base, offset, len
			);
		}
	}
	match dreg as _ {
		NFT_REG_1 => ctx.reg1_type = reg_type,
		NFT_REG_2 => ctx.reg2_type = reg_type,
		_ => {}
	}
}
fn parse_rule_cmp(e: &NftnlExpr, r: &mut rule_t, ctx: &mut parse_ctx) {
	unsafe {
		let op = e.get_u32(NFTNL_EXPR_CMP_OP as _);
		if op != NFT_CMP_EQ as u32 {
			return;
		}

		let sreg = e.get_u32(NFTNL_EXPR_CMP_SREG as _);

		if sreg != NFT_REG_1 as _ {
			error!("parse_rule_cmp: Unsupport reg:{}", sreg);
			return;
		}

		let data_val = e.get(NFTNL_EXPR_CMP_DATA as _);
		if data_val.is_none() {
			error!("parse_rule_cmp: nftnl_expr_get(NFTNL_EXPR_CMP_DATA as _) returned NULL");
			return;
		}
		let data_len = data_val.unwrap().len() as u32;
		let data_val = data_val.unwrap().as_ptr();
		match ctx.reg1_type {
			RULE_REG_IIF => {
				if data_len == size_of::<u32>() as u32 {
					r.ingress_ifidx = *(data_val as *const u32);
				}
			}
			RULE_REG_IP_SRC_ADDR => {
				if data_len == size_of::<u32>() as u32 {
					r.saddr = Ipv4Addr::from(*(data_val as *const u32));
				}
			}
			RULE_REG_IP6_SRC_ADDR => {
				if data_len == size_of::<Ipv6Addr>() as u32 {
					r.saddr6 = *(data_val as *const Ipv6Addr);
				}
			}
			RULE_REG_IP_DEST_ADDR => {
				if data_len == size_of::<u32>() as u32 {
					r.daddr = Ipv4Addr::from((*(data_val as *const u32)).to_ne_bytes());
				}
			}
			RULE_REG_IP6_DEST_ADDR => {
				if data_len == size_of::<Ipv6Addr>() as u32 {
					r.daddr6 = *(data_val as *const Ipv6Addr);
				}
			}
			RULE_REG_IP_SD_ADDR => {
				if data_len == (size_of::<u32>() * 2) as u32 {
					let addrs = data_val as *const u32;
					r.saddr = Ipv4Addr::from(*addrs);
					r.daddr = Ipv4Addr::from(*addrs.add(1));
				}
			}
			RULE_REG_IP6_SD_ADDR => {
				if data_len == (size_of::<Ipv6Addr>() * 2) as u32 {
					let addrs = data_val as *const Ipv6Addr;
					r.saddr6 = *addrs;
					r.daddr6 = *addrs.add(1);
				}
			}
			RULE_REG_IP_PROTO | RULE_REG_IP6_PROTO => {
				if data_len == size_of::<u8>() as u32 {
					r.proto = *(data_val as *const u8);
				}
			}
			RULE_REG_TCP_SPORT => {
				if data_len == size_of::<u16>() as u32 {
					r.sport = u16::from_be(*(data_val as *const u16));
				}
			}
			RULE_REG_TCP_DPORT => {
				if data_len == size_of::<u16>() as u32 {
					r.dport = u16::from_be(*(data_val as *const u16));
				}
			}
			RULE_REG_TCP_SD_PORT => {
				if data_len == (size_of::<u16>() * 2) as u32 {
					let ports = data_val as *const u16;
					r.sport = u16::from_be(*ports);
					r.dport = u16::from_be(*ports.add(1));
				}
			}
			_ => {
				debug!(
					"Unknown cmp (r1type:{}, data_len:{}, op:{})",
					ctx.reg1_type as u8, data_len, op
				);
				trace!("unknown parse rule expr: {:?}", e);
				return;
			}
		}

		ctx.reg1_type = RULE_REG_NONE;
	}
}
fn rule_expr_cb(e: &NftnlExpr, r: &mut rule_t, ctx: &mut parse_ctx) -> i32 {
	unsafe {
		let attr_name = e.get_str(NFTNL_EXPR_NAME as _);

		if attr_name.is_null() {
			return MNL_CB_OK as _;
		}
		trace!(
			"parse expr: attr={} {:?} ",
			CStr::from_ptr(attr_name).to_str().unwrap_or(""),
			e
		);
		match CStr::from_ptr(attr_name).to_str().unwrap_or("") {
			"cmp" => parse_rule_cmp(e, r, ctx),
			"nat" => parse_rule_nat(e, r, ctx),
			"meta" => parse_rule_meta(e, r, ctx),
			"counter" => parse_rule_counter(e, r),
			"payload" => parse_rule_payload(e, r, ctx),
			"immediate" => parse_rule_immediate(e, r, ctx),
			unknown => {
				debug!("unknown attr: {}", unknown);
			}
		}
	}

	MNL_CB_OK as _
}
extern "C" fn table_cb(nlh: *const nlmsghdr, data: *mut libc::c_void) -> i32 {
	let mut result = MNL_CB_OK as _;
	let cb_data = unsafe { &mut *(data as *mut table_cb_data) };

	// Log debug information
	debug!(
		"table_cb({:p}, {:p}) {} {} {}",
		nlh,
		data,
		cb_data.table.to_str().unwrap(),
		cb_data.chain.to_str().unwrap(),
		cb_data.type_0 as u8
	);

	// Allocate new rule
	let rule = NftnlRule::new();
	if rule.is_none() {
		return MNL_CB_ERROR;
	}
	let mut rule = rule.unwrap();
	// Parse the netlink message into the rule
	if rule.nlmsg_parse(nlh) < 0 {
		error!("nftnl_rule_nlmsg_parse FAILED");
		result = MNL_CB_ERROR;
		return MNL_CB_ERROR;
	}
	let mut r = rule_t::default();

	let chain = rule.get_str(NFTNL_RULE_CHAIN);
	if chain.is_null() {
		return MNL_CB_OK as _;
	}

	let chain_cstr = unsafe { CStr::from_ptr(chain) };

	if cb_data.chain.to_str().unwrap() != chain_cstr.to_str().unwrap() {
		warn!("unknown chain '{}'", chain_cstr.to_str().unwrap());
		return MNL_CB_OK as _;
	}

	// r.table = unsafe { CString::from(CStr::from_ptr(rule.get_str(NFTNL_RULE_TABLE) as *mut _)) };

	// r.chain = CString::from(chain_cstr);
	r.table = cb_data.table.into();
	r.chain = cb_data.chain.into();

	r.family = rule.get_u32(NFTNL_RULE_FAMILY);

	// Handle user data (description)
	if rule.is_set(NFTNL_RULE_USERDATA) {
		let descr = rule.get_data(NFTNL_RULE_USERDATA);
		if !descr.is_empty() {
			r.desc = Rc::from(unsafe { str::from_utf8_unchecked(descr) });
		}
	}

	r.handle = rule.get_u64(NFTNL_RULE_HANDLE);
	r.type_0 = cb_data.type_0;

	if let Some(iter) = rule.iter() {
		let mut ctx = parse_ctx::default();
		for itr in iter {
			rule_expr_cb(&itr, &mut r, &mut ctx);
		}
	}

	debug!(" cb rule {:?}", r);
	match r.type_0 {
		RULE_NAT => match r.nat_type as _ {
			NFT_NAT_SNAT | NFT_NAT_DNAT => {
				cb_data.head.push(r);
			}
			_ => {
				warn!("unknown nat type {}", r.nat_type);
			}
		},
		RULE_FILTER => {
			cb_data.head.push(r);
		}
		_ => {
			warn!("unknown rule type {}", r.type_0 as u8);
		}
	}
	result
}

impl nftable {
	pub(super) fn refresh_nft_cache_(&mut self, chain: rule_chain_type) -> i32 {
		match chain {
			rule_chain_type::RULE_CHAIN_FILTER => {
				if self.rule_list_filter_validate != RULE_CACHE_VALID {
					let r = Self::refresh_nft_cache(
						self.mnl_sock.as_ref().unwrap(),
						&mut self.mnl_seq,
						self.mnl_portid,
						&mut self.filter_rule,
						&self.nft_table,
						&self.nft_forward_chain,
						self.nft_ipv4_family as _,
						RULE_FILTER,
					);
					if r < 0 {
						-1
					} else {
						self.rule_list_filter_validate = RULE_CACHE_VALID;
						0
					}
				} else {
					0
				}
			}
			rule_chain_type::RULE_CHAIN_PEER => {
				if self.rule_list_peer_validate != RULE_CACHE_VALID {
					let r = Self::refresh_nft_cache(
						self.mnl_sock.as_ref().unwrap(),
						&mut self.mnl_seq,
						self.mnl_portid,
						&mut self.peer_rule,
						&self.nft_nat_table,
						&self.nft_postrouting_chain,
						self.nft_nat_family as _,
						RULE_NAT,
					);
					if r < 0 {
						-1
					} else {
						self.rule_list_peer_validate = RULE_CACHE_VALID;
						0
					}
				} else {
					0
				}
			}
			rule_chain_type::RULE_CHAIN_REDIRECT => {
				if self.rule_list_redirect_validate != RULE_CACHE_VALID {
					let r = Self::refresh_nft_cache(
						self.mnl_sock.as_ref().unwrap(),
						&mut self.mnl_seq,
						self.mnl_portid,
						&mut self.redirect_rule,
						&self.nft_nat_table,
						&self.nft_prerouting_chain,
						self.nft_nat_family as _,
						RULE_NAT,
					);
					if r < 0 {
						-1
					} else {
						self.rule_list_redirect_validate = RULE_CACHE_VALID;
						0
					}
				} else {
					0
				}
			}
		}
	}

	pub(super) fn flush_nft_cache(head: &mut Vec<rule_t>) {
		head.clear();
		head.shrink_to_fit();
	}

	pub(super) fn refresh_nft_cache(
		mnl_sock: &MnlSocket,
		mnl_seq: &mut u32,
		mnl_portid: u32,
		head: &mut Vec<rule_t>,
		table: &CStr,
		chain: &CStr,
		family: c_int,
		type_0: rule_type,
	) -> i32 {
		let mut buf = vec![0u8; max(page_size(), 8192)];

		// if mnl_sock.is_null() {
		// 	error!("netlink not connected");
		// 	return -1;
		// }

		Self::flush_nft_cache(head);

		let mut data = table_cb_data { table, chain, type_0, head };

		let rule = NftnlRule::new();
		if rule.is_none() {
			return -1;
		}
		let mut rule = rule.unwrap();
		// Build netlink message header
		*mnl_seq = upnp_time().as_secs() as u32;
		let nlh = unsafe {
			nftnl_nlmsg_build_hdr(
				buf.as_mut_ptr() as *mut libc::c_char,
				NFT_MSG_GETRULE as u16,
				family as u16,
				libc::NLM_F_DUMP as u16,
				*mnl_seq,
			)
		};

		rule.set_str(NFTNL_RULE_TABLE, table);
		rule.set_str(NFTNL_RULE_CHAIN, chain);
		rule.nlmsg_build_payload(nlh);
		drop(rule);

		// Send message
		if unsafe { mnl_socket_sendto(mnl_sock.as_ptr(), nlh as *const c_void, (*nlh).nlmsg_len as usize) } < 0 {
			error!("mnl_socket_sendto() FAILED: %m");
			return -1;
		}
		'exit: loop {
			let n = unsafe { mnl_socket_recvfrom(mnl_sock.as_ptr(), buf.as_mut_ptr() as *mut c_void, buf.capacity()) };
			if n < 0 {
				error!("mnl_socket_recvfrom FAILED: %m");
				return -1;
			} else if n == 0 {
				break 'exit 0;
			}
			unsafe {
				*libc::__errno_location() = 0;
			}
			let ret = unsafe {
				mnl_cb_run(
					buf.as_ptr() as *const c_void,
					n as usize,
					*mnl_seq,
					mnl_portid,
					Some(table_cb),
					&mut data as *mut table_cb_data as *mut c_void,
				)
			};

			if ret <= MNL_CB_ERROR {
				error!("mnl_cb_run returned {}: {}", ret, io::Error::last_os_error());
				return -1;
			}

			if ret == MNL_CB_STOP as _ {
				break 'exit 0;
			}
		}
	}
}
fn expr_add_payload(r: &mut NftnlRule, base: c_int, dreg: c_int, offset: u32, len: u32) {
	let e = NftnlExpr::new(c"payload");
	if e.is_none() {
		return;
	}
	let mut e = e.unwrap();

	e.set_u32(NFTNL_EXPR_PAYLOAD_BASE as _, base as _);
	e.set_u32(NFTNL_EXPR_PAYLOAD_DREG as _, dreg as u32);
	e.set_u32(NFTNL_EXPR_PAYLOAD_OFFSET as _, offset);
	e.set_u32(NFTNL_EXPR_PAYLOAD_LEN as _, len);

	r.add_expr(e);
}
fn expr_add_cmp(r: &mut NftnlRule, sreg: c_int, op: c_int, data: &[u8]) {
	let e = NftnlExpr::new(c"cmp");
	if e.is_none() {
		return;
	}
	let mut e = e.unwrap();

	e.set_u32(NFTNL_EXPR_CMP_SREG as _, sreg as _);
	e.set_u32(NFTNL_EXPR_CMP_OP as _, op as _);
	e.set(NFTNL_EXPR_CMP_DATA as _, data);

	r.add_expr(e);
}
fn expr_add_counter(r: &mut NftnlRule) {
	if let Some(e) = NftnlExpr::new(c"counter") {
		r.add_expr(e);
	}
}

fn expr_add_meta(r: &mut NftnlRule, meta_key: c_int, dreg: c_int) {
	let e = NftnlExpr::new(c"meta");
	if e.is_none() {
		return;
	}
	let mut e = e.unwrap();

	e.set_u32(NFTNL_EXPR_META_KEY as _, meta_key as _);
	e.set_u32(NFTNL_EXPR_META_DREG as _, dreg as _);
	r.add_expr(e);
}
fn expr_set_reg_val_u32(r: &mut NftnlRule, dreg: c_int, val: u32) {
	let e = NftnlExpr::new(c"immediate");
	if e.is_none() {
		return;
	}
	let mut e = e.unwrap();
	e.set_u32(NFTNL_EXPR_IMM_DREG as _, dreg as _);
	e.set_u32(NFTNL_EXPR_IMM_DATA as _, val);
	r.add_expr(e);
}

fn expr_set_reg_val_u16(r: &mut NftnlRule, dreg: u32, val: u16) {
	let e = NftnlExpr::new(c"immediate");
	if e.is_none() {
		return;
	}
	let mut e = e.unwrap();
	e.set_u32(NFTNL_EXPR_IMM_DREG as _, dreg);
	e.set_u16(NFTNL_EXPR_IMM_DATA as _, val);
	r.add_expr(e);
}

fn expr_set_reg_verdict(r: &mut NftnlRule, val: u32) {
	let e = NftnlExpr::new(c"immediate");
	if e.is_none() {
		return;
	}
	let mut e = e.unwrap();
	e.set_u32(NFTNL_EXPR_IMM_DREG as _, NFT_REG_VERDICT as _);
	e.set_u32(NFTNL_EXPR_IMM_VERDICT as _, val);
	r.add_expr(e);
}

fn expr_add_nat(r: &mut NftnlRule, t: c_int, family: c_int, addr_min: Ipv4Addr, proto_min: u16) {
	let e = NftnlExpr::new(c"nat");
	if e.is_none() {
		return;
	}
	let mut e = e.unwrap();
	e.set_u32(NFTNL_EXPR_NAT_TYPE as _, t as _);
	e.set_u32(NFTNL_EXPR_NAT_FAMILY as _, family as _);

	expr_set_reg_val_u32(r, NFT_REG_1, Ip4Addr::from(addr_min).into());
	e.set_u32(NFTNL_EXPR_NAT_REG_ADDR_MIN as _, NFT_REG_1 as u32);
	e.set_u32(NFTNL_EXPR_NAT_REG_ADDR_MAX as _, NFT_REG_1 as u32);

	expr_set_reg_val_u16(r, NFT_REG_2 as u32, proto_min);
	e.set_u32(NFTNL_EXPR_NAT_REG_PROTO_MIN as _, NFT_REG_2 as u32);
	e.set_u32(NFTNL_EXPR_NAT_REG_PROTO_MAX as _, NFT_REG_2 as u32);

	r.add_expr(e);
}
pub(super) fn rule_set_snat(
	table: &CStr,
	chain: &CStr,
	family: u8,
	proto: u8,
	rhost: Ipv4Addr, // in_addr_t (remote host)
	rport: u16,      // remote port
	ehost: Ipv4Addr, // in_addr_t (external host)
	eport: u16,      // external port
	ihost: Ipv4Addr, // in_addr_t (internal host)
	iport: u16,      // internal port
	descr: Option<&str>,
	_handle: Option<&str>, // Unused parameter
) -> Option<NftnlRule> {
	let mut rule = NftnlRule::new()?;

	// Set basic rule properties
	rule.set_u32(NFTNL_RULE_FAMILY, family as u32);

	rule.set_str(NFTNL_RULE_TABLE, table);
	rule.set_str(NFTNL_RULE_CHAIN, chain);

	// Set description if provided
	if let Some(desc) = descr {
		if !desc.is_empty() {
			rule.set_data(NFTNL_RULE_USERDATA, desc.as_bytes());
		}
	}

	// Destination IP
	expr_add_payload(
		&mut rule,
		NFT_PAYLOAD_NETWORK_HEADER,
		NFT_REG_1,
		offset_of!(IpHdr, daddr) as u32,
		size_of::<u32>() as u32,
	);
	expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, ihost.as_octets());

	// Source IP
	expr_add_payload(
		&mut rule,
		NFT_PAYLOAD_NETWORK_HEADER,
		NFT_REG_1,
		offset_of!(IpHdr, saddr) as u32,
		size_of::<u32>() as u32,
	);
	expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, rhost.as_octets());

	// Protocol
	expr_add_payload(
		&mut rule,
		NFT_PAYLOAD_NETWORK_HEADER,
		NFT_REG_1,
		offset_of!(IpHdr, protocol) as u32,
		size_of::<u8>() as u32,
	);
	expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, &proto.to_be_bytes());

	// Handle ports based on protocol
	match proto {
		TCP => {
			// Destination port
			expr_add_payload(
				&mut rule,
				NFT_PAYLOAD_TRANSPORT_HEADER,
				NFT_REG_1,
				offset_of!(TcpHdr, dest) as u32,
				size_of::<u16>() as u32,
			);
			expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, &iport.to_be_bytes());

			// Source port
			expr_add_payload(
				&mut rule,
				NFT_PAYLOAD_TRANSPORT_HEADER,
				NFT_REG_1,
				offset_of!(TcpHdr, source) as u32,
				size_of::<u16>() as u32,
			);
			expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, &rport.to_be_bytes());
		}
		UDP => {
			// Destination port
			expr_add_payload(
				&mut rule,
				NFT_PAYLOAD_TRANSPORT_HEADER,
				NFT_REG_1,
				offset_of!(UdpHdr, dest) as u32,
				size_of::<u16>() as u32,
			);
			expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, &iport.to_be_bytes());

			// Source port
			expr_add_payload(
				&mut rule,
				NFT_PAYLOAD_TRANSPORT_HEADER,
				NFT_REG_1,
				offset_of!(UdpHdr, source) as u32,
				size_of::<u16>() as u32,
			);
			expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, &rport.to_be_bytes());
		}
		_ => {}
	}

	// Add NAT expression
	expr_add_nat(&mut rule, NFT_NAT_SNAT, NFPROTO_IPV4, ehost, eport.to_be());

	// debug_rule(rule);

	Some(rule)
}

pub(super) fn rule_set_dnat(
	family: u8,
	table: &CStr,
	chain: &CStr,
	ifname: &IfName,
	entry: &MapEntry,
) -> Option<NftnlRule> {
	// Allocate new rule
	let mut rule = NftnlRule::new()?;

	// Set basic rule properties
	rule.set_u32(NFTNL_RULE_FAMILY, family as u32);
	rule.set_str(NFTNL_RULE_TABLE, table);
	rule.set_str(NFTNL_RULE_CHAIN, chain);

	// Set description if provided
	if let Some(desc) = &entry.desc {
		if !desc.is_empty() {
			rule.set_data(NFTNL_RULE_USERDATA, desc.as_bytes());
		}
	}

	// Set interface if provided
	#[cfg(feature = "rule_use_ifname")]
	if !ifname.is_empty() {
		let if_idx = unsafe { libc::if_nametoindex(ifname.as_ptr()) } as u32;
		expr_add_meta(&mut rule, NFT_META_IIF, NFT_REG_1);
		expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, &if_idx.to_ne_bytes());
	}

	// Source IP if provided
	if !entry.raddr.is_unspecified() {
		expr_add_payload(
			&mut rule,
			NFT_PAYLOAD_NETWORK_HEADER,
			NFT_REG_1,
			offset_of!(IpHdr, saddr) as u32,
			size_of::<u32>() as u32,
		);
		expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, entry.raddr.as_octets());
	}

	// Protocol
	expr_add_payload(
		&mut rule,
		NFT_PAYLOAD_NETWORK_HEADER,
		NFT_REG_1,
		offset_of!(IpHdr, protocol) as u32,
		size_of::<u8>() as u32,
	);
	expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, &entry.proto.to_ne_bytes());

	// Handle ports based on protocol
	match entry.proto {
		TCP => {
			let dport = entry.eport.to_be();
			expr_add_payload(
				&mut rule,
				NFT_PAYLOAD_TRANSPORT_HEADER,
				NFT_REG_1,
				offset_of!(TcpHdr, dest) as u32,
				size_of::<u16>() as u32,
			);
			expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, &dport.to_ne_bytes());
		}
		UDP => {
			let dport = entry.eport.to_be();
			expr_add_payload(
				&mut rule,
				NFT_PAYLOAD_TRANSPORT_HEADER,
				NFT_REG_1,
				offset_of!(UdpHdr, dest) as u32,
				size_of::<u16>() as u32,
			);
			expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, &dport.to_ne_bytes());
		}
		_ => {}
	}

	// Counter
	expr_add_counter(&mut rule);

	// Add NAT expression
	expr_add_nat(&mut rule, NFT_NAT_DNAT, NFPROTO_IPV4, entry.iaddr, entry.iport.to_be());

	// debug_rule(rule);

	Some(rule)
}

pub(super) fn rule_set_filter(
	table: &CStr,
	chain: &CStr,
	family: u8,
	ifname: &IfName,
	entry: &MapEntry,
) -> Option<NftnlRule> {
	// Allocate new rule
	let mut rule = NftnlRule::new()?;

	rule_set_filter_common(
		table,
		chain,
		&mut rule,
		family,
		ifname,
		entry.proto,
		entry.eport,
		entry.iport,
		entry.rport,
		entry.desc.as_deref(),
	);
	expr_add_payload(
		&mut rule,
		NFT_PAYLOAD_NETWORK_HEADER,
		NFT_REG_1,
		offset_of!(IpHdr, daddr) as u32,
		size_of::<Ipv4Addr>() as u32,
	);
	expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, entry.iaddr.as_octets());

	if !entry.raddr.is_unspecified() {
		expr_add_payload(
			&mut rule,
			NFT_PAYLOAD_NETWORK_HEADER,
			NFT_REG_1,
			offset_of!(IpHdr, saddr) as u32,
			4,
		);
		expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, entry.raddr.as_octets());
	}

	expr_add_payload(
		&mut rule,
		NFT_PAYLOAD_NETWORK_HEADER,
		NFT_REG_1,
		offset_of!(IpHdr, protocol) as u32,
		1,
	);
	expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, &entry.proto.to_ne_bytes());
	expr_set_reg_verdict(&mut rule, NF_ACCEPT as _);

	Some(rule)
}

pub(super) fn rule_set_filter6(
	table: &CStr,
	chain: &CStr,
	family: u8,
	ifname: &IfName,
	entry: &PinholeEntry,
	descr: Option<&str>,
) -> Option<NftnlRule> {
	let mut rule = NftnlRule::new()?;

	rule_set_filter_common(
		table,
		chain,
		&mut rule,
		family,
		ifname,
		entry.proto,
		0,
		entry.iport,
		entry.rport,
		descr.as_deref(),
	);
	expr_add_payload(
		&mut rule,
		NFT_PAYLOAD_NETWORK_HEADER,
		NFT_REG_1,
		offset_of!(Ipv6Hdr, daddr) as u32,
		size_of::<Ipv6Addr>() as u32,
	);
	expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, entry.iaddr.as_octets());
	if !entry.raddr.is_unspecified() {
		expr_add_payload(
			&mut rule,
			NFT_PAYLOAD_NETWORK_HEADER,
			NFT_REG_1,
			offset_of!(Ipv6Hdr, saddr) as u32,
			size_of::<Ipv6Addr>() as u32,
		);
		expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, entry.raddr.as_octets());
	}

	expr_add_payload(
		&mut rule,
		NFT_PAYLOAD_NETWORK_HEADER,
		NFT_REG_1,
		offset_of!(IpHdr, protocol) as u32,
		1,
	);
	expr_add_cmp(&mut rule, NFT_REG_1, NFT_CMP_EQ, &entry.proto.to_ne_bytes());
	expr_set_reg_verdict(&mut rule, NF_ACCEPT as _);
	Some(rule)
}

pub(super) fn rule_set_filter_common(
	table: &CStr,
	chain: &CStr,
	rule: &mut NftnlRule,
	family: u8,
	ifname: &IfName,
	proto: u8,
	_eport: u16, // ignored parameter
	iport: u16,  // destination port
	rport: u16,  // optional source port
	descr: Option<&str>,
) {
	// Set basic rule properties
	rule.set_u32(NFTNL_RULE_FAMILY, family as u32);
	rule.set_str(NFTNL_RULE_TABLE, table);
	rule.set_str(NFTNL_RULE_CHAIN, chain);

	// Set description if provided
	if let Some(desc) = descr {
		if !desc.is_empty() {
			rule.set_data(NFTNL_RULE_USERDATA, desc.as_bytes());
		}
	}

	// Set interface if provided
	#[cfg(feature = "rule_use_ifname")]
	if !ifname.is_empty() {
		let if_idx = unsafe { libc::if_nametoindex(ifname.as_ptr()) } as u32;
		expr_add_meta(rule, NFT_META_IIF, NFT_REG_1);
		expr_add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &if_idx.to_ne_bytes());
	}

	// Destination port

	match proto {
		TCP => {
			expr_add_payload(
				rule,
				NFT_PAYLOAD_TRANSPORT_HEADER,
				NFT_REG_1,
				offset_of!(TcpHdr, dest) as u32,
				size_of::<u16>() as u32,
			);
		}
		UDP => {
			expr_add_payload(
				rule,
				NFT_PAYLOAD_TRANSPORT_HEADER,
				NFT_REG_1,
				offset_of!(UdpHdr, dest) as u32,
				size_of::<u16>() as u32,
			);
		}
		_ => {}
	}
	expr_add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &iport.to_be_bytes());

	// Source port if provided
	if rport != 0 {
		match proto {
			TCP => {
				expr_add_payload(
					rule,
					NFT_PAYLOAD_TRANSPORT_HEADER,
					NFT_REG_1,
					offset_of!(TcpHdr, source) as u32,
					size_of::<u16>() as u32,
				);
			}
			UDP => {
				expr_add_payload(
					rule,
					NFT_PAYLOAD_TRANSPORT_HEADER,
					NFT_REG_1,
					offset_of!(UdpHdr, source) as u32,
					size_of::<u16>() as u32,
				);
			}
			_ => {}
		}
		expr_add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &rport.to_be_bytes());
	}
}

pub(super) fn rule_del_handle(rule: &rule_t, nft_nat_family: u8) -> Option<NftnlRule> {
	let mut r = NftnlRule::new()?;
	if rule.type_0 == RULE_NAT {
		r.set_u32(NFTNL_RULE_FAMILY, nft_nat_family as _);
	} else {
		r.set_u32(NFTNL_RULE_FAMILY, rule.family);
	}
	r.set_str(NFTNL_RULE_TABLE, &rule.table);
	r.set_str(NFTNL_RULE_CHAIN, &rule.chain);
	r.set_u64(NFTNL_RULE_HANDLE, rule.handle);
	Some(r)
}
fn nft_mnl_batch_put(buf: *mut u8, mut type_0: u16, mut seq: u32) {
	unsafe {
		let mut nlh = mnl_nlmsg_put_header(buf as _);
		let _nlh = &mut *nlh;
		_nlh.nlmsg_type = type_0;
		_nlh.nlmsg_flags = NLM_F_REQUEST as _;
		_nlh.nlmsg_seq = seq;

		let nfg = mnl_nlmsg_put_extra_header(nlh, size_of::<nfgenmsg>());
		let _nfg = &mut *(nfg as *mut nfgenmsg);
		_nfg.nfgen_family = libc::AF_INET as _;
		_nfg.version = libc::NFNETLINK_V0 as _;
		_nfg.res_id = libc::NFNL_SUBSYS_NFTABLES as _;
	}
}

impl nftable {
	pub(super) fn nft_send_rule(&mut self, mut rule: NftnlRule, cmd: c_int, chain_type: rule_chain_type) -> i32 {
		let mut buf = vec![0u8; max(page_size(), 8192)];

		let batch = self.start_batch(&mut buf);

		if batch.is_null() {
			return -1;
		}
		match chain_type {
			rule_chain_type::RULE_CHAIN_FILTER => self.rule_list_filter_validate = RULE_CACHE_INVALID,
			rule_chain_type::RULE_CHAIN_PEER => self.rule_list_peer_validate = RULE_CACHE_INVALID,
			rule_chain_type::RULE_CHAIN_REDIRECT => self.rule_list_redirect_validate = RULE_CACHE_INVALID,
		}

		let nlh = unsafe {
			nftnl_nlmsg_build_hdr(
				mnl_nlmsg_batch_current(batch) as _,
				cmd as _,
				rule.get_u32(NFTNL_RULE_FAMILY) as _,
				(libc::NLM_F_APPEND | libc::NLM_F_CREATE | libc::NLM_F_ACK) as _,
				self.mnl_seq,
			)
		};
		self.mnl_seq += 1;
		rule.nlmsg_build_payload(nlh);
		drop(rule);
		let ret = self.send_batch(batch);
		if ret < 0 {
			error!("nft_send_rule({}, {}) send_batch failed {}", cmd, chain_type as u8, ret);
		}
		ret
	}
	pub(super) fn start_batch(&mut self, buf: &mut [u8]) -> *mut mnl_nlmsg_batch {
		self.mnl_seq = upnp_time().as_secs() as _;
		if self.mnl_sock.is_none() {
			error!("netlink not connected");
			return ptr::null_mut();
		}
		let result = unsafe { mnl_nlmsg_batch_start(buf.as_mut_ptr() as _, buf.len()) };
		if result.is_null() {
			return ptr::null_mut();
		}
		nft_mnl_batch_put(buf.as_mut_ptr(), NFNL_MSG_BATCH_BEGIN as u16, self.mnl_seq);
		self.mnl_seq += 1;
		unsafe { mnl_nlmsg_batch_next(result) };
		result
	}
	pub(super) fn send_batch(&mut self, batch: *mut mnl_nlmsg_batch) -> i32 {
		unsafe {
			mnl_nlmsg_batch_next(batch);

			nft_mnl_batch_put(
				mnl_nlmsg_batch_current(batch) as _,
				NFNL_MSG_BATCH_END as _,
				self.mnl_seq,
			);
			self.mnl_seq += 1;
			mnl_nlmsg_batch_next(batch);

			if self.mnl_sock.is_none() {
				error!("netlink not connected");
				return -1;
			}

			let mut n = mnl_socket_sendto(
				self.mnl_sock.as_ref().unwrap().as_ptr(),
				mnl_nlmsg_batch_head(batch),
				mnl_nlmsg_batch_size(batch),
			);
			if n == -1 {
				error!("mnl_socket_sendto() FAILED: %m");
				return -2;
			}
			mnl_nlmsg_batch_stop(batch);
			let mut buf = vec![0u8; max(page_size(), 8192)];
			loop {
				n = mnl_socket_recvfrom(
					self.mnl_sock.as_ref().unwrap().as_ptr(),
					buf.as_mut_ptr() as _,
					buf.capacity(),
				);
				if n == -1 {
					error!("mnl_socket_recvfrom() FAILED: %m");
					return -3;
				} else if n == 0 {
					break;
				}
				*libc::__errno_location() = 0;
				let ret = mnl_cb_run(buf.as_mut_ptr() as _, n as _, 0, self.mnl_portid, None, ptr::null_mut());
				if ret <= -1 {
					error!(
						"send_batch: mnl_cb_run returned {}, {}",
						ret,
						io::Error::last_os_error()
					);
					return -4;
				}
				if ret == MNL_CB_STOP as _ {
					break;
				}
			}
			0
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Backend;
	use crate::log::openlog;
	fn check_root_premison() -> bool {
		let uid = unsafe { libc::getuid() };
		if uid != 0 {
			println!("skip this test with non-root, please run as \"sudo -E\"");
			return false;
		}
		true
	}
	fn opensys_log() {
		openlog(c"miniupnpd", libc::LOG_CONS | libc::LOG_PERROR, libc::LOG_USER);
	}
	#[test]
	fn test_nftnl_rule() {
		opensys_log();

		let mut rule = NftnlRule::new().unwrap();
		rule.set_str(NFTNL_RULE_TABLE, c"nat");
		let s = rule.get_str(NFTNL_RULE_TABLE);
		assert!(!s.is_null());
	}
	#[test]
	fn test_refresh_nft_cache() {
		opensys_log();

		let mut nft = nftable::init();
		assert_eq!(nft.init_redirect(), 0);
		let mut rules = vec![];
		let r = nftable::refresh_nft_cache(
			nft.mnl_sock.as_ref().unwrap(),
			&mut nft.mnl_seq,
			nft.mnl_portid,
			&mut rules,
			c"nat",
			c"POSTROUTING",
			NFPROTO_IPV4,
			RULE_NAT,
		);

		println!("{}", r);
		assert_eq!(r, 0);
		println!("{:?}", rules);

		unsafe { libc::closelog() };
	}
}
