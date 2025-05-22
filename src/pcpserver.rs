#![allow(dead_code)]

use crate::asyncsendto::*;

use crate::natpmp::*;
use crate::options::*;
use crate::upnpglobalvars::*;
use crate::upnppermissions::check_upnp_rule_against_permissions;
use crate::upnppinhole::*;
use crate::upnpredirect::*;
use crate::upnputils::*;
use crate::warp::copy_from_slice;
use crate::*;
use socket2::Socket;
use std::fmt;
use std::fmt::Formatter;
#[cfg(feature = "ipv6")]
use std::io;
#[cfg(feature = "pcp")]
use std::net::{IpAddr, SocketAddr};
use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::rc::Rc;

const PCP_MIN_LEN: u16 = 24;
const PCP_MAX_LEN: u16 = 1100;

const PCP_OPCODE_ANNOUNCE: u8 = 0;
const PCP_OPCODE_MAP: u8 = 1;
const PCP_OPCODE_PEER: u8 = 2;
#[cfg(feature = "pcp_sadscp")]
const PCP_OPCODE_SADSCP: u8 = 3;

/* Possible response codes sent by server, as a result of client request*/
const PCP_SUCCESS: u8 = 0;

const PCP_ERR_UNSUPP_VERSION: u8 = 1;
//  The version number at the start of the PCP Request
// header is not recognized by this PCP server.  This is a long
// lifetime error.  This document describes PCP version 2.
const PCP_ERR_NOT_AUTHORIZED: u8 = 2;
// The requested operation is disabled for this PCP
// client, or the PCP client requested an operation that cannot be
// fulfilled by the PCP server's security policy.  This is a long
// lifetime error.
const PCP_ERR_MALFORMED_REQUEST: u8 = 3;
// The request could not be successfully parsed.
// This is a long lifetime error.
const PCP_ERR_UNSUPP_OPCODE: u8 = 4;
//  Unsupported Opcode.  This is a long lifetime error.
const PCP_ERR_UNSUPP_OPTION: u8 = 5;
// Unsupported Option.  This error only occurs if the
// Option is in the mandatory-to-process range.  This is a long
// lifetime error.
const PCP_ERR_MALFORMED_OPTION: u8 = 6;
// Malformed Option (e.g., appears too many times,
// invalid length).  This is a long lifetime error.
const PCP_ERR_NETWORK_FAILURE: u8 = 7;
// The PCP server or the device it controls are
// experiencing a network failure of some sort (e.g., has not
// obtained an External IP address).  This is a short lifetime error.
const PCP_ERR_NO_RESOURCES: u8 = 8;
// Request is well-formed and valid, but the server has
// insufficient resources to complete the requested operation at this
// time.  For example, the NAT device cannot create more mappings at
// this time, is short of CPU cycles or memory, or is unable to
// handle the request due to some other temporary condition.  The
// same request may succeed in the future.  This is a system-wide
// error, different from USER_EX_QUOTA.  This can be used as a catch-
// all error, should no other error message be suitable.  This is a
// short lifetime error.
const PCP_ERR_UNSUPP_PROTOCOL: u8 = 9;
// Unsupported transport protocol, e.g.  SCTP in a
// NAT that handles only UDP and TCP.  This is a long lifetime error.
const PCP_ERR_USER_EX_QUOTA: u8 = 10;
//  This attempt to create a new mapping would exceed
// this subscriber's port quota.  This is a short lifetime error.
const PCP_ERR_CANNOT_PROVIDE_EXTERNAL: u8 = 11;
//  The suggested external port and/or
// external address cannot be provided.  This error MUST only be
// returned for:
//      *  MAP requests that included the PREFER_FAILURE Option
//          (normal MAP requests will return an available external port)
//      *  MAP requests for the SCTP protocol (PREFER_FAILURE is implied)
//      *  PEER requests
const PCP_ERR_ADDRESS_MISMATCH: u8 = 12;
//  The source IP address of the request packet does
// not match the contents of the PCP Client's IP Address field, due
// to an unexpected NAT on the path between the PCP client and the
// PCP-controlled NAT or firewall.  This is a long lifetime error.
const PCP_ERR_EXCESSIVE_REMOTE_PEERS: u8 = 13;
//  The PCP server was not able to create the
// filters in this request.  This result code MUST only be returned
// if the MAP request contained the FILTER Option.  See Section 13.3
// for processing information.  This is a long lifetime error.
/* PCP common request header*/
const PCP_COMMON_REQUEST_SIZE: u8 = 24;

/* PCP common response header*/
const PCP_COMMON_RESPONSE_SIZE: u8 = 24;

const PCP_OPTION_HDR_SIZE: u8 = 4;

const PCP_MAP_V2_SIZE: u8 = 36;

const PCP_MAP_V1_SIZE: u8 = 24;

/* same for both request and response */
const PCP_PEER_V1_SIZE: u8 = 44;

/* same for both request and response */
const PCP_PEER_V2_SIZE: u8 = 56;

const PCP_SADSCP_REQ_SIZE: u8 = 14;

const PCP_SADSCP_MASK: u8 = (1 << 6) - 1;

const PCP_PREFER_FAIL_OPTION_SIZE: u8 = 4;

const PCP_3RD_PARTY_OPTION_SIZE: u8 = 20;

const PCP_DSCP_MASK: u8 = (1 << 6) - 1;
const PCP_FLOW_PRIORITY_OPTION_SIZE: u8 = 8;

const PCP_FILTER_OPTION_SIZE: u8 = 24;

#[repr(C)]
pub struct pcp_info<'a> {
	pub version: u8,
	pub opcode: u8,
	pub result_code: u8,
	pub protocol: u8,
	pub lifetime: u32,
	pub epochtime: u32,
	pub nonce: [u32; 3],
	pub int_port: u16,
	pub ext_port: u16,
	pub int_ip: Ipv6Addr,

	pub ext_ip: Ipv6Addr,
	pub is_map_op: u8,
	pub is_peer_op: u8,
	#[cfg(feature = "pcp_peer")]
	pub peer_port: u16,
	#[cfg(feature = "pcp_peer")]
	pub peer_ip: Ipv6Addr,
	pub thirdp_ip: Option<Ipv6Addr>,
	pub mapped_ip: Ipv6Addr,
	pub pfailure_present: i32,
	pub sender_ip: Ipv6Addr,
	pub is_fw: bool,
	pub desc: Option<Rc<str>>,
	pub rt: Option<&'a mut RtOptions>,

	#[cfg(feature = "pcp_sadscp")]
	pub delay_tolerance: u8,
	#[cfg(feature = "pcp_sadscp")]
	pub loss_tolerance: u8,
	#[cfg(feature = "pcp_sadscp")]
	pub jitter_tolerance: u8,
	#[cfg(feature = "pcp_sadscp")]
	pub app_name: Rc<str>,
	#[cfg(feature = "pcp_sadscp")]
	pub sadscp_dscp: u8,
	#[cfg(feature = "pcp_sadscp")]
	pub matched_name: bool,
	#[cfg(feature = "pcp_sadscp")]
	pub is_sadscp_op: bool,

	#[cfg(feature = "pcp_flowp")]
	dscp_up: u8,
	#[cfg(feature = "pcp_flowp")]
	dscp_down: u8,
	#[cfg(feature = "pcp_flowp")]
	flowp_present: u8,
}
impl Default for pcp_info<'_> {
	fn default() -> Self {
		Self {
			version: 0,
			opcode: 0,
			result_code: 0,
			lifetime: 0,
			epochtime: 0,
			nonce: [0; 3],
			protocol: 0,
			int_port: 0,
			int_ip: Ipv6Addr::UNSPECIFIED,
			ext_port: 0,
			ext_ip: Ipv6Addr::UNSPECIFIED,
			#[cfg(feature = "pcp_peer")]
			peer_port: 0,
			#[cfg(feature = "pcp_peer")]
			peer_ip: Ipv6Addr::UNSPECIFIED,
			is_map_op: 0,
			is_peer_op: 0,
			thirdp_ip: None,
			mapped_ip: Ipv6Addr::UNSPECIFIED,
			pfailure_present: 0,
			sender_ip: Ipv6Addr::UNSPECIFIED,
			is_fw: false,
			desc: None,
			rt: None,

			#[cfg(feature = "pcp_sadscp")]
			delay_tolerance: 0,
			#[cfg(feature = "pcp_sadscp")]
			loss_tolerance: 0,
			#[cfg(feature = "pcp_sadscp")]
			jitter_tolerance: 0,
			#[cfg(feature = "pcp_sadscp")]
			app_name: Rc::from(""),
			#[cfg(feature = "pcp_sadscp")]
			sadscp_dscp: 0,
			#[cfg(feature = "pcp_sadscp")]
			matched_name: false,
			#[cfg(feature = "pcp_sadscp")]
			is_sadscp_op: false,

			#[cfg(feature = "pcp_flowp")]
			dscp_up: 0,
			#[cfg(feature = "pcp_flowp")]
			dscp_down: 0,
			#[cfg(feature = "pcp_flowp")]
			flowp_present: 0,
		}
	}
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct pcp_server_info {
	pub server_version: u8,
}

type pcp_options = u8;
const PCP_OPTION_3RD_PARTY: pcp_options = 1;
const PCP_OPTION_PREF_FAIL: pcp_options = 2;
const PCP_OPTION_FILTER: pcp_options = 3;
#[cfg(feature = "pcp_flowp")]
const PCP_OPTION_FLOW_PRIORITY: pcp_options = 4; /*TODO: change it to correct value*/

enum PcpOpCode {
	Announce = 0,
	Map,
	Peer,
	Sadscp,
}
impl fmt::Display for PcpOpCode {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		match self {
			PcpOpCode::Announce => write!(f, "ANNOUNCE"),
			PcpOpCode::Map => write!(f, "MAP"),
			PcpOpCode::Peer => write!(f, "PEER"),
			PcpOpCode::Sadscp => write!(f, "SADSCP"),
		}
	}
}

const this_server_info: pcp_server_info = pcp_server_info { server_version: 2 };

fn parseCommonRequestHeader(buf: &[u8], pcp_msg_info: &mut pcp_info) -> i32 {
	pcp_msg_info.version = buf[0];
	pcp_msg_info.opcode = buf[1] & 0x7F;
	pcp_msg_info.lifetime = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
	copy_from_slice(&mut pcp_msg_info.int_ip, &buf[8..24]);
	pcp_msg_info.mapped_ip = pcp_msg_info.int_ip;

	if pcp_msg_info.version > this_server_info.server_version {
		pcp_msg_info.result_code = PCP_ERR_UNSUPP_VERSION;
		return 1;
	}
	let v = global_option.get().unwrap();
	if pcp_msg_info.lifetime > v.max_lifetime as u32 {
		pcp_msg_info.lifetime = v.max_lifetime as u32;
	}
	if pcp_msg_info.lifetime < v.min_lifetime as u32 && pcp_msg_info.lifetime != 0 {
		pcp_msg_info.lifetime = v.min_lifetime as u32;
	}
	0
}
fn parsePCPMAP_version1(buf: &[u8], pcp_msg_info: &mut pcp_info) {
	pcp_msg_info.is_map_op = 1;
	pcp_msg_info.protocol = buf[0];
	pcp_msg_info.int_port = u16::from_be_bytes([buf[4], buf[5]]);
	pcp_msg_info.ext_port = u16::from_be_bytes([buf[6], buf[7]]);
	copy_from_slice(&mut pcp_msg_info.ext_ip, &buf[8..24]);
}
fn parsePCPMAP_version2(buf: &[u8], pcp_msg_info: &mut pcp_info) {
	pcp_msg_info.is_map_op = 1;
	copy_from_slice(&mut pcp_msg_info.nonce, &buf[0..12]);
	pcp_msg_info.protocol = buf[12];
	pcp_msg_info.int_port = u16::from_be_bytes([buf[16], buf[17]]);
	pcp_msg_info.ext_port = u16::from_be_bytes([buf[18], buf[19]]);
	copy_from_slice(&mut pcp_msg_info.ext_ip, &buf[20..36]);
}
#[cfg(feature = "pcp_peer")]
fn parsePCPPEER_version1(buf: &[u8], pcp_msg_info: &mut pcp_info) {
	pcp_msg_info.is_peer_op = 1;
	pcp_msg_info.protocol = buf[0];
	pcp_msg_info.int_port = u16::from_be_bytes([buf[4], buf[5]]);
	pcp_msg_info.ext_port = u16::from_be_bytes([buf[6], buf[7]]);
	copy_from_slice(&mut pcp_msg_info.ext_ip, &buf[8..24]);
	pcp_msg_info.peer_port = u16::from_be_bytes([buf[24], buf[25]]);
	copy_from_slice(&mut pcp_msg_info.peer_ip, &buf[28..44]);
}
#[cfg(feature = "pcp_peer")]
fn parsePCPPEER_version2(buf: &[u8], pcp_msg_info: &mut pcp_info) {
	pcp_msg_info.is_peer_op = 1;
	copy_from_slice(&mut pcp_msg_info.nonce, &buf[0..12]);
	pcp_msg_info.protocol = buf[12];
	pcp_msg_info.int_port = u16::from_be_bytes([buf[16], buf[17]]);
	pcp_msg_info.ext_port = u16::from_be_bytes([buf[18], buf[19]]);

	#[cfg(feature = "pcp_peer")]
	{
		pcp_msg_info.peer_port = u16::from_be_bytes([buf[36], buf[37]])
	};

	copy_from_slice(&mut pcp_msg_info.ext_ip, &buf[20..36]);
	#[cfg(feature = "pcp_peer")]
	copy_from_slice(&mut pcp_msg_info.peer_ip, &buf[40..56]);
}

#[cfg(feature = "pcp_sadscp")]
fn parseSADSCP(buf: &[u8], pcp_msg_info: &mut pcp_info) {
	pcp_msg_info.delay_tolerance = (buf[12] >> 6) & 3;
	pcp_msg_info.loss_tolerance = (buf[12] >> 4) & 3;
	pcp_msg_info.jitter_tolerance = (buf[12] >> 2) & 3;

	if pcp_msg_info.delay_tolerance == 3 || pcp_msg_info.loss_tolerance == 3 || pcp_msg_info.jitter_tolerance == 3 {
		pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
		return;
	}
	let app_name_len = buf[13];
	if let Ok(s) = str::from_utf8(&buf[14..14 + app_name_len as usize]) {
		pcp_msg_info.app_name = Rc::from(s);
	} else {
		pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
		return;
	}
}

fn parsePCPOption(pcp_buf: &[u8], remain: i32, pcp_msg_info: &mut pcp_info) -> i32 {
	if remain < PCP_OPTION_HDR_SIZE as i32 {
		pcp_msg_info.result_code = PCP_ERR_MALFORMED_OPTION;
	}
	let option_length = u16::from_be_bytes([pcp_buf[2], pcp_buf[3]]) + 4;
	if remain < option_length as i32 {
		pcp_msg_info.result_code = PCP_ERR_MALFORMED_OPTION;
		return 0;
	}

	match pcp_buf[0] {
		PCP_OPTION_3RD_PARTY => {
			if option_length != PCP_3RD_PARTY_OPTION_SIZE as u16 {
				pcp_msg_info.result_code = PCP_ERR_MALFORMED_OPTION;
				return 0;
			}
			trace!("PCP OPTION: \t Third party\n");
			trace!("Third PARTY IP: \t {:?}\n", pcp_msg_info.thirdp_ip);
			if pcp_msg_info.thirdp_ip.is_some() {
				error!("PCP: THIRD PARTY OPTION was already present. ");
				pcp_msg_info.result_code = PCP_ERR_MALFORMED_OPTION;
				return 0;
			} else {
				let mut ipv6 = Ipv6Addr::UNSPECIFIED;
				copy_from_slice(&mut ipv6, &pcp_buf[4..20]);
				pcp_msg_info.thirdp_ip = Some(ipv6);
				pcp_msg_info.mapped_ip = ipv6;
			}
		}
		PCP_OPTION_PREF_FAIL => {
			if option_length != PCP_PREFER_FAIL_OPTION_SIZE as u16 {
				pcp_msg_info.result_code = PCP_ERR_MALFORMED_OPTION;
				return 0;
			}
			trace!("PCP OPTION: \t Prefer failure");
			if pcp_msg_info.opcode != PCP_OPCODE_MAP {
				debug!("PCP: Unsupported OPTION for given OPCODE.");
				pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
			}
			if pcp_msg_info.pfailure_present != 0 {
				debug!("PCP: PREFERENCE FAILURE OPTION was already present. ");
				pcp_msg_info.result_code = PCP_ERR_MALFORMED_OPTION;
			} else {
				pcp_msg_info.pfailure_present = 1;
			}
		}
		PCP_OPTION_FILTER => {
			if option_length != PCP_FILTER_OPTION_SIZE as _ {
				pcp_msg_info.result_code = PCP_ERR_MALFORMED_OPTION;
				return 0;
			}
			trace!("PCP OPTION: \t Filter\n");
			if pcp_msg_info.opcode != PCP_OPCODE_MAP {
				debug!("PCP: Unsupported OPTION for given OPCODE.");
				pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
				return 0;
			}
		}
		#[cfg(feature = "pcp_flowp")]
		PCP_OPTION_FLOW_PRIORITY => {
			trace!("PCP OPTION: \t Flow priority\n");
			if option_length != PCP_FLOW_PRIORITY_OPTION_SIZE as _ {
				error!(
					"PCP: Error processing DSCP. sizeof {} and remaining {}. flow len {} \n",
					PCP_FLOW_PRIORITY_OPTION_SIZE,
					remain,
					u16::from_be_bytes([pcp_buf[2], pcp_buf[3]])
				);
				pcp_msg_info.result_code = PCP_ERR_MALFORMED_OPTION;
				return 0;
			}
			trace!("DSCP UP: \t {}", pcp_buf[4]);
			trace!("DSCP DOWN: \t {}", pcp_buf[5]);
			pcp_msg_info.dscp_up = pcp_buf[4];
			pcp_msg_info.dscp_down = pcp_buf[5];
			pcp_msg_info.flowp_present = 1;
		}
		_ => {
			if pcp_buf[0] < 128 {
				error!("PCP: Unrecognized mandatory PCP OPTION: {}", pcp_buf[0]);
				pcp_msg_info.result_code = PCP_ERR_UNSUPP_OPTION;
			}
		}
	}
	option_length as i32
}
fn parsePCPOptions(pcp_buf: &[u8], remain: i32, pcp_msg_info: &mut pcp_info) {
	let mut buf = pcp_buf;
	let mut remain = remain;
	while remain > 0 {
		let option_length = parsePCPOption(buf, remain, pcp_msg_info);
		if option_length == 0 {
			break;
		}
		remain -= option_length;
		buf = &buf[option_length as usize..];
	}
	if remain > 0 {
		warn!("parsePCPOptions: remain={}", remain);
	}
}
// CheckExternalAddress()
// Check that suggested external address in request match a real external
// IP address.
// Suggested address can also be 0 IPv4 or IPv6 address.
//  (see http://tools.ietf.org/html/rfc6887#section-10 )
// return values :
//   0 : check is OK
//  -1 : check failed
#[cfg(feature = "pcp")]
fn CheckExternalAddress(pcp_msg_info: &mut pcp_info) -> bool {
	use crate::getifaddr::*;

	let ipv4 = pcp_msg_info.mapped_ip.is_ipv4_mapped();

	pcp_msg_info.is_fw = !ipv4;

	let external_addr = if pcp_msg_info.is_fw {
		pcp_msg_info.mapped_ip
	} else {
		let addr;
		let rt = pcp_msg_info.rt.as_ref().unwrap();
		let op = global_option.get().unwrap();
		// 处理外部IP地址
		if let Some(use_ext_ip) = &rt.use_ext_ip_addr {
			match use_ext_ip {
				IpAddr::V4(v4addr) => {
					addr = v4addr.to_ipv6_mapped();
				}
				IpAddr::V6(v6addr) => {
					addr = *v6addr;
				}
			}
		} else if cfg!(feature = "ipv6") && !ipv4 && op.ext_ifname != op.ext_ifname6 {
			if op.ext_ifname6.is_empty() {
				pcp_msg_info.result_code = PCP_ERR_NETWORK_FAILURE;
				return false;
			}
			if let Some(v6addr) = getifaddr_in6(&op.ext_ifname6, true) {
				addr = v6addr;
			} else {
				pcp_msg_info.result_code = PCP_ERR_NETWORK_FAILURE;
				return false;
			}
		} else {
			if op.ext_ifname.is_empty() {
				pcp_msg_info.result_code = PCP_ERR_NETWORK_FAILURE;
				return false;
			}
			if let Some(v6addr) = getifaddr_in6(&op.ext_ifname6, !ipv4) {
				addr = v6addr;
			} else {
				pcp_msg_info.result_code = PCP_ERR_NETWORK_FAILURE;
				return false;
			}
		}
		addr
	};

	// 检查外部IP是否为未指定地址
	if pcp_msg_info.ext_ip == Ipv6Addr::UNSPECIFIED
		|| (pcp_msg_info.ext_ip.is_ipv4_mapped() && pcp_msg_info.ext_ip.segments()[3] == 0)
	{
		// 使用实际的外部地址
		pcp_msg_info.ext_ip = external_addr;
		return true;
	}

	// 比较请求的外部IP和实际外部IP
	if pcp_msg_info.ext_ip != external_addr {
		error!("PCP: External IP in request didn't match interface IP");
		trace!("Interface IP {}", external_addr);
		trace!("IP in the PCP request {}", pcp_msg_info.ext_ip);

		if pcp_msg_info.pfailure_present != 0 {
			pcp_msg_info.result_code = PCP_ERR_CANNOT_PROVIDE_EXTERNAL;
			return false;
		} else {
			pcp_msg_info.ext_ip = external_addr;
		}
	}

	true
}

fn CreatePCPMap_NAT(pcp_msg_info: &mut pcp_info) -> i32 {
	let mut eport_first = 0u16;
	let mut any_eport_allowed = 0;
	let timestamp = upnp_time().as_secs() as u32 + pcp_msg_info.lifetime;

	if pcp_msg_info.ext_port == 0 {
		pcp_msg_info.ext_port = pcp_msg_info.int_port;
	}

	if pcp_msg_info.ext_port == 0 {
		return PCP_ERR_MALFORMED_REQUEST as i32;
	}
	let op = global_option.get().unwrap();
	let rt = pcp_msg_info.rt.as_mut().unwrap();
	loop {
		if eport_first == 0 {
			eport_first = pcp_msg_info.ext_port;
		} else if pcp_msg_info.ext_port == eport_first {
			if any_eport_allowed == 0 {
				return PCP_ERR_NOT_AUTHORIZED as i32;
			}
			return PCP_ERR_NO_RESOURCES as i32;
		}

		if pcp_msg_info.mapped_ip.is_ipv4_mapped()
			&& !check_upnp_rule_against_permissions(
				&op.upnpperms,
				pcp_msg_info.ext_port,
				pcp_msg_info.mapped_ip.to_ipv4().unwrap(),
				pcp_msg_info.int_port,
				pcp_msg_info.desc.as_deref().unwrap_or_default(),
			) {
			if pcp_msg_info.pfailure_present != 0 {
				return PCP_ERR_CANNOT_PROVIDE_EXTERNAL as i32;
			}
			pcp_msg_info.ext_port += 1;
			if pcp_msg_info.ext_port == 0 {
				pcp_msg_info.ext_port += 1;
			}
			continue;
		}

		any_eport_allowed = 1;

		#[cfg(feature = "portinuse")]
		{
			if rt.os.port_in_use(
				&rt.nat_impl,
				&op.ext_ifname,
				pcp_msg_info.ext_port,
				pcp_msg_info.protocol,
				&pcp_msg_info.mapped_ip.to_ipv4_mapped().unwrap(),
				pcp_msg_info.int_port,
			) > 0
			{
				info!(
					"port {} protocol {} already in use",
					pcp_msg_info.ext_port,
					proto_itoa(pcp_msg_info.protocol)
				);
				pcp_msg_info.ext_port += 1;
				if pcp_msg_info.ext_port == 0 {
					pcp_msg_info.ext_port += 1;
				}
				continue;
			}
		}

		if let Some(entry) = rt
			.nat_impl
			.get_redirect_rule(|x| x.eport == pcp_msg_info.ext_port && x.proto == pcp_msg_info.protocol)
		{
			if pcp_msg_info.mapped_ip.to_ipv4_mapped().unwrap() != entry.eaddr || pcp_msg_info.int_port != entry.eport {
				if pcp_msg_info.pfailure_present != 0 {
					return PCP_ERR_CANNOT_PROVIDE_EXTERNAL as i32;
				}
			} else {
				info!(
					"port {} {} already redirected to {}:{}, replacing",
					pcp_msg_info.ext_port, pcp_msg_info.protocol, entry.eaddr, entry.eport
				);
				if rt.nat_impl.delete_redirect(&op.ext_ifname, entry.index) == 0 {
					break;
				} else if pcp_msg_info.pfailure_present != 0 {
					return PCP_ERR_CANNOT_PROVIDE_EXTERNAL as i32;
				}
			}
			pcp_msg_info.ext_port += 1;
			if pcp_msg_info.ext_port == 0 {
				pcp_msg_info.ext_port += 1;
			}
		} else {
			break;
		}
	}

	// let rto = mem::replace(&mut pcp_msg_info.rt, None);
	// let rt = rto.unwrap();
	let rt = pcp_msg_info.rt.as_mut().unwrap();
	let entry = MapEntry {
		iaddr: pcp_msg_info.int_ip.to_ipv4().unwrap(),
		eport: pcp_msg_info.ext_port,
		iport: pcp_msg_info.int_port,
		proto: pcp_msg_info.protocol,
		desc: pcp_msg_info.desc.clone(),
		timestamp: timestamp as _,
		..Default::default()
	};
	let r = upnp_redirect_internal(op, rt, &entry);
	// pcp_msg_info.rt = Some(rt);

	if r < 0 {
		return PCP_ERR_NO_RESOURCES as i32;
	}
	PCP_SUCCESS as i32
}
fn CreatePCPMap_FW(pcp_msg_info: &mut pcp_info) -> i32 {
	let r: i32;

	let _rt = pcp_msg_info.rt.as_mut().unwrap();
	#[cfg(all(feature = "ipv6", feature = "pcp"))]
	match upnp_find_inboundpinhole(&mut _rt.nat_impl, |x| {
		x.iaddr == pcp_msg_info.int_ip && pcp_msg_info.int_port == x.iport && pcp_msg_info.protocol == x.proto
	}) {
		Some(entry) => {
			if entry.desc != pcp_msg_info.desc {
				// nonce不匹配
				error!(
					"Unauthorized to update pinhole : \"{}\" != \"{}\"",
					entry.desc.as_ref().map(|x| x.as_str()).unwrap_or_default(),
					pcp_msg_info.desc.as_deref().unwrap_or_default()
				);
				return PCP_ERR_NOT_AUTHORIZED as i32;
			}

			info!(
				"updating pinhole {} to {}:{} {}",
				entry.index,
				pcp_msg_info.mapped_ip,
				pcp_msg_info.int_port,
				proto_itoa(pcp_msg_info.protocol)
			);
			let index = entry.index;
			let _ = entry;
			r = upnp_update_inboundpinhole(&mut _rt.nat_impl, index as u16, pcp_msg_info.lifetime);
			(if r >= 0 { PCP_SUCCESS } else { PCP_ERR_NO_RESOURCES }) as _
		}
		None => {
			let mut uid: u16 = 0;
			let pinhole = PinholeEntry {
				iport: pcp_msg_info.int_port,
				proto: pcp_msg_info.protocol,
				iaddr: pcp_msg_info.mapped_ip,
				desc: pcp_msg_info.desc.clone(),
				timestamp: upnp_time().as_secs() + pcp_msg_info.lifetime as u64,
				..Default::default()
			};
			let op = global_option.get().unwrap();
			r = upnp_add_inboundpinhole(op, &mut _rt.nat_impl, &pinhole, &mut uid);

			if r < 0 {
				return 8; // PCP_ERR_NO_RESOURCES
			}

			pcp_msg_info.ext_port = pcp_msg_info.int_port;
			0 // PCP_SUCCESS
		}
	}
	#[cfg(not(all(feature = "ipv6", feature = "pcp")))]
	PCP_ERR_NO_RESOURCES
}
fn CreatePCPMap(pcp_msg_info: &mut pcp_info) {
	let r = if pcp_msg_info.is_fw {
		CreatePCPMap_FW(pcp_msg_info)
	} else {
		CreatePCPMap_NAT(pcp_msg_info)
	};

	pcp_msg_info.result_code = r as u8;

	log!(
		if r == 0 { 6 } else { 3 },
		"PCP MAP: {} mapping {} {}->{}:{} '{}'\0",
		if r == 0 { "added" } else { "failed to add" },
		proto_itoa(pcp_msg_info.protocol),
		pcp_msg_info.ext_port,
		pcp_msg_info.mapped_ip,
		pcp_msg_info.int_port,
		pcp_msg_info.desc.as_deref().unwrap_or_default()
	);
}

fn DeletePCPMap(pcp_msg_info: &mut pcp_info) {
	let iport: u16 = pcp_msg_info.int_port;
	let proto: u8 = pcp_msg_info.protocol;
	let mut r: i32 = -1;
	let mut eport2: u16 = 0;

	debug!(
		"is_fw={} addr={} iport={} proto={}",
		pcp_msg_info.is_fw, pcp_msg_info.mapped_ip, iport, proto,
	);
	let rt = pcp_msg_info.rt.as_mut().unwrap();
	if !pcp_msg_info.is_fw {
		// let mut index = 0;

		if let Some(entry) = rt.nat_impl.get_redirect_rule(|x| {
			x.iaddr == pcp_msg_info.int_ip.to_ipv4().unwrap()
				&& x.proto == pcp_msg_info.protocol
				&& (x.iport == iport || iport == 0)
		}) {
			eport2 = entry.eport;
			if entry.desc != pcp_msg_info.desc {
				pcp_msg_info.result_code = PCP_ERR_NOT_AUTHORIZED;
				error!(
					"Unauthorized to remove PCP mapping internal port {}, protocol {}",
					iport, pcp_msg_info.protocol
				);
				return;
			} else {
				r = _upnp_delete_redir(rt, entry.eport, pcp_msg_info.protocol);
			}
		}
	} else {
		let mut uid = -1;
		let mut old_entry = None;
		if let Some(pinholes) = rt.nat_impl.get_pinhole_iter() {
			for entry in pinholes {
				if proto == entry.proto && pcp_msg_info.mapped_ip == entry.iaddr && iport == entry.iport {
					uid = entry.index as i32;
					old_entry.replace(entry);
				}
			}
		}
		if uid < 0 {
			error!(
				"Failed to find mapping to {}:{}, protocol {}",
				pcp_msg_info.mapped_ip, iport, proto
			);
			return;
		}
		let old_entry = old_entry.unwrap();
		if old_entry.desc != pcp_msg_info.desc {
			pcp_msg_info.result_code = PCP_ERR_NOT_AUTHORIZED;
			error!(
				"Unauthorized to remove PCP mapping internal port {}, protocol {}",
				iport, pcp_msg_info.protocol
			);
			return;
		} else {
			r = upnp_delete_inboundpinhole(&mut rt.nat_impl, uid as u16);
		}
	}

	if r >= 0 {
		info!(
			"PCP: {} port {} mapping removed",
			proto_itoa(proto),
			if pcp_msg_info.is_fw { iport } else { eport2 },
		);
	} else {
		error!(
			"Failed to remove PCP mapping to {}:{} {}",
			pcp_msg_info.mapped_ip,
			iport,
			proto_itoa(proto),
		);
		pcp_msg_info.result_code = PCP_ERR_NO_RESOURCES;
	}
}
#[cfg(feature = "pcp")]
fn ValidatePCPMsg(pcp_msg_info: &mut pcp_info) -> i32 {
	if pcp_msg_info.result_code != 0 {
		return 0;
	}

	/* RFC 6887, section 8.2: MUST return address mismatch if NAT
	 * in middle. */
	if pcp_msg_info.int_ip != pcp_msg_info.sender_ip {
		pcp_msg_info.result_code = PCP_ERR_ADDRESS_MISMATCH;
		return 0;
	}

	if let Some(third_ip) = pcp_msg_info.thirdp_ip {
		let op = global_option.get().unwrap();

		if !GETFLAG!(op.runtime_flags, PCP_ALLOWTHIRDPARTYMASK) {
			pcp_msg_info.result_code = PCP_ERR_UNSUPP_OPTION;
			return 0;
		}
		if third_ip == pcp_msg_info.sender_ip {
			pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
			return 0;
		}
	}

	/* protocol zero means 'all protocols' : internal port MUST be zero */
	if pcp_msg_info.protocol == 0 && pcp_msg_info.int_port != 0 {
		error!(
			"PCP {}: Protocol was ZERO, but internal port has non-ZERO value.",
			getPCPOpCodeStr(pcp_msg_info.opcode)
		);
		pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
		return 0;
	}

	if pcp_msg_info.pfailure_present != 0
		&& (pcp_msg_info.ext_ip.is_unspecified()
			|| (pcp_msg_info.ext_ip.is_ipv4_mapped() && pcp_msg_info.ext_ip.segments()[3] == 0))
		&& pcp_msg_info.ext_port == 0
	{
		pcp_msg_info.result_code = PCP_ERR_MALFORMED_OPTION;
		return 0;
	}

	if !CheckExternalAddress(pcp_msg_info) {
		return 0;
	}

	if matches!(pcp_msg_info.opcode, PCP_OPCODE_MAP | PCP_OPCODE_PEER) {
		let desc = format!(
			"PCP {} {:08x}{:08x}{:08x}",
			getPCPOpCodeStr(pcp_msg_info.opcode),
			pcp_msg_info.nonce[0],
			pcp_msg_info.nonce[1],
			pcp_msg_info.nonce[2]
		);
		pcp_msg_info.desc = Some(desc.as_str().into());
	}

	1
}
#[cfg(feature = "pcp_peer")]
fn CreatePCPPeer_NAT(p: &mut pcp_info) -> i32 {
	let rt = p.rt.as_mut().unwrap();
	let proto = p.protocol;
	let mut eport = p.ext_port;

	let i_sockaddr = SocketAddr::new(p.mapped_ip.into(), p.int_port);
	let peer_sockaddr = SocketAddr::new(p.peer_ip.into(), p.peer_port);
	// let ext_sockaddr = SocketAddr::new(p.ext_ip.into(), eport);

	let conn = os::get_nat_ext_addr(Some(i_sockaddr), Some(peer_sockaddr), proto);

	let op = global_option.get().unwrap();
	let mut ext_if = &op.ext_ifname;
	#[cfg(feature = "ipv6")]
	if let Some(ext_addr) = conn {
		eport = ext_addr.port();
		if ext_addr.is_ipv6() {
			ext_if = &op.ext_ifname6;
		}
	}
	if eport == 0 {
		eport = p.int_port;
	}
	let mut entry = MapEntry {
		raddr: p.peer_ip.to_ipv4_mapped().unwrap(),
		rport: p.peer_port,
		eaddr: p.ext_ip.to_ipv4_mapped().unwrap(),
		eport,
		iaddr: p.int_ip.to_ipv4_mapped().unwrap(),
		iport: p.int_port,
		proto,
		desc: p.desc.clone(),
		..Default::default()
	};
	#[cfg(feature = "pcp_flowp")]
	if p.flowp_present != 0 && p.dscp_up != 0 {
		entry.dscp = p.dscp_up;
		if rt.nat_impl.add_peer_dscp_rule(ext_if, &entry) < 0 {
			error!(
				"PCP: failed to add flowp upstream mapping {}:{}->{}:{} '{}'",
				p.mapped_ip,
				p.int_port,
				p.peer_ip,
				p.peer_port,
				p.desc.as_deref().unwrap_or_default()
			);
			return PCP_ERR_NO_RESOURCES as _;
		}
	}
	#[cfg(feature = "pcp_flowp")]
	if p.flowp_present != 0 && p.dscp_down != 0 {
		entry.dscp = p.dscp_down;
		if rt.nat_impl.add_peer_dscp_rule(ext_if, &entry) < 0 {
			error!(
				"PCP: failed to add flowp downstream mapping {}:{}->{}:{} '{}'",
				p.mapped_ip,
				p.int_port,
				p.peer_ip,
				p.peer_port,
				p.desc.as_deref().unwrap_or_default()
			);
			p.result_code = PCP_ERR_NO_RESOURCES;
			return PCP_ERR_NO_RESOURCES as _;
		}
	}

	let r = rt.nat_impl.add_peer_redirect_rule(ext_if, &entry);
	if r < 0 {
		return PCP_ERR_NO_RESOURCES as _;
	}
	p.ext_port = eport;
	PCP_SUCCESS as _
}
#[cfg(feature = "pcp_peer")]
fn CreatePCPPeer(p: &mut pcp_info) {
	let r = if p.is_fw {
		PCP_ERR_UNSUPP_OPCODE
	} else {
		CreatePCPPeer_NAT(p) as u8
	};
	p.result_code = r;

	log!(
		if r == PCP_SUCCESS { log::LOG_INFO } else { log::LOG_ERR },
		"PCP PEER: {} peer mapping {} {}:{}({})->{}:{} '{}'",
		if r == PCP_SUCCESS { "added" } else { "failed to add" },
		proto_itoa(p.protocol),
		p.mapped_ip,
		p.int_port,
		p.ext_port,
		p.peer_ip,
		p.peer_port,
		p.desc.as_deref().unwrap_or_default()
	)
}
#[cfg(feature = "pcp_peer")]
fn DeletePCPPeer(p: &mut pcp_info) {
	if p.is_fw {
		p.result_code = PCP_ERR_UNSUPP_OPCODE;
		return;
	}

	let rhost = p.peer_ip.to_ipv4_mapped().unwrap();
	let iaddr = p.mapped_ip.to_ipv4_mapped().unwrap();

	let rt = p.rt.as_mut().unwrap();
	let op = global_option.get().unwrap();
	let mut eport = 0;
	if let Some(iter) = rt.nat_impl.get_iter(&op.ext_ifname, RuleTable::Peer) {
		for entry in iter {
			if entry.iaddr == iaddr
				&& entry.raddr == rhost
				&& entry.proto == p.protocol
				&& entry.desc == p.desc
				&& entry.iport == p.int_port
				&& entry.rport == p.peer_port
			{
				eport = entry.eport;
			}
		}
	}
	let r = if eport != 0 {
		let ret = _upnp_delete_redir(rt, eport, p.protocol);
		if ret < 0 {
			error!("PCP PEER: failed to remove peer mapping");
		} else {
			info!(
				"PCP PEER: {} port {} peer mapping removed",
				proto_itoa(p.protocol),
				eport
			);
		}
		ret
	} else {
		-1
	};
	if r == -1 {
		error!(
			"PCP PEER: Failed to find PCP mapping internal port {}, protocol {}",
			p.int_port,
			proto_itoa(p.protocol)
		);
	}
}

fn getPCPOpCodeStr(p0: u8) -> &'static str {
	match p0 {
		PCP_OPCODE_ANNOUNCE => "ANNOUNCE",
		PCP_OPCODE_MAP => "MAP",
		PCP_OPCODE_PEER => "PEER",
		#[cfg(feature = "pcp_sadscp")]
		PCP_OPCODE_SADSCP => "SADSCP",
		_ => "UNKNOWN",
	}
}
#[cfg(feature = "pcp_sadscp")]
fn get_dscp_value(pcp_info: &mut pcp_info) {
	let op = global_option.get().unwrap();
	for dscp in &op.dscp_value {
		if pcp_info.app_name.as_str() == dscp.app_name.as_str()
			&& pcp_info.delay_tolerance == dscp.delay
			&& pcp_info.loss_tolerance == dscp.loss
			&& pcp_info.jitter_tolerance == dscp.jitter
		{
			pcp_info.sadscp_dscp = dscp.value;
			pcp_info.matched_name = true;
			return;
		} else if dscp.app_name.is_empty()
			&& pcp_info.app_name.is_empty()
			&& pcp_info.delay_tolerance == dscp.delay
			&& pcp_info.loss_tolerance == dscp.loss
			&& pcp_info.jitter_tolerance == dscp.jitter
		{
			pcp_info.sadscp_dscp = dscp.value;
			pcp_info.matched_name = false;
			return;
		} else if dscp.app_name.is_empty()
			&& pcp_info.delay_tolerance == dscp.delay
			&& pcp_info.loss_tolerance == dscp.loss
			&& pcp_info.jitter_tolerance == dscp.jitter
		{
			pcp_info.sadscp_dscp = dscp.value;
			pcp_info.matched_name = false;
		}
	}

	pcp_info.sadscp_dscp = 0;
	pcp_info.matched_name = false;
}

#[cfg(feature = "pcp")]
fn processPCPRequest(req: &[u8], pcp_msg_info: &mut pcp_info) -> i32 {
	pcp_msg_info.result_code = 0;
	let req_size = req.len() as i32;

	if !req_size >= PCP_MIN_LEN as i32 && req_size <= PCP_MAX_LEN as i32 && req_size & 3 == 0 {
		pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
		return if req_size < 3 { 0 } else { 1 };
	}

	if parseCommonRequestHeader(req, pcp_msg_info) != 0 {
		return 1;
	}

	let mut remaining_size = req_size - PCP_COMMON_REQUEST_SIZE as i32;
	if remaining_size < 0 {
		pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
		return 1;
	}

	let mut req = &req[PCP_COMMON_REQUEST_SIZE as usize..];

	if pcp_msg_info.version == 1 {
		match pcp_msg_info.opcode {
			PCP_OPCODE_MAP => {
				remaining_size -= PCP_MAP_V1_SIZE as i32;
				if remaining_size < 0 {
					pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
					return pcp_msg_info.result_code as i32;
				}
				parsePCPMAP_version1(req, pcp_msg_info);
				req = &req[PCP_MAP_V1_SIZE as usize..];
				parsePCPOptions(req, remaining_size, pcp_msg_info);
				if ValidatePCPMsg(pcp_msg_info) != 0 {
					if pcp_msg_info.lifetime == 0 {
						DeletePCPMap(pcp_msg_info);
					} else {
						CreatePCPMap(pcp_msg_info);
					}
				} else {
					error!("PCP: Invalid PCP v1 MAP message.");
					return pcp_msg_info.result_code as i32;
				}
			}
			#[cfg(feature = "pcp_peer")]
			PCP_OPCODE_PEER => {
				remaining_size -= PCP_PEER_V1_SIZE as i32;
				if remaining_size < 0 {
					pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
					return pcp_msg_info.result_code as i32;
				}

				parsePCPPEER_version1(req, pcp_msg_info);

				req = &req[PCP_PEER_V1_SIZE as usize..];

				parsePCPOptions(req, remaining_size, pcp_msg_info);

				if (ValidatePCPMsg(pcp_msg_info)) != 0 {
					if pcp_msg_info.lifetime == 0 {
						DeletePCPPeer(pcp_msg_info);
					} else {
						CreatePCPPeer(pcp_msg_info);
					}
				} else {
					error!("PCP: Invalid PCP v1 PEER message.");
					return pcp_msg_info.result_code as i32;
				}
			}
			#[cfg(feature = "pcp_sadscp")]
			PCP_OPCODE_SADSCP => {
				remaining_size -= PCP_SADSCP_REQ_SIZE as i32;
				if remaining_size < 0 {
					pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
					return pcp_msg_info.result_code as i32;
				}
				remaining_size -= req[13] as i32;
				if remaining_size < 0 {
					pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
					return pcp_msg_info.result_code as i32;
				}
				parseSADSCP(req, pcp_msg_info);

				if pcp_msg_info.result_code != 0 {
					return pcp_msg_info.result_code as i32;
				}
				// req = &req[PCP_SADSCP_REQ_SIZE as usize + pcp_msg_info.app_name.len()..];

				get_dscp_value(pcp_msg_info);
			}
			_ => {
				pcp_msg_info.result_code = PCP_ERR_UNSUPP_OPCODE;
			}
		}
	} else if pcp_msg_info.version == 2 {
		match pcp_msg_info.opcode {
			PCP_OPCODE_ANNOUNCE => {}
			PCP_OPCODE_MAP => {
				remaining_size -= PCP_MAP_V2_SIZE as i32;
				if remaining_size < 0 {
					pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
					return pcp_msg_info.result_code as i32;
				}
				parsePCPMAP_version2(req, pcp_msg_info);
				req = &req[PCP_MAP_V2_SIZE as usize..];
				parsePCPOptions(req, remaining_size, pcp_msg_info);
				if ValidatePCPMsg(pcp_msg_info) != 0 {
					if pcp_msg_info.lifetime == 0 {
						DeletePCPMap(pcp_msg_info);
					} else {
						CreatePCPMap(pcp_msg_info);
					}
				} else {
					error!("PCP: Invalid PCP v2 MAP message.");
					return pcp_msg_info.result_code as i32;
				}
			}
			#[cfg(feature = "pcp_peer")]
			PCP_OPCODE_PEER => {
				remaining_size -= PCP_PEER_V2_SIZE as i32;
				if remaining_size < 0 {
					pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
					return pcp_msg_info.result_code as i32;
				}

				parsePCPPEER_version2(req, pcp_msg_info);

				req = &req[PCP_PEER_V2_SIZE as usize..];

				parsePCPOptions(req, remaining_size, pcp_msg_info);

				if (ValidatePCPMsg(pcp_msg_info)) != 0 {
					if pcp_msg_info.lifetime == 0 {
						DeletePCPPeer(pcp_msg_info);
					} else {
						CreatePCPPeer(pcp_msg_info);
					}
				} else {
					error!("PCP: Invalid PCP v1 PEER message.");
					return pcp_msg_info.result_code as i32;
				}
			}
			#[cfg(feature = "pcp_sadscp")]
			PCP_OPCODE_SADSCP => {
				remaining_size -= PCP_SADSCP_REQ_SIZE as i32;
				if remaining_size < 0 {
					pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
					return pcp_msg_info.result_code as i32;
				}
				remaining_size -= req[13] as i32;
				if remaining_size < 0 {
					pcp_msg_info.result_code = PCP_ERR_MALFORMED_REQUEST;
					return pcp_msg_info.result_code as i32;
				}
				parseSADSCP(req, pcp_msg_info);

				if pcp_msg_info.result_code != 0 {
					return pcp_msg_info.result_code as i32;
				}
				// req = &req[PCP_SADSCP_REQ_SIZE as usize + pcp_msg_info.app_name.len()..];

				get_dscp_value(pcp_msg_info);
			}
			_ => {
				pcp_msg_info.result_code = PCP_ERR_UNSUPP_OPCODE;
			}
		}
	} else {
		pcp_msg_info.result_code = PCP_ERR_UNSUPP_VERSION;
		return pcp_msg_info.result_code as i32;
	}
	1
}

fn createPCPResponse(response: &mut [u8], pcp_msg_info: &mut pcp_info) {
	macro_rules! copy_to_response {
		($response:expr, $base:expr, $offset:expr, $value:expr) => {
			let start: usize = $base as usize + $offset as usize;
			let end: usize = start + $value.len();
			$response[start..end].copy_from_slice($value);
		};
	}
	response[2] = 0;
	response[12..24].copy_from_slice(&[0u8; 12]);
	if pcp_msg_info.result_code == PCP_ERR_UNSUPP_VERSION {
		response[0] = this_server_info.server_version;
	} else {
		response[0] = pcp_msg_info.version;
	}
	response[1] = pcp_msg_info.opcode | 0x80;
	response[3] = pcp_msg_info.result_code;
	let rt = pcp_msg_info.rt.as_mut().unwrap();

	if rt.epoch_origin.is_zero() {
		rt.epoch_origin = *(startup_time.get().unwrap());
	}
	response[8..12].copy_from_slice(((upnp_time() - rt.epoch_origin).as_secs() as u32).to_be_bytes().as_ref());
	match pcp_msg_info.result_code {
		PCP_ERR_UNSUPP_VERSION
		| PCP_ERR_NOT_AUTHORIZED
		| PCP_ERR_MALFORMED_REQUEST
		| PCP_ERR_UNSUPP_OPCODE
		| PCP_ERR_UNSUPP_OPTION
		| PCP_ERR_MALFORMED_OPTION
		| PCP_ERR_UNSUPP_PROTOCOL
		| PCP_ERR_ADDRESS_MISMATCH
		| PCP_ERR_CANNOT_PROVIDE_EXTERNAL
		| PCP_ERR_EXCESSIVE_REMOTE_PEERS => {
			response[4] = 0;
			response[5] = 0;
			response[6] = 0;
			response[7] = 0;
		}
		PCP_ERR_NETWORK_FAILURE | PCP_ERR_NO_RESOURCES | PCP_ERR_USER_EX_QUOTA => {
			response[4] = 0;
			response[5] = 0;
			response[6] = 0;
			response[7] = 30;
		}
		_ => {
			copy_to_response!(response, 0, 4, &pcp_msg_info.lifetime.to_be_bytes());
		}
	}
	if response[1] == 0x81 {
		if response[0] == 1 {
			copy_to_response!(
				response,
				PCP_COMMON_RESPONSE_SIZE,
				4,
				&pcp_msg_info.int_port.to_be_bytes()
			);
			copy_to_response!(
				response,
				PCP_COMMON_RESPONSE_SIZE,
				6,
				&pcp_msg_info.ext_port.to_be_bytes()
			);
			copy_to_response!(response, PCP_COMMON_RESPONSE_SIZE, 8, pcp_msg_info.ext_ip.as_octets());
		} else if response[1] == 2 {
			copy_to_response!(
				response,
				PCP_COMMON_RESPONSE_SIZE,
				16,
				&pcp_msg_info.int_port.to_be_bytes()
			);
			copy_to_response!(
				response,
				PCP_COMMON_RESPONSE_SIZE,
				18,
				&pcp_msg_info.ext_port.to_be_bytes()
			);
			copy_to_response!(response, PCP_COMMON_RESPONSE_SIZE, 20, pcp_msg_info.ext_ip.as_octets());
		}
	}
	#[cfg(feature = "pcp_peer")]
	if response[1] == 0x82 {
		if response[0] == 1 {
			copy_to_response!(
				response,
				PCP_COMMON_RESPONSE_SIZE,
				4,
				&pcp_msg_info.int_port.to_be_bytes()
			);
			copy_to_response!(
				response,
				PCP_COMMON_RESPONSE_SIZE,
				6,
				&pcp_msg_info.ext_port.to_be_bytes()
			);
			copy_to_response!(response, PCP_COMMON_RESPONSE_SIZE, 8, pcp_msg_info.ext_ip.as_octets());
			copy_to_response!(
				response,
				PCP_COMMON_RESPONSE_SIZE,
				24,
				&pcp_msg_info.peer_port.to_be_bytes()
			);
		} else if response[0] == 2 {
			copy_to_response!(
				response,
				PCP_COMMON_RESPONSE_SIZE,
				16,
				&pcp_msg_info.int_port.to_be_bytes()
			);
			copy_to_response!(
				response,
				PCP_COMMON_RESPONSE_SIZE,
				18,
				&pcp_msg_info.ext_port.to_be_bytes()
			);
			copy_to_response!(response, PCP_COMMON_RESPONSE_SIZE, 20, pcp_msg_info.ext_ip.as_octets());
			copy_to_response!(
				response,
				PCP_COMMON_RESPONSE_SIZE,
				36,
				&pcp_msg_info.peer_port.to_be_bytes()
			);
		}
	}
	#[cfg(feature = "pcp_sadscp")]
	if response[1] == 0x83 {
		response[PCP_COMMON_RESPONSE_SIZE as usize + 12] =
			((pcp_msg_info.matched_name as u8) << 7) | pcp_msg_info.sadscp_dscp & PCP_SADSCP_MASK;
		copy_to_response!(response, PCP_COMMON_RESPONSE_SIZE, 13, &[0u8, 3]);
	}
}
#[cfg(feature = "pcp")]
pub fn ProcessIncomingPCPPacket(
	rt: &mut RtOptions,
	s: &Socket,
	buff: &mut [u8],
	senderaddr: &SocketAddr,
	receiveraddr: Option<&SocketAddrV6>,
) -> i32 {
	let mut pcp_msg_info: pcp_info = pcp_info { rt: Some(rt), ..Default::default() };

	pcp_msg_info.sender_ip = match senderaddr {
		SocketAddr::V4(addr4) => {
			let mut ip6 = [0u8; 16];
			ip6[10] = 0xff;
			ip6[11] = 0xff;
			ip6[12..16].copy_from_slice(addr4.ip().as_octets());
			Ipv6Addr::from(ip6)
		}
		SocketAddr::V6(addr6) => *addr6.ip(),
	};

	debug!("PCP request received from {} {} bytes", senderaddr, buff.len());

	if buff[1] & 0x80 != 0 {
		return 0;
	}
	let op = global_option.get().unwrap();
	if !GETFLAG!(op.runtime_flags, PCP_ALLOWTHIRDPARTYMASK) {
		let lan_addr = get_lan_for_peer(op, senderaddr);
		if lan_addr.is_none() {
			warn!("PCP packet sender {} not from a LAN, ignoring", senderaddr);
			return 0;
		}
	}

	if processPCPRequest(buff, &mut pcp_msg_info) != 0 {
		createPCPResponse(buff, &mut pcp_msg_info);

		let len = if buff.len() < 24 { 24 } else { (buff.len() + 3) & !3 };

		match send_from_to(s, &buff[..len], 0, receiveraddr, senderaddr) {
			Ok(_) => (),
			Err(e) => error!("sendto(pcpserver): {}", e),
		}
	}

	0
}

#[cfg(feature = "ipv6")]
pub fn OpenAndConfPCPv6Socket(v: &Options) -> io::Result<Socket> {
	// Create a new IPv6 UDP socket
	let socket = Socket::new(
		socket2::Domain::IPV6,
		socket2::Type::DGRAM,
		Some(socket2::Protocol::UDP),
	)?;

	if let Err(e) = socket.set_reuse_address(true) {
		warn!("OpenAndConfPCPv6Socket: setsockopt(SO_REUSEADDR): {}", e);
	}
	if let Err(e) = socket.set_only_v6(true) {
		warn!("OpenAndConfPCPv6Socket: set_only_v6(true): {}", e);
	}
	if v.listening_ip.len() == 1 {
		let ifname = v.listening_ip[0].ifname;
		if let Err(e) = socket.bind_device(Some(ifname.as_bytes())) {
			warn!(
				"OpenAndConfPCPv6Socket: udp6 bindtodevice {}: {}",
				v.listening_ip[0].ifname.as_str(),
				e
			);
		}
	}

	// Set IPV6_RECVPKTINFO option
	let recv_pktinfo: libc::c_int = 1;
	unsafe {
		if libc::setsockopt(
			socket.as_raw_fd(),
			libc::IPPROTO_IPV6,
			libc::IPV6_RECVPKTINFO,
			&recv_pktinfo as *const _ as *const libc::c_void,
			size_of_val(&recv_pktinfo) as libc::socklen_t,
		) < 0
		{
			warn!("OpenAndConfPCPv6Socket: setsockopt(IPV6_RECVPKTINFO): %m");
		}
	}

	if let Err(e) = socket.set_nonblocking(true) {
		warn!("OpenAndConfPCPv6Socket: set_nonblocking(true): {}", e);
	}

	// Bind the socket to the specified address and port
	let addr = SocketAddrV6::new(ipv6_bind_addr, NATPMP_PORT, 0, 0);
	socket.bind(&socket2::SockAddr::from(addr))?;

	Ok(socket)
}

pub fn PCPSendUnsolicitedAnnounce(
	rt: &mut RtOptions,
	send_list: &mut Vec<scheduled_send>,
	sockets: &[Rc<Socket>],
	socket6: Option<&Rc<Socket>>,
) {
	let mut info = pcp_info {
		version: this_server_info.server_version,
		opcode: PCP_OPCODE_ANNOUNCE,
		result_code: PCP_SUCCESS,
		lifetime: 0,
		rt: Some(rt),
		..Default::default()
	};
	let mut buff = [0u8; PCP_MIN_LEN as usize];

	createPCPResponse(&mut buff, &mut info);
	let sendaddr = SocketAddrV4::new(NATPMP_NOTIF_ADDR, NATPMP_NOTIF_PORT);

	for sock in sockets {
		if let Err(e) = sendto_or_schedule(send_list, sock, &buff, 0, sendaddr.into()) {
			error!(
				"PCPSendUnsolicitedAnnounce(sockets[{}]) sendto(): {}",
				sock.as_raw_fd(),
				e
			);
		}
	}
	if let Some(socket6) = socket6 {
		let sendaddr = SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0), NATPMP_NOTIF_PORT, 0, 0);
		if let Err(e) = sendto_or_schedule(send_list, socket6, &buff, 0, sendaddr.into()) {
			error!(
				"PCPSendUnsolicitedAnnounce(sockets[{}]) Ipv6 sendto(): {}",
				socket6.as_raw_fd(),
				e
			);
		}
	}
}

pub fn PCPPublicAddressChanged(
	rt: &mut RtOptions,
	send_list: &mut Vec<scheduled_send>,
	sockets: &[Rc<Socket>],
	socket6: Option<&Rc<Socket>>,
) {
	rt.epoch_origin = upnp_time();
	PCPSendUnsolicitedAnnounce(rt, send_list, sockets, socket6);
}
