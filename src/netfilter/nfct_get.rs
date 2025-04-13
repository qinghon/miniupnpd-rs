#![allow(
	dead_code,
	mutable_transmutes,
	non_camel_case_types,
	non_snake_case,
	non_upper_case_globals,
	unused_assignments,
	unused_mut
)]

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const DST: &str = "dst=";
const DST_PORT: &str = "dport=";
const SRC: &str = "src=";
const SRC_PORT: &str = "sport=";
const IP_CONNTRACK_LOCATION: &str = "/proc/net/ip_conntrack";
const NF_CONNTRACK_LOCATION: &str = "/proc/net/nf_conntrack";

pub(super) fn get_nat_ext_addr(src: Option<SocketAddr>, dst: Option<SocketAddr>, proto: u8) -> Option<SocketAddr> {
	let src = src?;
	let af = match src.ip() {
		IpAddr::V4(_) => 4,
		IpAddr::V6(_) => 6,
	};

	let file = File::open(NF_CONNTRACK_LOCATION).or_else(|_| File::open(IP_CONNTRACK_LOCATION)).ok()?;
	let reader = BufReader::new(file);

	for line in reader.lines().flatten() {
		let mut tokens = line.split_whitespace();
		if tokens.nth(1).and_then(|t| t.parse::<i32>().ok()) != Some(af) {
			continue;
		}
		if tokens.nth(1).and_then(|t| t.parse::<u8>().ok()) != Some(proto) {
			continue;
		}

		let mut src_f = false;
		let mut src_port_f = false;
		let mut dst_f = false;
		let mut dst_port_f = false;
		let mut ret_ext: Option<SocketAddr> = None;

		for token in tokens {
			if let Some(src_ip) = token.strip_prefix(SRC) {
				if src.ip().to_string() == src_ip {
					src_f = true;
				}
			} else if let Some(src_port) = token.strip_prefix(SRC_PORT) {
				if src.port().to_string() == src_port {
					src_port_f = true;
				}
			} else if let Some(dst_ip) = token.strip_prefix(DST) {
				if let Ok(ip) = dst_ip.parse::<Ipv4Addr>() {
					if let Some(dst) = dst {
						if dst.ip() == IpAddr::V4(ip) {
							dst_f = true;
						} else {
							ret_ext = Some(SocketAddr::new(IpAddr::V4(ip), 0));
						}
					}
				}
			} else if let Some(dst_port) = token.strip_prefix(DST_PORT) {
				if let Ok(port) = dst_port.parse::<u16>() {
					if let Some(dst) = dst {
						if dst.port() == port {
							dst_port_f = true;
						} else if let Some(ref mut ret_ext) = ret_ext {
							*ret_ext = SocketAddr::new(ret_ext.ip(), port);
						}
					}
				}
			}
		}

		if src_f && src_port_f && dst_f && dst_port_f {
			return ret_ext;
		}
	}

	None
}
