use crate::getifstats::ifdata;
use crate::warp::IfName;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::path::Path;

const BAUDRATE_DEFAULT: u64 = 4_200_000;

mod if_addr {
	#![allow(
		dead_code,
		mutable_transmutes,
		non_camel_case_types,
		non_snake_case,
		non_upper_case_globals,
		unused_assignments,
		unused_mut
	)]
	include!(concat!(env!("OUT_DIR"), "/if_addr.rs"));
}
pub(super) use if_addr::*;
// #[inline]
// fn RTA_OK(rta: &rtattr, len: u16) -> bool {
// 	len >= size_of::<rtattr>() as u16 && rta.rta_len >= size_of::<rtattr>() as u16 && rta.rta_len <= len
// }

pub(super) fn getifstats(ifname: &IfName, data: &mut ifdata) -> i32 {
	data.ibytes = 0;
	data.obytes = 0;
	data.ipackets = 0;
	data.opackets = 0;
	data.baudrate = BAUDRATE_DEFAULT;

	let path = Path::new("/proc/net/dev");
	let file = match File::open(&path) {
		Ok(f) => f,
		Err(_) => return -1,
	};
	let reader = io::BufReader::new(file);

	for line in reader.lines().skip(2) {
		let line = match line {
			Ok(l) => l,
			Err(_) => return -1,
		};
		let mut parts = line.split_whitespace();

		if let Some(iface) = parts.next() {
			if iface.trim_end_matches(':') == ifname.as_str() {
				data.ibytes = parts.next().and_then(|s| u64::from_str_radix(s, 10).ok()).unwrap_or(0);
				data.ipackets = parts.next().and_then(|s| u64::from_str_radix(s, 10).ok()).unwrap_or(0);
				for _ in 0..6 {
					parts.next();
				}
				data.obytes = parts.next().and_then(|s| u64::from_str_radix(s, 10).ok()).unwrap_or(0);
				data.opackets = parts.next().and_then(|s| u64::from_str_radix(s, 10).ok()).unwrap_or(0);
				break;
			}
		}
	}

	let speed_path = format!("/sys/class/net/{}/speed", ifname);
	if let Ok(file) = File::open(&speed_path) {
		let mut reader = io::BufReader::new(file);
		let mut line = String::new();
		if reader.read_line(&mut line).is_ok() {
			if let Ok(speed) = line.trim().parse::<u64>() {
				if speed > 0 && speed < 65535 {
					data.baudrate = speed * 1_000_000;
				}
			}
		}
	}

	0
}

#[cfg(test)]
mod test {}
