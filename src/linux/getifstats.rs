use crate::getifstats::ifdata;
use crate::warp::{IfName, StackBufferReader};
use std::fs::File;

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

	let mut file = match File::open("/proc/net/dev") {
		Ok(f) => f,
		Err(_) => return -1,
	};
	let mut buf = [0u8; 512];

	let mut reader = StackBufferReader::new(&mut buf);
	let mut count = 0;
	while let Some(Ok(line_buf)) = reader.read_line(&mut file) {
		// let line = match line {
		// 	Ok(l) => l,
		// 	Err(_) => return -1,
		// };
		count += 1;
		if count < 2 {
			continue;
		}
		let line = unsafe { str::from_utf8_unchecked(line_buf) };

		let mut parts = line.split_whitespace();

		if let Some(iface) = parts.next()
			&& iface.trim_end_matches(':') == ifname.as_str() {
				data.ibytes = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
				data.ipackets = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
				for _ in 0..6 {
					parts.next();
				}
				data.obytes = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
				data.opackets = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
				break;
			}
	}

	let speed_path = format!("/sys/class/net/{ifname}/speed");
	if let Ok(mut file) = File::open(&speed_path)
		&& let Some(Ok(line)) = reader.read_line(&mut file) {
			let line = unsafe { str::from_utf8_unchecked(line) };
			if let Ok(speed) = line.trim().parse::<u64>()
				&& speed > 0 && speed < 65535 {
					data.baudrate = speed * 1_000_000;
				}
		}

	0
}

#[cfg(test)]
mod test {}
