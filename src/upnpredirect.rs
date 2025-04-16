use crate::options::RtOptions;
use crate::upnpevents::subscriber_service_enum::EWanIPC;
use crate::upnpevents::upnp_event_var_change_notify;
use crate::upnpglobalvars::global_option;
use crate::upnppermissions::check_upnp_rule_against_permissions;
use crate::upnputils::{proto_atoi, proto_itoa, upnp_time};
use crate::RuleTable::Redirect;
use crate::{nat_impl, Backend, FilterEntry};
use std::fs;
use std::fs::{remove_file, File};
use std::io::{self, BufRead, Write};
use std::net::Ipv4Addr;
use std::ops::Add;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Copy, Clone)]
#[repr(C)]
pub struct rule_state {
	pub packets: u64,
	pub bytes: u64,
	pub eport: u16,
	pub proto: u8,
	pub to_remove: u8,
}

fn lease_file_add(iaddr: Ipv4Addr, eport: u16, iport: u16, proto: u8, desc: Option<&str>, timestamp: u32) -> i32 {
	let lease_file = &global_option.get().unwrap().lease_file;
	if lease_file.is_empty() {
		return 0;
	}
	let mut fd = match fs::OpenOptions::new().read(true).write(true).append(true).open(lease_file) {
		Ok(fd) => fd,
		Err(_) => {
			error!("could to open lease file {}", lease_file);
			return -1;
		}
	};
	let timestamp = timestamp;
	if timestamp != 0 {
		// timestamp -= upnp_time().as_secs() as u32;
	};

	let _ = writeln!(
		fd,
		"{}:{eport}:{iaddr}:{iport}:{timestamp}:{}",
		proto_itoa(proto),
		desc.unwrap_or("")
	);

	0
}
fn lease_file_remove(eport: u16, proto: u8) -> i32 {
	let lease_file = &global_option.get().unwrap().lease_file;
	if lease_file.is_empty() {
		return 0;
	}
	let fd = match fs::File::open(lease_file) {
		Ok(fd) => fd,
		Err(_) => return -1,
	};
	let tmpfilename = format!("{}XXXXXX", lease_file);

	let mut tmp = match fs::File::create(tmpfilename.as_str()) {
		Ok(f) => f,
		Err(_) => {
			error!("could not open temporary lease file");
			return -1;
		}
	};
	let _ = tmp.set_permissions(fs::Permissions::from_mode(0o644));
	let mut fdr = io::BufReader::new(fd);
	let mut buf = String::with_capacity(512);
	let str = format!("{}:{}", proto_itoa(proto), eport);
	while let Ok(l) = fdr.read_line(&mut buf) {
		if l == 0 {
			break;
		}
		if !buf.starts_with(str.as_str()) {
			let _ = tmp.write(buf.as_bytes());
		}
	}

	if let Err(_) = fs::rename(&tmpfilename, lease_file) {
		error!("could not rename temporary lease file to {}", lease_file);
		let _ = fs::remove_file(tmpfilename.as_str());
	}
	0
}
pub fn reload_from_lease_file(rt: &mut RtOptions, lease_file: &str) -> io::Result<()> {
	if !Path::new(lease_file).exists() {
		return Err(io::ErrorKind::NotFound.into());
	}

	let file = File::open(lease_file)?;

	if remove_file(lease_file).is_err() {
		eprintln!("Warning: Could not unlink file {}", lease_file);
	}

	let current_time = upnp_time().as_secs();

	for line in io::BufReader::new(file).lines() {
		let line = line?;
		println!("Parsing lease file line '{}'", line);

		let mut parts = line.split(':');
		let proto = match parts.next().and_then(|s| Some(proto_atoi(s))) {
			Some(proto) => proto,
			None => continue,
		};
		let eport = match parts.next().and_then(|s| s.parse::<u16>().ok()) {
			Some(p) => p,
			None => continue,
		};
		let iaddr = match parts.next().and_then(|s| s.parse::<Ipv4Addr>().ok()) {
			Some(int) => int,
			None => continue,
		};
		let iport = match parts.next().and_then(|s| s.parse::<u16>().ok()) {
			Some(s) => s,
			None => continue,
		};

		let timestamp = match parts.next().and_then(|s| s.parse::<u32>().ok()) {
			Some(v) => v,
			None => continue,
		};
		let desc = parts.next();

		let leaseduration = if timestamp > 0 {
			if timestamp as u64 <= current_time {
				println!("Notice: Already expired lease in lease file");
				continue;
			} else {
				timestamp as u64 - current_time
			}
		} else {
			0
		};

		match upnp_redirect(rt, None, iaddr, eport, iport, proto, desc, leaseduration as u32) {
			-1 => eprintln!(
				"Error: Failed to redirect {} -> {}:{} protocol {}",
				eport, iaddr, iport, proto
			),
			-2 => {
				lease_file_add(iaddr, eport, iport, proto, desc, timestamp);
			}
			_ => {}
		}
	}

	Ok(())
}

pub fn upnp_redirect(
	rt: &mut RtOptions,
	rhost: Option<Ipv4Addr>,
	iaddr: Ipv4Addr,
	eport: u16,
	iport: u16,
	proto: u8,
	desc: Option<&str>,
	leaseduration: u32,
) -> i32 {
	let v = global_option.get().unwrap();

	if !check_upnp_rule_against_permissions(&v.upnpperms, eport, iaddr, iport, desc.unwrap_or("")) {
		info!(
			"redirection permission check failed for {}->{}:{} {} {}",
			eport,
			iaddr,
			iport,
			proto,
			desc.unwrap_or_default(),
		);
		return -3;
	}

	if let Some(entry) = rt
		.nat_impl
		.get_redirect_rule(|x| x.dport == eport && x.proto == proto && x.daddr == iaddr && x.sport == iport)
	{
		if entry.daddr == iaddr && rhost.is_none() && entry.saddr.is_unspecified() {
			info!(
				"updating existing port mapping {} {} (rhost '{}') => {}:{}",
				eport,
				proto,
				rhost.unwrap_or(Ipv4Addr::UNSPECIFIED),
				iaddr,
				iport
			);

			let timestamp = if leaseduration > 0 {
				upnp_time().as_secs() + leaseduration as u64
			} else {
				0
			} as u32;
			let op = global_option.get().unwrap();
			let ret = if iport != entry.sport {
				rt.nat_impl.update_portmapping(&op.ext_ifname, eport, proto, iport, desc.unwrap(), timestamp)
			} else {
				rt.nat_impl
					.update_portmapping_desc_timestamp(&op.ext_ifname, eport, proto, desc.unwrap(), timestamp)
			};

			if ret == 0 {
				lease_file_remove(eport, proto);
				lease_file_add(iaddr, eport, iport, proto, desc, timestamp);
			}
			return ret;
		} else {
			info!(
				"port {} {} (rhost '{}') already redirected to {}:{}",
				eport,
				proto,
				rhost.unwrap_or(Ipv4Addr::UNSPECIFIED),
				iaddr,
				iport
			);
			return -2;
		}
	} else {
		let timestamp = if leaseduration > 0 {
			upnp_time().as_secs() + leaseduration as u64
		} else {
			0
		} as u32;
		info!(
			"redirecting port {} to {}:{} protocol {} for: {}",
			eport,
			proto,
			iaddr,
			iport,
			desc.unwrap_or_default()
		);
		return upnp_redirect_internal(rt, rhost, iaddr, eport, iport, proto, desc, timestamp);
	}
}

pub fn upnp_redirect_internal(
	rt: &mut RtOptions,
	rhost: Option<Ipv4Addr>,
	iaddr: Ipv4Addr,
	eport: u16,
	iport: u16,
	proto: u8,
	desc: Option<&str>,
	timestamp: u32,
) -> i32 {
	let v = global_option.get().unwrap();

	if rt.disable_port_forwarding {
		return -1;
	}
	if rt.nat_impl.add_redirect_rule2(&v.ext_ifname, rhost, iaddr, eport, iport, proto, desc, timestamp) < 0 {
		return -1;
	}
	lease_file_add(iaddr.into(), eport, iport, proto, desc, timestamp);
	if rt.nat_impl.add_filter_rule2(&v.ext_ifname, rhost, iaddr, eport, iport, proto, desc) < 0 {
		return -(1);
	}
	if timestamp > 0 {
		let add = Duration::from_secs(timestamp as u64) - upnp_time();
		let xx = Instant::now() + add;
		if xx < rt.nextruletoclean_timestamp {
			rt.nextruletoclean_timestamp = xx;
		}
	}
	upnp_event_var_change_notify(&mut rt.subscriber_list, EWanIPC);
	return 0;
}
pub fn upnp_get_redirection_infos(nat: &nat_impl, eport: u16, protocol: u8) -> Option<FilterEntry> {
	nat.get_redirect_rule(|x| x.dport == eport && x.proto == protocol)
}
pub fn upnp_get_redirection_infos_by_index(nat: &nat_impl, index: usize) -> Option<FilterEntry> {
	let op = global_option.get().unwrap();
	let iter = nat.get_iter(&op.ext_ifname, Redirect)?;
	let mut cur_idx = 0;
	for entry in iter {
		if cur_idx == index {
			return Some(entry.clone());
		}
		cur_idx += 1;
	}
	None
}

pub fn _upnp_delete_redir(
	rt: &mut RtOptions,
	// nat: &mut impl Backend,
	eport: u16,
	proto: u8,
) -> i32 {
	let op = global_option.get().unwrap();
	let r = rt.nat_impl.delete_redirect_and_filter_rules(&op.ext_ifname, eport, proto);
	lease_file_remove(eport, proto);
	#[cfg(feature = "events")]
	upnp_event_var_change_notify(&mut rt.subscriber_list, EWanIPC);
	r
}

pub fn upnp_delete_redirection(rt: &mut RtOptions, eport: u16, protocol: u8) -> i32 {
	info!("removing redirect rule port {} {}", eport, protocol);
	_upnp_delete_redir(rt, eport, protocol)
}
pub fn upnp_get_portmapping_number_of_entries(nat: &nat_impl) -> i32 {
	nat.get_redirect_rule_count(&global_option.get().unwrap().ext_ifname)
}

pub fn get_upnp_rules_state_list(rt: &mut RtOptions, max_rules_number_target: i32) -> Option<Vec<rule_state>> {
	let mut list = vec![];
	let cur_time = upnp_time().as_secs();
	let cur_ins = Instant::now();
	// like set to zero, instant cannot set to zero
	rt.nextruletoclean_timestamp = cur_ins + Duration::from_secs(86400);
	let op = global_option.get().unwrap();
	if let Some(iter) = rt.nat_impl.get_iter(&op.ext_ifname, Redirect) {
		for entry in iter {
			let mut remove = 0;
			if entry.timestamp > 0 {
				if entry.timestamp <= cur_time {
					remove = 1;
				} else {
					let entry_ins = Instant::now().add(Duration::from_secs(entry.timestamp - cur_time));
					if rt.nextruletoclean_timestamp < cur_ins || entry_ins < rt.nextruletoclean_timestamp {
						rt.nextruletoclean_timestamp = cur_ins;
					}
				}
			}
			list.push(rule_state {
				packets: entry.packets,
				bytes: entry.bytes,
				eport: entry.dport,
				proto: entry.proto,
				to_remove: remove,
			});
		}
	}
	let mut idx = 0;
	while idx < list.len() {
		if list[idx].to_remove != 0 {
			_upnp_delete_redir(rt, list[idx].eport, list[idx].proto);
			list.swap_remove(idx);
			continue;
		}
		idx += 1;
	}
	if list.len() < max_rules_number_target as usize {
		return None;
	}
	Some(list)
}

pub fn remove_unused_rules(rt: &mut RtOptions, list: &mut Vec<rule_state>) {
	let n: i32 = 0;
	let mut idx = 0;
	while idx < list.len() {
		let rule = &list[idx];
		if let Some(entry) = rt.nat_impl.get_redirect_rule(|x| x.dport == rule.eport && rule.proto == x.proto) {
			debug!(
				"removing unused mapping {} {}: still {} packets {} packets",
				rule.eport, rule.proto, entry.packets, entry.bytes
			);
			_upnp_delete_redir(rt, rule.eport, rule.proto);
			let _ = rule;
			list.swap_remove(idx);
			continue;
		}
		idx += 1;
	}

	if n > 0 {
		notice!("removed {} unused rules", n);
	}
}

pub fn upnp_get_portmappings_in_range(
	nat_impl: &nat_impl,
	startport: u16,
	endport: u16,
	proto: u8,
) -> Option<Vec<u16>> {
	let x = nat_impl.get_portmappings_in_range(startport, endport, proto);
	if x.is_empty() { None } else { Some(x) }
}
