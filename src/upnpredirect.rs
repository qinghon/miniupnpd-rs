use crate::RuleTable::Redirect;
use crate::options::{Options, RtOptions};
use crate::upnpevents::subscriber_service_enum::EWanIPC;
use crate::upnpevents::upnp_event_var_change_notify;
use crate::upnpglobalvars::{ALLOWPRIVATEIPV4MASK, global_option};
use crate::upnppermissions::check_upnp_rule_against_permissions;
use crate::upnputils::{proto_atoi, proto_itoa, upnp_time};
use crate::warp::StackBufferReader;
use crate::{Backend, MapEntry, OS, nat_impl};
use std::fs;
use std::fs::{File, remove_file};
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::ops::Add;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::rc::Rc;
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

fn lease_file_add(
	lease_file: &str,
	iaddr: Ipv4Addr,
	eport: u16,
	iport: u16,
	proto: u8,
	desc: Option<&str>,
	timestamp: u32,
) -> i32 {
	if lease_file.is_empty() {
		return 0;
	}
	let mut fd = match fs::OpenOptions::new().read(true).append(true).create(true).open(lease_file.as_str()) {
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
	let mut fd = match fs::File::open(lease_file.as_str()) {
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
	let mut buf = [0; 512];
	let mut fdr = StackBufferReader::new(&mut buf);
	let str = format!("{}:{}", proto_itoa(proto), eport);
	while let Some(Ok(l)) = fdr.read_line(&mut fd) {
		if let Ok(line) = str::from_utf8(&l) {
			if !line.starts_with(str.as_str()) {
				let _ = tmp.write(line.as_bytes());
				let _ = tmp.write(b"\n");
			}
		}
	}

	if let Err(_) = fs::rename(&tmpfilename, lease_file.as_str()) {
		error!("could not rename temporary lease file to {}", lease_file);
		let _ = fs::remove_file(tmpfilename.as_str());
	}
	0
}
pub fn reload_from_lease_file(op: &Options, rt: &mut RtOptions, lease_file: &str) -> io::Result<()> {
	if !Path::new(lease_file).exists() {
		return Err(io::ErrorKind::NotFound.into());
	}

	let mut file = File::open(lease_file)?;

	if remove_file(lease_file).is_err() {
		eprintln!("Warning: Could not unlink file {}", lease_file);
	}

	let current_time = upnp_time().as_secs();
	let mut buf = [0; 512];
	let mut fdr = StackBufferReader::new(&mut buf);

	while let Some(line_buf) = fdr.read_line(&mut file) {
		let line = str::from_utf8(line_buf?);
		if line.is_err() {
			continue;
		}
		let line = line.unwrap();
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
				notice!(
					"already expired lease in lease file ({}=>{}:{} {})",
					eport,
					iaddr,
					iport,
					proto_itoa(proto)
				);
				continue;
			} else {
				timestamp as u64 - current_time
			}
		} else {
			0
		};

		match upnp_redirect(
			op,
			rt,
			Ipv4Addr::UNSPECIFIED,
			iaddr,
			eport,
			iport,
			proto,
			desc,
			leaseduration as u32,
		) {
			-1 => eprintln!(
				"Error: Failed to redirect {} -> {}:{} protocol {}",
				eport, iaddr, iport, proto
			),
			-2 => {
				lease_file_add(&op.lease_file, iaddr, eport, iport, proto, desc, timestamp);
			}
			_ => {}
		}
	}

	Ok(())
}

pub fn upnp_redirect(
	op: &Options,
	rt: &mut RtOptions,
	raddr: Ipv4Addr,
	iaddr: Ipv4Addr,
	eport: u16,
	iport: u16,
	proto: u8,
	desc: Option<&str>,
	leaseduration: u32,
) -> i32 {
	// let op = global_option.get().unwrap();

	if !check_upnp_rule_against_permissions(&op.upnpperms, eport, iaddr, iport, desc.unwrap_or("")) {
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
		.get_redirect_rule(|x| x.iport == eport && x.proto == proto && x.iaddr == iaddr && x.eport == iport)
	{
		if entry.iaddr == iaddr && raddr.is_unspecified() && entry.eaddr.is_unspecified() {
			debug!(
				"updating existing port mapping {} {} (rhost '{}') => {}:{}",
				eport, proto, raddr, iaddr, iport
			);

			let timestamp = if leaseduration > 0 {
				upnp_time().as_secs() + leaseduration as u64
			} else {
				0
			} as u32;
			let op = global_option.get().unwrap();
			let ret = if iport != entry.eport {
				rt.nat_impl.update_portmapping(&op.ext_ifname, eport, proto, iport, desc.unwrap(), timestamp)
			} else {
				rt.nat_impl
					.update_portmapping_desc_timestamp(&op.ext_ifname, eport, proto, desc.unwrap(), timestamp)
			};

			if ret == 0 {
				lease_file_remove(eport, proto);
				lease_file_add(&op.lease_file, iaddr, eport, iport, proto, desc, timestamp);
			}
			if ret == 0 {
				info!(
					"action=UpdatePortMapping rhost={} eport={} iaddr={} iport={} proto={} desc={} timestamp={}",
					raddr,
					eport,
					iaddr,
					iport,
					proto_itoa(proto),
					desc.unwrap_or_default(),
					timestamp
				);
			}
			return ret;
		} else {
			info!(
				"port {} {} (rhost '{}') already redirected to {}:{}",
				eport, proto, raddr, iaddr, iport
			);
			return -2;
		}
	} else if cfg!(feature = "portinuse")
		&& rt.os.port_in_use(&rt.nat_impl, &op.ext_ifname, eport, proto, &iaddr, iport) > 0
	{
		info!("port {} protocol {} already in use", eport, proto);
		return -4;
	} else {
		let timestamp = if leaseduration > 0 {
			upnp_time().as_secs() + leaseduration as u64
		} else {
			0
		} as u32;
		debug!(
			"redirecting port {} to {}:{} protocol {} for: {}",
			eport,
			proto,
			iaddr,
			iport,
			desc.unwrap_or_default()
		);
		let entry = MapEntry {
			iaddr,
			eport,
			iport,
			raddr,
			proto,
			desc: desc.map(Rc::from),
			timestamp: timestamp as _,
			..Default::default()
		};
		return upnp_redirect_internal(op, rt, &entry);
	}
}

pub fn upnp_redirect_internal(op: &Options, rt: &mut RtOptions, entry: &MapEntry) -> i32 {
	if !GETFLAG!(op.runtime_flags, ALLOWPRIVATEIPV4MASK) && rt.disable_port_forwarding {
		return -1;
	}
	if rt.nat_impl.add_redirect_rule(&op.ext_ifname, &entry) < 0 {
		return -1;
	}
	lease_file_add(
		&op.lease_file,
		entry.iaddr,
		entry.eport,
		entry.iport,
		entry.proto,
		entry.desc.as_deref(),
		entry.timestamp as _,
	);
	if rt.nat_impl.add_filter_rule(&op.ext_ifname, &entry) < 0 {
		return -(1);
	}
	if entry.timestamp > 0 {
		let add = Duration::from_secs(entry.timestamp) - upnp_time();
		let xx = Instant::now() + add;
		if xx < rt.nextruletoclean_timestamp {
			rt.nextruletoclean_timestamp = xx;
		}
	}
	info!(
		"action=AddPortMapping rhost={} eport={} iaddr={} iport={} proto={} desc={} timestamp={}",
		entry.raddr,
		entry.eport,
		entry.iaddr,
		entry.iport,
		proto_itoa(entry.proto),
		entry.desc.as_deref().unwrap_or_default(),
		entry.timestamp
	);
	upnp_event_var_change_notify(&mut rt.subscriber_list, EWanIPC);
	return 0;
}
pub fn upnp_get_redirection_infos(nat: &nat_impl, eport: u16, protocol: u8) -> Option<MapEntry> {
	nat.get_redirect_rule(|x| x.iport == eport && x.proto == protocol)
}
pub fn upnp_get_redirection_infos_by_index(nat: &nat_impl, index: usize) -> Option<MapEntry> {
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

pub fn _upnp_delete_redir(rt: &mut RtOptions, eport: u16, proto: u8) -> i32 {
	let op = global_option.get().unwrap();
	let r = rt.nat_impl.delete_redirect_and_filter_rules(&op.ext_ifname, eport, proto);
	lease_file_remove(eport, proto);
	#[cfg(feature = "events")]
	upnp_event_var_change_notify(&mut rt.subscriber_list, EWanIPC);
	if r == 0 {
		info!(
			"action={} eport={} proto={}",
			"DeletePortMapping",
			eport,
			proto_itoa(proto)
		);
	} else {
		info!(
			"failed to remove port mapping eport={} proto={}",
			eport,
			proto_itoa(proto)
		);
	}
	r
}

pub fn upnp_delete_redirection(rt: &mut RtOptions, eport: u16, protocol: u8) -> i32 {
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
				eport: entry.eport,
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
		if let Some(entry) = rt.nat_impl.get_redirect_rule(|x| x.eport == rule.eport && rule.proto == x.proto) {
			if rule.packets == entry.packets && rule.bytes == entry.bytes {
				debug!(
					"removing unused mapping {} {}: still {} packets {} packets",
					rule.eport, rule.proto, entry.packets, entry.bytes
				);
				_upnp_delete_redir(rt, rule.eport, rule.proto);
				let _ = rule;
				list.swap_remove(idx);
				continue;
			}
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
