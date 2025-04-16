use crate::upnpglobalvars::global_option;
use crate::upnputils::{proto_atoi, proto_itoa, upnp_time};
use crate::{Backend, PinholeEntry, nat_impl};
use std::fs::{File, remove_file};
use std::io::{BufRead, Write};
use std::net::Ipv6Addr;
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;
use std::rc::Rc;
use std::{fs, io};

pub fn reload_from_lease_file6(nat: &mut nat_impl, lease_file6: &str) -> io::Result<()> {
	if !Path::new(lease_file6).exists() {
		return Err(io::ErrorKind::NotFound.into());
	}

	let file = File::open(lease_file6)?;

	if remove_file(lease_file6).is_err() {
		eprintln!("Warning: Could not unlink file {}", lease_file6);
	}

	let current_time = upnp_time().as_secs();

	for line in io::BufReader::new(file).lines() {
		let line = line?;
		println!("Parsing lease file line '{}'", line);

		let mut parts = line.split(';');

		let proto = match parts.next().and_then(|s| Some(proto_atoi(s))) {
			Some(proto) => proto,
			None => continue,
		};
		let int_client = match parts.next().and_then(|s| s.parse::<Ipv6Addr>().ok()) {
			Some(int) => int,
			None => continue,
		};
		let int_port = match parts.next().and_then(|s| s.parse::<u16>().ok()) {
			Some(s) => s,
			None => continue,
		};
		let rem_client = match parts.next().and_then(|s| s.parse::<Ipv6Addr>().ok()) {
			Some(rem) => rem,
			None => continue,
		};
		let rem_port = match parts.next().and_then(|s| s.parse::<u16>().ok()) {
			Some(p) => p,
			None => continue,
		};
		let uid = match parts.next().and_then(|s| s.parse::<i32>().ok()) {
			Some(uid) => uid,
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
		let mut uid_new = 0;
		let r = upnp_add_inboundpinhole(
			nat,
			Some(rem_client),
			rem_port,
			int_client,
			int_port,
			proto,
			desc,
			leaseduration as u32,
			&mut uid_new,
		);
		if r == -1 {
			error!(
				"Error: Failed to add {}:{} -> {}:{} protocol {}",
				rem_client, rem_port, int_client, int_port, proto
			);
		} else if r == -2 {
			lease_file6_add(
				Some(rem_client),
				int_client,
				rem_port,
				int_port,
				proto,
				desc,
				uid as u32,
				timestamp,
			);
		}
	}

	Ok(())
}

fn lease_file6_add(
	raddr: Option<Ipv6Addr>,
	iaddr: Ipv6Addr,
	eport: u16,
	iport: u16,
	proto: u8,
	desc: Option<&str>,
	uid: u32,
	leaseduration: u32,
) -> i32 {
	let lease_file = global_option.get().unwrap().lease_file6.as_str();
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
	let timestamp = if leaseduration > 0 {
		upnp_time().as_secs() + leaseduration as u64
	} else {
		0
	};

	// if timestamp != 0 {
	//     // timestamp -= upnp_time().as_secs() as u32;
	// };

	let _ = write!(
		fd,
		"{};{iaddr};{iport};{};{eport};{uid};{timestamp};{}\n",
		proto_itoa(proto),
		if raddr.is_none() {
			"".to_string()
		} else {
			format!("{}", raddr.unwrap())
		},
		desc.unwrap_or("")
	);

	0
}
fn lease_file6_update(uid: i32, leaseduration: u32) -> i32 {
	let lease_file = &global_option.get().unwrap().lease_file6;
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

	let timestamp = if leaseduration > 0 {
		upnp_time().as_secs() + leaseduration as u64
	} else {
		0
	};

	let _ = tmp.set_permissions(fs::Permissions::from_mode(0o644));
	let mut fdr = io::BufReader::new(fd);
	let mut buf = String::with_capacity(128);
	let uid_str = format!("{}", uid);
	loop {
		match fdr.read_line(&mut buf) {
			Ok(l) => {
				if l == 0 {
					break;
				}
				if buf.trim().is_empty() {
					continue;
				}
				let mut split = buf.split(';');

				let proto = match split.next() {
					Some(v) => v,
					None => break,
				};
				let int_client = match split.next() {
					Some(v) => v,
					None => break,
				};
				let int_port = match split.next() {
					Some(v) => v,
					None => break,
				};
				let rem_client = match split.next() {
					Some(v) => v,
					None => break,
				};
				let rem_port = match split.next() {
					Some(v) => v,
					None => break,
				};
				let uid = match split.next() {
					Some(v) => v,
					None => break,
				};
				let timestamp_ = match split.next() {
					Some(v) => v,
					None => break,
				};
				let desc = match split.next() {
					Some(v) => v,
					None => break,
				};

				if uid == uid_str {
					let _ = write!(
						tmp,
						"{proto};{int_client};{int_port};{rem_client};{rem_port};{uid};{};{desc}\n",
						format!("{}", timestamp).as_str()
					);
				} else {
					let _ = write!(
						tmp,
						"{proto};{int_client};{int_port};{rem_client};{rem_port};{uid};{timestamp_};{desc}\n",
					);
				}
			}
			Err(_) => break,
		}
	}

	if let Err(_) = fs::rename(&tmpfilename, lease_file) {
		error!("could not rename temporary lease file to {}", lease_file);
		let _ = fs::remove_file(tmpfilename.as_str());
	}
	0
}
fn lease_file6_remove(int_client: Ipv6Addr, int_port: u16, proto: u8, uid: i32) -> i32 {
	let lease_file = &global_option.get().unwrap().lease_file6;
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
	let mut buf = String::with_capacity(128);
	let uid_str = format!("{}", uid);

	let prefix_str = format!("{};{};{}", proto_itoa(proto), int_client, int_port);

	loop {
		match fdr.read_line(&mut buf) {
			Ok(l) => {
				if l == 0 {
					break;
				}
				if buf.trim().is_empty() {
					continue;
				}
				if uid > 0 {
					let mut split = buf.split(';');

					let proto = match split.next() {
						Some(v) => v,
						None => break,
					};
					let int_client = match split.next() {
						Some(v) => v,
						None => break,
					};
					let int_port = match split.next() {
						Some(v) => v,
						None => break,
					};
					let rem_client = match split.next() {
						Some(v) => v,
						None => break,
					};
					let rem_port = match split.next() {
						Some(v) => v,
						None => break,
					};
					let uid = match split.next() {
						Some(v) => v,
						None => break,
					};
					let timestamp = match split.next() {
						Some(v) => v,
						None => break,
					};
					let desc = match split.next() {
						Some(v) => v,
						None => break,
					};

					if uid == uid_str {
						continue;
					}

					let _ = write!(
						tmp,
						"{proto};{int_client};{int_port};{rem_client};{rem_port};{uid};{timestamp};{desc}\n"
					);
				} else if !buf.starts_with(prefix_str.as_str()) {
					let _ = write!(tmp, "{}\n", buf.as_str());
				}
			}
			Err(_) => break,
		}
	}

	if let Err(_) = fs::rename(&tmpfilename, lease_file) {
		error!("could not rename temporary lease file to {}", lease_file);
		let _ = fs::remove_file(tmpfilename.as_str());
	}
	0
}

pub fn lease_file6_expire() -> i32 {
	let lease_file = &global_option.get().unwrap().lease_file6;
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
	let mut buf = String::with_capacity(128);

	let current_unix_time = upnp_time().as_secs();

	loop {
		match fdr.read_line(&mut buf) {
			Ok(l) => {
				if l == 0 {
					break;
				}
				if buf.trim().is_empty() {
					continue;
				}
				let mut split = buf.split(';');

				let proto = match split.next() {
					Some(v) => v,
					None => continue,
				};
				let int_client = match split.next() {
					Some(v) => v,
					None => continue,
				};
				let int_port = match split.next() {
					Some(v) => v,
					None => continue,
				};
				let rem_client = match split.next() {
					Some(v) => v,
					None => continue,
				};
				let rem_port = match split.next() {
					Some(v) => v,
					None => continue,
				};
				let uid = match split.next() {
					Some(v) => v,
					None => continue,
				};
				let timestamp = match split.next() {
					Some(v) => v,
					None => continue,
				};
				let desc = match split.next() {
					Some(v) => v,
					None => continue,
				};

				match u64::from_str_radix(timestamp, 10) {
					Ok(t) => {
						debug!("Expire: timestamp is '{}'", t);
						debug!("Expire: current timestamp is '{}'", current_unix_time);
						if t > 0 && current_unix_time > t || t == 0 {
							continue;
						}
					}
					Err(_) => {}
				}

				let _ = write!(
					tmp,
					"{proto};{int_client};{int_port};{rem_client};{rem_port};{uid};{timestamp};{desc}\n"
				);
			}
			Err(_) => break,
		}
	}

	if let Err(_) = fs::rename(&tmpfilename, lease_file) {
		error!("could not rename temporary lease file to {}", lease_file);
		let _ = fs::remove_file(tmpfilename.as_str());
	}
	0
}

pub fn upnp_find_inboundpinhole<P>(nat: &mut nat_impl, filter: P) -> Option<&PinholeEntry>
where
	P: Fn(&PinholeEntry) -> bool,
{
	if let Some(mut iter) = nat.get_pinhole_iter() {
		if let Some(p) = iter.find(|x| filter(x)) {
			return Some(p);
		}
	}
	None
}
pub fn upnp_add_inboundpinhole(
	nat: &mut nat_impl,
	raddr: Option<Ipv6Addr>,
	rport: u16,
	iaddr: Ipv6Addr,
	iport: u16,
	proto: u8,
	desc: Option<&str>,
	leasetime: u32,
	uid: &mut u16,
) -> i32 {
	let timestamp = upnp_time().as_secs() + leasetime as u64;

	let mut uid_old = -1;
	if let Some(iter) = nat.get_pinhole_iter() {
		for entry in iter {
			if let Some(raddr) = raddr.as_ref() {
				if raddr.eq(&entry.eaddr)
					&& rport == entry.eport
					&& iaddr.eq(&entry.iaddr)
					&& iport == entry.iport
					&& proto == entry.proto
				{
					uid_old = entry.index as i32;
					info!(
						"Pinhole for inbound traffic from [{}]:{} to [{}]:{} with proto {} found uid={}. Updating it.",
						raddr, rport, iaddr, iport, proto, entry.index
					);
				}
			} else if rport == entry.eport && iaddr.eq(&entry.iaddr) && iport == entry.iport && proto == entry.proto {
				info!(
					"Pinhole for inbound traffic from [{}]:{} to [{}]:{} with proto {} found uid={}. Updating it.",
					Ipv6Addr::UNSPECIFIED,
					rport,
					iaddr,
					iport,
					proto,
					entry.index
				);
				uid_old = entry.index as i32;
			}
		}
	}

	if uid_old != -1 {
		let r = upnp_update_inboundpinhole(nat, uid_old as u16, leasetime);
		if r >= 0 {
			lease_file6_remove(iaddr, iport, proto, -1);
			lease_file6_add(
				raddr,
				iaddr,
				rport,
				iport,
				proto,
				desc,
				uid_old as u32,
				timestamp as u32,
			);
		}
		return if r >= 0 { 1 } else { r };
	}
	let ext_ifname6 = &global_option.get().unwrap().ext_ifname6;
	let uid_new = nat.add_pinhole(
		ext_ifname6,
		&PinholeEntry {
			index: 0,
			proto,
			iport,
			eport: rport,
			iaddr,
			eaddr: raddr.unwrap_or(Ipv6Addr::UNSPECIFIED),
			desc: desc.map(Rc::from),
			packets: 0,
			bytes: 0,
			timestamp,
		},
	);
	if uid_new >= 0 {
		lease_file6_remove(iaddr, iport, proto, -1);
		lease_file6_add(
			raddr,
			iaddr,
			rport,
			iport,
			proto,
			desc,
			uid_new as u32,
			timestamp as u32,
		);
		*uid = uid_new as u16;
	}
	if uid_new >= 0 { 1 } else { -1 }
}
pub fn upnp_get_pinhole_info(nat: &mut nat_impl, uid: u16) -> Option<&PinholeEntry> {
	for entry in nat.get_pinhole_iter()? {
		if entry.index as u16 == uid {
			return Some(entry);
		}
	}

	None
}

pub fn upnp_update_inboundpinhole(nat: &mut nat_impl, uid: u16, leasetime: u32) -> i32 {
	let timestamp = (upnp_time().as_secs() + leasetime as u64) as u32;
	let ret = nat.update_pinhole(uid, timestamp);
	if ret == 0 {
		lease_file6_update(uid as i32, timestamp);
	}
	ret
}
pub fn upnp_delete_inboundpinhole(nat: &mut nat_impl, uid: u16) -> i32 {
	let ret = nat.delete_pinhole(uid);
	if ret == 0 {
		lease_file6_remove(Ipv6Addr::UNSPECIFIED, 0, 0, uid as i32);
	}
	ret
}

pub fn upnp_clean_expired_pinholes(nat: &mut nat_impl, next_timestamp: &mut u32) -> i32 {
	let ret = nat.clean_pinhole_list(next_timestamp);
	lease_file6_expire();
	ret
}
