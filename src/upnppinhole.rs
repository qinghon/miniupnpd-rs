use crate::options::Options;
use crate::upnpglobalvars::global_option;
use crate::upnputils::{proto_atoi, proto_itoa, upnp_time};
use crate::warp::StackBufferReader;
use crate::{Backend, PinholeEntry, nat_impl};
use std::fmt::Write as FmtWrite;
use std::fs::{File, remove_file};
use std::io::Write;
use std::net::Ipv6Addr;
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;
use std::rc::Rc;
use std::{fs, io};

pub fn reload_from_lease_file6(op: &Options, nat: &mut nat_impl, lease_file6: &str) -> io::Result<()> {
	if !Path::new(lease_file6).exists() {
		return Err(io::ErrorKind::NotFound.into());
	}

	let mut file = File::open(lease_file6)?;

	if remove_file(lease_file6).is_err() {
		eprintln!("Warning: Could not unlink file {}", lease_file6);
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
		let _uid = match parts.next().and_then(|s| s.parse::<i32>().ok()) {
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
		let mut pinhole = PinholeEntry {
			raddr: rem_client,
			rport: rem_port,
			iport: int_port,
			proto,
			iaddr: int_client,
			desc: desc.map(Rc::from),
			timestamp: upnp_time().as_secs() + leaseduration,
			..Default::default()
		};
		let r = upnp_add_inboundpinhole(op, nat, &pinhole, &mut uid_new);
		if r == -1 {
			error!(
				"Error: Failed to add {}:{} -> {}:{} protocol {}",
				rem_client, rem_port, int_client, int_port, proto
			);
		} else if r == -2 {
			pinhole.index = uid_new as _;
			lease_file6_add(&pinhole, uid_new as _, &op.lease_file6);
		}
	}

	Ok(())
}

fn lease_file6_add(pinhole: &PinholeEntry, uid: i32, lease_file6: &str) -> i32 {
	if lease_file6.is_empty() {
		return 0;
	}
	let mut fd = match fs::OpenOptions::new().read(true).append(true).open(lease_file6) {
		Ok(fd) => fd,
		Err(_) => {
			error!("could to open lease file {}", lease_file6);
			return -1;
		}
	};
	let timestamp = if pinhole.timestamp > 0 { pinhole.timestamp } else { 0 };

	// if timestamp != 0 {
	//     // timestamp -= upnp_time().as_secs() as u32;
	// };
	let uid = if uid >= 0 { uid as u16 } else { pinhole.index as u16 };
	let mut raddr = arrayvec::ArrayString::<60>::new();
	if !pinhole.raddr.is_unspecified() {
		let _ = FmtWrite::write_fmt(&mut raddr, format_args!("{}", pinhole.raddr));
	}
	let _ = writeln!(
		fd,
		"{};{};{};{};{};{};{};{}",
		proto_itoa(pinhole.proto),
		pinhole.iaddr,
		pinhole.iport,
		raddr,
		pinhole.rport,
		uid,
		timestamp,
		pinhole.desc.as_deref().unwrap_or_default()
	);

	0
}
fn lease_file6_update(uid: i32, leaseduration: u32) -> i32 {
	let lease_file = &global_option.get().unwrap().lease_file6;
	if lease_file.is_empty() {
		return 0;
	}
	let mut fd = match File::open(lease_file.as_str()) {
		Ok(fd) => fd,
		Err(_) => return -1,
	};
	let tmpfilename = format!("{}XXXXXX", lease_file);

	let mut tmp = match File::create(tmpfilename.as_str()) {
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
	let mut buf = [0; 128];
	let mut fdr = StackBufferReader::new(&mut buf);
	// let mut buf = String::with_capacity(128);

	let mut uid_str = arrayvec::ArrayString::<60>::new();

	let _ = FmtWrite::write_fmt(&mut uid_str, format_args!("{uid}"));
	while let Some(Ok(line_buf)) = fdr.read_line(&mut fd) {
		if let Ok(buf) = str::from_utf8(line_buf) {
			// if l == 0 {
			// 	break;
			// }
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

			if uid == uid_str.as_str() {
				let _ = writeln!(
					tmp,
					"{proto};{int_client};{int_port};{rem_client};{rem_port};{uid};{timestamp};{desc}",
				);
			} else {
				let _ = writeln!(
					tmp,
					"{proto};{int_client};{int_port};{rem_client};{rem_port};{uid};{timestamp_};{desc}",
				);
			}
		}
	}

	if let Err(_) = fs::rename(&tmpfilename, lease_file.as_str()) {
		error!("could not rename temporary lease file to {}", lease_file);
		let _ = remove_file(tmpfilename.as_str());
	}
	0
}
fn lease_file6_remove(int_client: Ipv6Addr, int_port: u16, proto: u8, uid: i32) -> i32 {
	let lease_file = &global_option.get().unwrap().lease_file6;
	if lease_file.is_empty() {
		return 0;
	}
	let mut fd = match File::open(lease_file.as_str()) {
		Ok(fd) => fd,
		Err(_) => return -1,
	};
	let tmp_filename = format!("{}XXXXXX", lease_file);

	let mut tmp = match File::create(tmp_filename.as_str()) {
		Ok(f) => f,
		Err(_) => {
			error!("could not open temporary lease file");
			return -1;
		}
	};

	let _ = tmp.set_permissions(fs::Permissions::from_mode(0o644));
	let mut buf = [0; 128];
	let mut fdr = StackBufferReader::new(&mut buf);
	let mut uid_str = arrayvec::ArrayString::<60>::new();
	let mut prefix_str = arrayvec::ArrayString::<60>::new();

	let _ = FmtWrite::write_fmt(&mut uid_str, format_args!("{uid}"));
	let _ = FmtWrite::write_fmt(
		&mut prefix_str,
		format_args!("{};{};{}", proto_itoa(proto), int_client, int_port),
	);

	while let Some(Ok(line_buf)) = fdr.read_line(&mut fd) {
		if let Ok(buf) = str::from_utf8(line_buf) {
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

				if uid == uid_str.as_str() {
					continue;
				}

				let _ = write!(
					tmp,
					"{proto};{int_client};{int_port};{rem_client};{rem_port};{uid};{timestamp};{desc}\n"
				);
			} else if !buf.starts_with(prefix_str.as_str()) {
				let _ = writeln!(tmp, "{}", buf.as_str());
			}
		}
	}

	if let Err(_) = fs::rename(&tmp_filename, lease_file.as_str()) {
		error!("could not rename temporary lease file to {}", lease_file);
		let _ = remove_file(tmp_filename.as_str());
	}
	0
}

pub fn lease_file6_expire() -> i32 {
	let lease_file = &global_option.get().unwrap().lease_file6;
	if lease_file.is_empty() {
		return 0;
	}
	let mut fd = match File::open(lease_file.as_str()) {
		Ok(fd) => fd,
		Err(_) => return -1,
	};
	let tmpfilename = format!("{}XXXXXX", lease_file);

	let mut tmp = match File::create(tmpfilename.as_str()) {
		Ok(f) => f,
		Err(_) => {
			error!("could not open temporary lease file");
			return -1;
		}
	};

	let _ = tmp.set_permissions(fs::Permissions::from_mode(0o644));
	let mut buf = [0; 128];
	let mut fdr = StackBufferReader::new(&mut buf);

	let current_unix_time = upnp_time().as_secs();

	while let Some(Ok(line_buf)) = fdr.read_line(&mut fd) {
		if let Ok(buf) = str::from_utf8(line_buf) {
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

			if let Ok(t) = u64::from_str_radix(timestamp, 10) {
				debug!("Expire: timestamp is '{}'", t);
				debug!("Expire: current timestamp is '{}'", current_unix_time);
				if t > 0 && current_unix_time > t || t == 0 {
					continue;
				}
			}

			let _ = writeln!(
				tmp,
				"{proto};{int_client};{int_port};{rem_client};{rem_port};{uid};{timestamp};{desc}"
			);
		}
	}

	if let Err(_) = fs::rename(&tmpfilename, lease_file.as_str()) {
		error!("could not rename temporary lease file to {}", lease_file);
		let _ = remove_file(tmpfilename.as_str());
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
pub fn upnp_add_inboundpinhole(op: &Options, nat: &mut nat_impl, pe: &PinholeEntry, uid: &mut u16) -> i32 {
	// let timestamp = upnp_time().as_secs() + pinhole_entry.timestamp;

	let mut uid_old = -1;
	if let Some(iter) = nat.get_pinhole_iter() {
		for entry in iter {
			if pe.raddr.is_unspecified() {
				if pe.raddr == entry.raddr
					&& pe.rport == entry.rport
					&& pe.iaddr.eq(&entry.iaddr)
					&& pe.iport == entry.iport
					&& pe.proto == entry.proto
				{
					uid_old = entry.index as i32;
					info!(
						"Pinhole for inbound traffic from [{}]:{} to [{}]:{} with proto {} found uid={}. Updating it.",
						pe.raddr, pe.rport, pe.iaddr, pe.iport, pe.proto, entry.index
					);
				}
			} else if pe.rport == entry.rport
				&& pe.iaddr.eq(&entry.iaddr)
				&& pe.iport == entry.iport
				&& pe.proto == entry.proto
			{
				info!(
					"Pinhole for inbound traffic from [{}]:{} to [{}]:{} with proto {} found uid={}. Updating it.",
					Ipv6Addr::UNSPECIFIED,
					pe.rport,
					pe.iaddr,
					pe.iport,
					pe.proto,
					entry.index
				);
				uid_old = entry.index as i32;
			}
		}
	}

	if uid_old != -1 {
		let r = upnp_update_inboundpinhole(nat, uid_old as u16, pe.timestamp as _);
		if r >= 0 {
			lease_file6_remove(pe.iaddr, pe.iport, pe.proto, -1);
			lease_file6_add(pe, uid_old, &op.lease_file6);
		}
		return if r >= 0 { 1 } else { r };
	}
	let ext_ifname6 = &global_option.get().unwrap().ext_ifname6;
	let uid_new = nat.add_pinhole(ext_ifname6, pe);
	if uid_new >= 0 {
		lease_file6_remove(pe.iaddr, pe.iport, pe.proto, -1);
		lease_file6_add(pe, uid_new, &op.lease_file6);
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
