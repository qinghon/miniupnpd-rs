
use crate::getifaddr::{addr_is_reserved, getifaddr};
use crate::upnpevents::{subscriber, upnp_event_notify};
use crate::upnpglobalvars::{lan_addr_s};
pub use crate::upnppermissions::{read_permission_line, upnpperm};
use crate::warp::IfName;
use crate::{error, nat_impl, os};
use std::cell::RefCell;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::str::FromStr;
use std::time::{Duration, Instant};
use crate::uuid::UUID;

pub const DEFAULT_MINISSDP_DSOCKET_PATH: &'static str = "/var/run/minissdpd.sock";

#[derive(Default)]
pub struct Options {
	pub ext_ifname: IfName,

	pub ext_ifname6: IfName,
	pub ext_ip: Option<Ipv4Addr>,
	pub ext_perform_stun: bool,
	pub ext_stun_host: Option<String>,
	pub ext_stun_port: u16,
	pub listening_ip: Vec<lan_addr_s>,
	pub ipv6_listening_ip: Option<Ipv6Addr>,
	pub ipv6_disable: bool,
	pub port: u16,
	pub http_port: u16,
	#[cfg(feature = "https")]
	pub https_port: u16,
	pub bitrate_up: Option<usize>,
	pub bitrate_down: Option<usize>,
	pub presentation_url: Option<String>,
	pub notify_interval: u32,
	pub system_uptime: bool,
	pub packet_log: bool,
	pub uuid: UUID,
	pub serial: String,
	pub model_number: String,
	pub clean_ruleset_threshold: u32,
	pub clean_ruleset_interval: u32,
	pub upnp_table_name: String,
	pub upnp_nat_table_name: String,
	pub upnp_forward_chain: String,
	pub upnp_nat_chain: String,
	pub upnp_nat_postrouting_chain: String,
	pub upnp_nftables_family_split: bool,
	pub enable_natpmp: bool,
	pub enable_pcp_pmp: bool,
	pub min_lifetime: usize,
	pub max_lifetime: usize,
	pub pcp_allow_thirdparty: String,
	pub enable_upnp: bool,
	pub lease_file: String,
	pub lease_file6: String,
	pub force_igd_desc_v1: bool,
	pub minissdpdsocket: Option<PathBuf>,
	pub secure_mode: bool,
	pub quickrules: bool,
	pub upnpperms: Vec<upnpperm>,

	// re-generation once init flag
	pub upnp_bootid: u32,
	pub runtime_flag: u32,
}

pub struct RtOptions {
	pub use_ext_ip_addr: Option<IpAddr>,
	pub disable_port_forwarding: bool,
	pub epoch_origin: Duration,
	pub nat_impl: nat_impl,
	pub nextruletoclean_timestamp: Instant,
	pub subscriber_list: Vec<Rc<RefCell<subscriber>>>,
	pub notify_list: Vec<upnp_event_notify>,
	pub os: os,
}

pub fn parselanaddr(lan_addr: &mut lan_addr_s, lan: &str) -> i32 {
	if let Ok(ifname) = IfName::from_str(lan) {
		if getifaddr(&ifname, &mut lan_addr.addr, Some(&mut lan_addr.mask)) <= 0 {
			lan_addr.index = ifname.index();
			lan_addr.ifname = ifname;
		} else {
			eprintln!("interface \"{}\" has no IPv4 address", lan);
			notice!("interface \"{}\" has no IPv4 address", lan);
		}
	} else {
		if let Ok(ipn) = ipnet::Ipv4Net::from_str(lan) {
			lan_addr.addr = ipn.addr();
			lan_addr.mask = ipn.netmask();
			return 0;
		}
		match Ipv4Addr::from_str(lan) {
			Ok(ip) => {
				lan_addr.addr = ip;
				lan_addr.mask = Ipv4Addr::new(255, 255, 255, 0)
			}
			Err(_) => {
				println!("cannot parse addr {lan}");
			}
		}
	}
	if ! addr_is_reserved(&lan_addr.addr) {
		println!("Error: LAN address contains public IP address : {}", lan_addr.addr);
		println!("Public IP address can be configured via ext_ip= option");
		println!("LAN address should contain private address, e.g. from 192.168. block");
		println!("Listening on public IP address is a security issue");
		return -1;
	}

	0
}

fn parse_option_line(op: &mut Options, key: &str, value: &str) -> bool {
	if value.is_empty() {
		return false;
	};

	match key {
		"ext_ifname" => {
			op.ext_ifname = match IfName::from_str(value) {
				Ok(x) => x,
				Err(_) => return false,
			};
		}
		#[cfg(feature = "ipv6")]
		"ext_ifname6" => {
			op.ext_ifname6 = match IfName::from_str(value) {
				Ok(x) => x,
				Err(_) => return false,
			};
		}
		"ext_ip" => match Ipv4Addr::from_str(&value) {
			Ok(ip) => {
				op.ext_ip = Some(ip);
			}
			Err(_) => return false,
		},
		"ext_perform_stun" => match parse_bool(value) {
			Some(v) => {
				op.ext_perform_stun = v;
			}
			None => return false,
		},
		"ext_stun_host" => {
			op.ext_stun_host = Some(value.to_string());
		}
		"ext_stun_port" => {
			op.ext_stun_port = u16::from_str(&value).unwrap_or(0);
		}
		"listening_ip" => {
			let mut lan_addr = Default::default();
			if parselanaddr(&mut lan_addr, value) >= 0 {
				op.listening_ip.push(lan_addr);
			} else {
				return false;
			}
		}
		#[cfg(feature = "ipv6")]
		"ipv6_listening_ip" => match Ipv6Addr::from_str(&value) {
			Ok(ip) => {
				op.ipv6_listening_ip = Some(ip);
			}
			Err(_) => return false,
		},
		#[cfg(feature = "ipv6")]
		"ipv6_disable" => match parse_bool(value) {
			Some(v) => {
				op.ipv6_disable = v;
			}
			None => return false,
		},
		"port" => match u16::from_str(value) {
			Ok(v) => {
				op.port = v;
			}
			Err(_) => return false,
		},
		"http_port" => match u16::from_str(value) {
			Ok(v) => {
				op.http_port = v;
			}
			Err(_) => return false,
		},
		"bitrate_up" => match usize::from_str(value) {
			Ok(v) => {
				op.bitrate_up = Some(v);
			}
			Err(_) => return false,
		},
		"bitrate_down" => match usize::from_str(value) {
			Ok(v) => {
				op.bitrate_down = Some(v);
			}
			Err(_) => return false,
		},
		"presentation_url" => {
			op.presentation_url = Some(value.to_string());
		}
		"notify_interval" => match u32::from_str(value) {
			Ok(v) => {
				op.notify_interval = v;
			}
			Err(_) => return false,
		},
		"system_uptime" => match parse_bool(value) {
			Some(v) => op.system_uptime = v,
			None => return false,
		},
		"packet_log" => match parse_bool(value) {
			Some(v) => op.system_uptime = v,
			None => return false,
		},
		"uuid" => match UUID::from_str(value) {
			Ok(v) => {
				op.uuid = v;
			}
			Err(e) => {
				eprintln!("parse uuid \"{}\" {}", value, e);
			}
		},
		"serial" => op.serial = value.to_string(),
		"model_number" => op.model_number = value.to_string(),
		"clean_ruleset_threshold" => match u32::from_str(value) {
			Ok(v) => {
				op.clean_ruleset_interval = v;
			}
			Err(_) => return false,
		},
		"clean_ruleset_interval" => match u32::from_str(value) {
			Ok(v) => {
				op.clean_ruleset_interval = v;
			}
			Err(_) => return false,
		},
		#[cfg(fw = "nftables")]
		"upnp_table_name" => op.upnp_table_name = value.to_string(),
		#[cfg(fw = "nftables")]
		"upnp_nat_table_name" => op.upnp_nat_table_name = value.to_string(),
		#[cfg(fw = "nftables")]
		"upnp_forward_chain" => op.upnp_forward_chain = value.to_string(),
		#[cfg(fw = "nftables")]
		"upnp_nat_chain" => op.upnp_nat_chain = value.to_string(),
		#[cfg(fw = "nftables")]
		"upnp_nat_postrouting_chain" => op.upnp_nat_postrouting_chain = value.to_string(),
		#[cfg(fw = "nftables")]
		"upnp_nftables_family_split" => match parse_bool(value) {
			Some(v) => op.upnp_nftables_family_split = v,
			None => return false,
		},

		"enable_natpmp" => match parse_bool(value) {
			Some(v) => op.enable_natpmp = v,
			None => return false,
		},
		"enable_pcp_pmp" => match parse_bool(value) {
			Some(v) => op.enable_pcp_pmp = v,
			None => return false,
		},
		#[cfg(feature = "pcp")]
		"min_lifetime" => match usize::from_str(value) {
			Ok(v) => op.min_lifetime = v,
			Err(_) => return false,
		},
		#[cfg(feature = "pcp")]
		"max_lifetime" => match usize::from_str(value) {
			Ok(v) => op.max_lifetime = v,
			Err(_) => return false,
		},
		"pcp_allow_thirdparty" => op.pcp_allow_thirdparty = value.to_string(),
		"enable_upnp" => match parse_bool(value) {
			Some(v) => op.enable_upnp = v,
			None => return false,
		},
		"lease_file" => op.lease_file = value.to_string(),
		"lease_file6" => op.lease_file6 = value.to_string(),
		#[cfg(feature = "igd2")]
		"force_igd_desc_v1" => match parse_bool(value) {
			Some(v) => op.force_igd_desc_v1 = v,
			None => return false,
		},
		"minissdpdsocket" => op.minissdpdsocket = Some(PathBuf::from(value)),
		"secure_mode" => match parse_bool(value) {
			Some(v) => op.secure_mode = v,
			None => return false,
		},
		"quickrules" => match parse_bool(value) {
			Some(v) => op.quickrules = v,
			None => return false,
		},
		// ignore unknown option
		_ => return true,
	}
	true
}

pub fn readoptionsfile(fname: &Path, _debug_flag: i32) -> Result<Options, io::Error> {
	trace!("Reading configuration from file {:?}", fname);
	let file = File::open(fname)?;

	let reader = BufReader::with_capacity(1024, file);
	let mut perms = vec![];
	let mut option = Options::default();

	for line in reader.lines() {
		let line = line?;
		if line.trim_start().is_empty() || line.trim_start().starts_with('#') {
			continue;
		}
		let line_ = line.trim_start();
		if line_.starts_with("allow") | line_.starts_with("deny") {
			let perm = read_permission_line(line_)?;
			perms.push(perm);
			continue;
		}
		if let Some((key, value)) = line_.split_once('=') {
			if !parse_option_line(&mut option, key, value) {
				error!("cannot parse option {}", line_);
			}
		}
	}
	option.upnpperms = perms;

	Ok(option)
}

fn parse_bool(s: &str) -> Option<bool> {
	if s.is_empty() {
		return None;
	}
	match s {
		"true" | "yes" | "True" => Some(true),
		"false" | "no" | "False" => Some(false),
		_ => None,
	}
}

#[cfg(test)]

mod tests {
	use crate::options::parselanaddr;
	use std::net::Ipv4Addr;

	#[test]
	fn test_readoptionsfile() {}
	#[test]
	fn test_parse_lan() {
		let mut lan_addr = Default::default();
		assert_eq!(parselanaddr(&mut lan_addr, "127.0.0.1"), 0);
		assert_eq!(parselanaddr(&mut lan_addr, "127.0.0.1/8"), 0);
		#[cfg(target_family = "unix")]
		{
			// let lan = parselanaddr("lo").unwrap();
			assert!(parselanaddr(&mut lan_addr, "lo") >= 0);
			assert_eq!(lan_addr.addr, Ipv4Addr::new(127, 0, 0, 1));
		}
	}
}
