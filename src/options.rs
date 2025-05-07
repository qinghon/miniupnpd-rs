use crate::getifaddr::{addr_is_reserved, getifaddr};
#[cfg(feature = "pcp_sadscp")]
use crate::pcplearndscp::{dscp_value, read_learn_dscp_line};
use crate::upnpevents::{subscriber, upnp_event_notify};
use crate::upnpglobalvars::{lan_addr_s, IGNOREPRIVATEIPMASK};
pub use crate::upnppermissions::{read_permission_line, upnpperm};
use crate::uuid::UUID;
use crate::warp::{IfName, StackBufferReader};
use crate::{error, nat_impl, os};
#[cfg(feature = "https")]
use openssl_sys::SSL_CTX;
use std::cell::RefCell;
use std::ffi::CStr;
#[cfg(feature = "https")]
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use std::str::FromStr;
use std::time::{Duration, Instant};

pub const DEFAULT_MINISSDP_DSOCKET_PATH: &str = "/var/run/minissdpd.sock";
#[cfg(feature = "https")]
pub const DEFAULT_HTTPS_CERT: &CStr = c"/etc/miniupnpd/certificate.pem";
pub const DEFAULT_HTTPS_KEY: &CStr = c"/etc/miniupnpd/private-key.pem";

#[derive(Debug)]
pub struct Options {
	pub ext_ifname: IfName,

	pub ext_ifname6: IfName,
	pub ext_ip: Option<Ipv4Addr>,
	pub ext_perform_stun: bool,
	pub ext_stun_host: Option<Rc<str>>,
	pub ext_stun_port: u16,
	pub listening_ip: Vec<lan_addr_s>,
	pub ipv6_listening_ip: Option<Ipv6Addr>,
	pub ipv6_disable: bool,
	pub port: u16,
	pub http_port: u16,
	#[cfg(feature = "https")]
	pub https_port: u16,
	#[cfg(feature = "https")]
	pub https_cert: CString,
	#[cfg(feature = "https")]
	pub https_key: CString,

	pub bitrate_up: Option<usize>,
	pub bitrate_down: Option<usize>,
	pub presentation_url: Option<Rc<str>>,
	pub notify_interval: u32,
	pub system_uptime: bool,
	pub packet_log: bool,
	pub uuid: UUID,
	pub serial: Rc<str>,
	pub model_number: Rc<str>,
	pub clean_ruleset_threshold: u32,
	pub clean_ruleset_interval: u32,
	pub upnp_table_name: Rc<str>,
	pub upnp_nat_table_name: Rc<str>,
	pub upnp_forward_chain: Rc<str>,
	pub upnp_nat_chain: Rc<str>,
	pub upnp_nat_postrouting_chain: Rc<str>,
	pub upnp_nftables_family_split: bool,
	pub enable_natpmp: bool,
	pub enable_pcp_pmp: bool,
	pub min_lifetime: usize,
	pub max_lifetime: usize,
	pub pcp_allow_thirdparty: Rc<str>,
	pub enable_upnp: bool,
	pub lease_file: Rc<str>,
	pub lease_file6: Rc<str>,
	pub force_igd_desc_v1: bool,
	pub minissdpdsocket: Option<Rc<str>>,
	pub secure_mode: bool,
	pub quickrules: bool,
	pub upnpperms: Vec<upnpperm>,
	#[cfg(feature = "pcp_sadscp")]
	pub(crate) dscp_value: Vec<dscp_value>,

	// re-generation once init flag
	pub upnp_bootid: u32,
	pub runtime_flags: u32,
}

// Usually, manually implementing send/sync is not multi-threaded safe,
// but we only have one thread, so everything will be ok
unsafe impl Sync for Options {}
unsafe impl Send for Options {}

impl Default for Options {
	fn default() -> Self {
		Self {
			ext_ifname: Default::default(),
			ext_ifname6: Default::default(),
			ext_ip: None,
			ext_perform_stun: false,
			ext_stun_host: None,
			ext_stun_port: 0,
			listening_ip: vec![],
			ipv6_listening_ip: None,
			ipv6_disable: false,
			port: 0,
			http_port: 0,
			#[cfg(feature = "https")]
			https_port: 0,
			#[cfg(feature = "https")]
			https_cert: DEFAULT_HTTPS_CERT.into(),
			#[cfg(feature = "https")]
			https_key: DEFAULT_HTTPS_KEY.into(),
			bitrate_up: None,
			bitrate_down: None,
			presentation_url: None,
			notify_interval: 0,
			system_uptime: false,
			packet_log: false,
			uuid: Default::default(),
			serial: Default::default(),
			model_number: Default::default(),
			clean_ruleset_threshold: 0,
			clean_ruleset_interval: 0,
			upnp_table_name: Default::default(),
			upnp_nat_table_name: Default::default(),
			upnp_forward_chain: Default::default(),
			upnp_nat_chain: Default::default(),
			upnp_nat_postrouting_chain: Default::default(),
			upnp_nftables_family_split: false,
			enable_natpmp: false,
			enable_pcp_pmp: false,
			min_lifetime: 0,
			max_lifetime: 0,
			pcp_allow_thirdparty: Default::default(),
			enable_upnp: false,
			lease_file: Default::default(),
			lease_file6: Default::default(),
			force_igd_desc_v1: false,
			minissdpdsocket: None,
			secure_mode: false,
			quickrules: false,
			upnpperms: vec![],
			#[cfg(feature = "pcp_sadscp")]
			dscp_value: vec![],

			upnp_bootid: 0,
			runtime_flags: 0,
		}
	}
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
	#[cfg(feature = "https")]
	pub ssl_ctx: *mut SSL_CTX,
}

pub fn parselanaddr(lan_addr: &mut lan_addr_s, lan: &str, runtime_flag: u32) -> i32 {
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
	if !addr_is_reserved(&lan_addr.addr) && !GETFLAG!(runtime_flag, IGNOREPRIVATEIPMASK) {
		println!("Error: LAN address contains public IP address : {}", lan_addr.addr);
		println!("Public IP address can be configured via ext_ip= option");
		println!("LAN address should contain private address, e.g. from 192.168. block");
		println!("Listening on public IP address is a security issue");
		return -1;
	}

	0
}

fn parse_option_line(op: &mut Options, key: &str, value: &str, line: &str) -> bool {
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
		"ignore_private_ip"=> match parse_bool(value) {
			Some(true) => SETFLAG!(op.runtime_flags, IGNOREPRIVATEIPMASK),
			Some(false) => {},
			None => return false,
		},
		"ext_perform_stun" => match parse_bool(value) {
			Some(v) => {
				op.ext_perform_stun = v;
			}
			None => return false,
		},
		"ext_stun_host" => {
			op.ext_stun_host = Some(value.into());
		}
		"ext_stun_port" => {
			op.ext_stun_port = u16::from_str(&value).unwrap_or(0);
		}
		"listening_ip" => {
			let mut lan_addr = Default::default();
			if parselanaddr(&mut lan_addr, value, op.runtime_flags) >= 0 {
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
		#[cfg(feature = "https")]
		"https_port" => match u16::from_str(value) {
			Ok(v) => {
				op.https_port = v;
			}
			Err(_) => return false,
		},
		#[cfg(feature = "https")]
		"https_cert" => op.https_cert = CString::from_str(&value).unwrap(),
		#[cfg(feature = "https")]
		"https_key" => op.https_key = CString::from_str(&value).unwrap(),

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
			op.presentation_url = Some(value.into());
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
		"serial" => op.serial = value.into(),
		"model_number" => op.model_number = value.into(),
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
		"allow" | "deny" => match read_permission_line(line) {
			Ok(perm) => {
				op.upnpperms.push(perm);
			}
			Err(_) => return false,
		},
		#[cfg(feature = "pcp_sadscp")]
		"set_learn_dscp" => {
			let mut dscp_value = Default::default();
			if read_learn_dscp_line(&mut dscp_value, line) < 0 {
				op.dscp_value.push(dscp_value);
			} else {
				return false;
			}
		}
		#[cfg(fw = "nftables")]
		"upnp_table_name" => op.upnp_table_name = value.into(),
		#[cfg(fw = "nftables")]
		"upnp_nat_table_name" => op.upnp_nat_table_name = value.into(),
		#[cfg(fw = "nftables")]
		"upnp_forward_chain" => op.upnp_forward_chain = value.into(),
		#[cfg(fw = "nftables")]
		"upnp_nat_chain" => op.upnp_nat_chain = value.into(),
		#[cfg(fw = "nftables")]
		"upnp_nat_postrouting_chain" => op.upnp_nat_postrouting_chain = value.into(),
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
		"pcp_allow_thirdparty" => op.pcp_allow_thirdparty = value.into(),
		"enable_upnp" => match parse_bool(value) {
			Some(v) => op.enable_upnp = v,
			None => return false,
		},
		"lease_file" => op.lease_file = value.into(),
		"lease_file6" => op.lease_file6 = value.into(),
		#[cfg(feature = "igd2")]
		"force_igd_desc_v1" => match parse_bool(value) {
			Some(v) => op.force_igd_desc_v1 = v,
			None => return false,
		},
		"minissdpdsocket" => op.minissdpdsocket = Some(value.into()),
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

pub fn readoptionsfile(fname: &str, _debug_flag: bool) -> Result<Options, io::Error> {
	trace!("Reading configuration from file {:?}", fname);
	let mut file = File::open(fname)?;

	let mut buf = [0; 1024];
	let mut reader = StackBufferReader::new(&mut buf);

	let mut option = Options::default();

	while let Some(Ok(line_buf)) = reader.read_line(&mut file) {
		let line = match str::from_utf8(line_buf) {
			Ok(v) => v,
			Err(_) => continue,
		};
		let line_ = line.trim_start();
		if line_.is_empty() || line_.starts_with('#') {
			continue;
		}

		if let Some((key, value)) = line_.split_once(['=', ' ']) {
			if !parse_option_line(&mut option, key, value, line_) {
				error!("cannot parse option {}", line_);
			}
		}
	}

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
		assert_eq!(parselanaddr(&mut lan_addr, "127.0.0.1", 0), 0);
		assert_eq!(parselanaddr(&mut lan_addr, "127.0.0.1/8", 0), 0);
		#[cfg(target_family = "unix")]
		{
			// let lan = parselanaddr("lo").unwrap();
			assert!(parselanaddr(&mut lan_addr, "lo", 0) >= 0);
			assert_eq!(lan_addr.addr, Ipv4Addr::new(127, 0, 0, 1));
		}
	}
}
