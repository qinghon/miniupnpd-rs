#![feature(random)]
#![feature(ip)]
#![feature(const_format_args)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use daemonize::checkforrunning;
use miniupnpd_rs::asyncsendto::*;
use miniupnpd_rs::getifaddr::*;
use miniupnpd_rs::log::setlogmask;
use miniupnpd_rs::minissdp::*;
use miniupnpd_rs::natpmp::*;
use miniupnpd_rs::options::*;
use miniupnpd_rs::pcpserver::*;
use miniupnpd_rs::rdr_name_type::*;
use miniupnpd_rs::upnpdescstrings::MINIUPNPD_VERSION;
use miniupnpd_rs::upnpevents::subscriber_service_enum::*;
#[cfg(use_systemd)]
use miniupnpd_rs::upnpevents::upnp_update_status;
use miniupnpd_rs::upnpevents::*;
use miniupnpd_rs::upnpglobalvars::*;
use miniupnpd_rs::upnphttp::{ESendingAndClosing, EToDelete, EWaitingForHttpContent, upnphttp};
use miniupnpd_rs::upnphttp::{MINIUPNPD_SERVER_STRING, New_upnphttp, Process_upnphttp};
use miniupnpd_rs::upnppinhole::upnp_clean_expired_pinholes;
use miniupnpd_rs::upnpredirect::{get_upnp_rules_state_list, remove_unused_rules, rule_state};
use miniupnpd_rs::upnpstun::perform_stun;
use miniupnpd_rs::upnputils::{get_lan_for_peer, upnp_gettimeofday, upnp_time};
use miniupnpd_rs::uuid::UUID;
use miniupnpd_rs::warp::{FdSet, IfName, make_timeval, select, sockaddr_to_v4};
use miniupnpd_rs::*;
use miniupnpd_rs::{Backend, OS, options};
use miniupnpd_rs::{debug, error, info, nat_impl, notice};
use socket2::Socket;
use std::cmp::max;
use std::ffi::CStr;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::{Add, Sub};
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::random::random;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicBool, AtomicI32};
use std::time::{Duration, Instant};
use std::{fs, io, mem, ptr};

#[cfg(feature = "https")]
use miniupnpd_rs::upnphttp::{InitSSL_upnphttp, init_ssl};

mod daemonize;

const SYSTEM_OS: os = os::new();

const DEF_CONF_FILE: &str = "/etc/miniupnpd/miniupnpd.conf";
const DEF_PID_FILE: &str = "/var/run/miniupnpd.pid";

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct runtime_vars {
	// pub port: u16,
	/// seconds between SSDP announces. Should be >= 900s
	pub notify_interval: i32,
	pub clean_ruleset_threshold: i32,
	pub clean_ruleset_interval: i32,
	#[cfg(use_systemd)]
	pub systemd_notify: bool,
}

static quitting: AtomicI32 = AtomicI32::new(0);

pub static should_send_public_address_change_notif: AtomicBool = AtomicBool::new(false);

#[cfg(use_systemd)]
mod systemd {
	#![allow(
		dead_code,
		non_camel_case_types,
		non_snake_case,
		non_upper_case_globals,
		unused_assignments,
		unused_mut
	)]
	include!(concat!(env!("OUT_DIR"), "/libsystemd.rs"));
}

#[cfg(use_systemd)]
fn systemd_notify(rtv: &mut runtime_vars, status: &'static str) {
	use systemd::*;
	let ret = unsafe {
		sd_notify(
			0,
			const_format_args!("STATUS=version {} {status}\n\0", MINIUPNPD_VERSION).as_str().unwrap().as_ptr()
				as *const _,
		)
	};
	if ret > 0 {
		rtv.systemd_notify = true;
	}
}
#[cfg(not(use_systemd))]
fn systemd_notify(_rtv: &mut runtime_vars, _status: &'static str) {}

#[cfg(cap_lib = "pledge")]
fn drop_privilge() -> i32 {
	use libc::{c_char, c_int};
	unsafe extern "C" {
		fn pledge(promises: *const c_char, execpromises: *const c_char) -> c_int;
	}
	unsafe {
		if pledge(c"stdio inet pf", ptr::null()) < 0 {
			error!("pledge(): %m");
			return 1;
		}
	}
	0
}

#[cfg(cap_lib = "cap")]
mod cap {
	#![allow(
		dead_code,
		non_camel_case_types,
		non_snake_case,
		non_upper_case_globals,
		unused_assignments,
		unused_mut
	)]
	include!(concat!(env!("OUT_DIR"), "/capability.rs"));
}
#[cfg(cap_lib = "cap")]
fn drop_privilege() -> i32 {
	use cap::*;
	use ffi::CStr;
	unsafe {
		let caps = cap_get_proc();
		if caps.is_null() {
			error!("cap_get_proc(): %m");
			return 0;
		}
		const cap_list: [cap_value_t; 3] = [CAP_NET_BROADCAST as _, CAP_NET_ADMIN as _, CAP_NET_RAW as _];
		let mut txt_caps = cap_to_text(caps, ptr::null_mut());
		if txt_caps.is_null() {
			error!("cap_to_text(): %m");
		} else {
			debug!("txt_caps: {}", CStr::from_ptr(txt_caps).to_str().unwrap());
			if cap_free(txt_caps as _) < 0 {
				error!("cap_free(): %m");
			}
		}
		if cap_clear(caps as _) < 0 {
			error!("cap_clear(): %m");
		}
		if cap_set_flag(caps, CAP_PERMITTED, cap_list.len() as _, cap_list.as_ptr(), CAP_SET) < 0 {
			error!("cap_set_flag(): %m");
		}
		if cap_set_flag(caps, CAP_EFFECTIVE, cap_list.len() as _, cap_list.as_ptr(), CAP_SET) < 0 {
			error!("cap_set_flag(): %m");
		}
		txt_caps = cap_to_text(caps, ptr::null_mut());
		if txt_caps.is_null() {
			error!("cap_to_text(): %m");
		} else {
			debug!("txt_caps: {}", CStr::from_ptr(txt_caps).to_str().unwrap());
			if cap_free(txt_caps as _) < 0 {
				error!("cap_free(): %m");
			}
		}
		if cap_set_proc(caps) < 0 {
			error!("cap_set_proc(): %m");
		}
		if cap_free(caps as _) < 0 {
			error!("cap_free(): %m");
		}
	}
	0
}

#[cfg(cap_lib = "cap_ng")]
mod capng {
	#![allow(
		dead_code,
		non_camel_case_types,
		non_snake_case,
		non_upper_case_globals,
		unused_assignments,
		unused_mut
	)]
	include!(concat!(env!("OUT_DIR"), "/cap-ng.rs"));
}

#[cfg(cap_lib = "cap_ng")]
fn drop_privilege() -> i32 {
	use capng::*;
	unsafe {
		capng_setpid(libc::getpid());
		capng_clear(CAPNG_SELECT_BOTH);
		if capng_updatev(
			CAPNG_ADD,
			CAPNG_EFFECTIVE | CAPNG_PERMITTED,
			CAP_NET_BROADCAST,
			CAP_NET_ADMIN,
			CAP_NET_RAW,
			-1,
		) < 0
		{
			error!("capng_updatev() failed");
		} else if capng_apply(CAPNG_SELECT_BOTH) < 0 {
			error!("capng_apply() failed");
		}
	}
	0
}
#[cfg(cap_lib = "none")]
fn drop_privilege() -> i32 {
	0
}

fn setup_signal_handle() -> i32 {
	let mut sa: libc::sigaction = unsafe { mem::zeroed() };
	sa.sa_sigaction = sigterm as usize;

	if unsafe { libc::sigaction(libc::SIGTERM, &sa, ptr::null_mut()) } < 0 {
		error!("Failed to set SIGTERM handler. EXITING");
		return 1;
	}
	if unsafe { libc::sigaction(libc::SIGINT, &sa, ptr::null_mut()) } < 0 {
		error!("Failed to set SIGINT handler. EXITING");
		return 1;
	}
	sa.sa_sigaction = libc::SIG_IGN;
	if unsafe { libc::sigaction(libc::SIGPIPE, &sa, ptr::null_mut()) } < 0 {
		return 1;
	}
	sa.sa_sigaction = sigusr1 as usize;
	if unsafe { libc::sigaction(libc::SIGUSR1, &sa, ptr::null_mut()) } < 0 {
		return 1;
	}
	0
}

fn gen_current_notify_interval(notify_interval: u32) -> u32 {
	if notify_interval > 65 {
		let rand: u8 = random();
		(notify_interval - 1) - (rand & 0x3f) as u32
	} else {
		notify_interval
	}
}
fn OpenAndConfHTTPSocket(v: &Options, port: &mut u16, ipv6: bool, runtime_flags: &mut u32) -> io::Result<Socket> {
	let socket = if ipv6 {
		match socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None) {
			Ok(s) => s,
			Err(e) => {
				if e.kind() == io::ErrorKind::Unsupported {
					warn!("socket(PF_INET6, ...) failed with EAFNOSUPPORT, disabling IPv6");
					SETFLAG!(*runtime_flags, IPV6DISABLEDMASK);
					Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?
				} else {
					return Err(e);
				}
			}
		}
	} else {
		socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?
	};

	let _ = socket.set_reuse_address(true);
	if let Err(_) = socket.set_nonblocking(true) {
		warn!("set_non_blocking(http): %m");
	}

	let listen_addr = if ipv6 {
		SocketAddrV6::new(ipv6_bind_addr, *port, 0, 0).into()
	} else {
		SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, *port).into()
	};
	socket.bind(&listen_addr)?;
	if v.listening_ip.len() == 1 && v.listening_ip[0].ifname.len() != 0 {
		let _ = socket.bind_device(Some(v.listening_ip[0].ifname.as_bytes()));
	}

	socket.listen(5)?;

	if *port == 0 {
		*port = socket.local_addr().unwrap().as_socket().unwrap().port();
	}
	Ok(socket)
}
fn ProcessIncomingHTTP<'a>(v: &Options, shttpl: &'a Socket, protocol: &str) -> io::Result<upnphttp<'a>> {
	let (shttp, clientaddr) = shttpl.accept()?;
	let mut raddr = clientaddr.as_socket().unwrap();
	match raddr.ip() {
		IpAddr::V4(_) => {}
		IpAddr::V6(v) => {
			if v.is_ipv4_mapped() {
				raddr.set_ip(IpAddr::V4(v.to_ipv4().unwrap()))
			}
		}
	}

	trace!("{} connection from {}", protocol, raddr);
	if get_lan_for_peer(v, &raddr).is_some() {
		Ok(New_upnphttp(shttp, raddr.ip()))
	} else {
		warn!("{} peer {} is not from a LAN, closing the connection", protocol, raddr);
		Err(io::Error::new(
			ErrorKind::InvalidInput,
			"peer {} is not from a LAN certificate",
		))
	}
}
#[unsafe(no_mangle)]
extern "C" fn sigterm(_sig: i32) {
	quitting.store(1, std::sync::atomic::Ordering::Release);
}
#[unsafe(no_mangle)]
extern "C" fn sigusr1(_sig: i32) {
	should_send_public_address_change_notif.store(true, Relaxed);
}
#[inline(never)]
fn set_startup_time(runtime_flag: u32) {
	let mut startup_time_ = upnp_time();

	if upnp_bootid.load(Relaxed) == 1 {
		upnp_bootid.store(startup_time_.as_secs() as u32, Relaxed);
	}
	if GETFLAG!(runtime_flag, SYSUPTIMEMASK) {
		startup_time_ -= SYSTEM_OS.uptime()
	}
	startup_time.set(startup_time_).unwrap()
}

pub fn update_ext_ip_addr_from_stun(
	v: &Options,
	rt: &mut RtOptions,
	init_0: bool,
	ext_if_name: &IfName,
	port_forward: &mut bool,
) -> i32 {
	let mut if_addr = Ipv4Addr::UNSPECIFIED;
	let ext_addr;
	let mut restrictive_nat: i32 = 0;
	if v.ext_stun_host.is_none() {
		return 0;
	}
	info!(
		"STUN: Performing with host={} and port={} ...",
		v.ext_stun_host.as_ref().unwrap().as_str(),
		v.ext_stun_port
	);
	let mut ip = Ipv4Addr::UNSPECIFIED;

	if getifaddr(ext_if_name, &mut ip, None) < 0 {
		error!("STUN: Cannot get IP address for ext interface {}", ext_if_name);
		return 1;
	}

	match perform_stun(
		&mut rt.nat_impl,
		ext_if_name,
		ip,
		v.ext_stun_host.as_ref().unwrap().as_str(),
		v.ext_stun_port,
		&mut restrictive_nat,
	) {
		Ok(addr) => {
			ext_addr = addr;
		}
		Err(e) => {
			error!("STUN: Performing STUN failed: {}", e);
			return 1;
		}
	}

	// ext_addr_str.push_str(&format!("{}", ext_addr));

	if (init_0 || *port_forward) && restrictive_nat == 0 {
		if addr_is_reserved(&mut if_addr) {
			info!(
				"STUN: ext interface {} with IP address {} is now behind unrestricted full-cone NAT 1:1 with public IP address {} and firewall does not block incoming connections set by miniupnpd",
				ext_if_name, ip, ext_addr
			);
		} else {
			info!(
				"STUN: ext interface {} has now public IP address {} and firewall does not block incoming connections set by miniupnpd",
				ext_if_name, ip,
			);
		}
		info!("Port forwarding is now enabled");
	} else if (init_0 || !*port_forward) && restrictive_nat != 0 {
		if addr_is_reserved(&if_addr) {
			warn!(
				"STUN: ext interface {} with private IP address {} is now behind restrictive or symmetric NAT with public IP address {} which does not support port forwarding",
				ext_if_name, ip, ext_addr
			);
			warn!("NAT on upstream router blocks incoming connections set by miniupnpd");
			warn!("Turn off NAT on upstream router or change it to full-cone NAT 1:1 type");
		} else {
			warn!(
				"STUN: ext interface {} has now public IP address {} but firewall filters incoming connections set by miniunnpd",
				ext_if_name, if_addr,
			);
			warn!("Check configuration of firewall on local machine and also on upstream router");
		}
		warn!("Port forwarding is now disabled");
	} else {
		info!("STUN: ... done");
	}
	rt.use_ext_ip_addr = Some(ext_addr.into());
	*port_forward = restrictive_nat != 0;
	0
}

pub fn complete_uuidvalues(v: &Options) {
	let mut wan = v.uuid;
	let _ = uuidvalue_igd.set(wan);
	wan.0[15] += 1;
	let mut wcd = wan;
	wcd.0[15] += 1;

	let _ = uuidvalue_wan.set(wan);
	let _ = uuidvalue_wcd.set(wcd);
}

fn set_os_version() {
	let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };
	if unsafe { libc::uname(&mut utsname) < 0 } {
		error!("uname(): %m");
		let _ = os_version.set("unknown".to_owned());
	} else {
		let _ = os_version.set(unsafe { CStr::from_ptr(utsname.release.as_ptr()) }.to_string_lossy().to_string());
	}
	let _ = MINIUPNPD_SERVER_STRING.set(format!(
		"{}/{} UPnP/1.1 MiniUPnPd/{}",
		env!("OS_NAME"),
		os_version.get().unwrap(),
		MINIUPNPD_VERSION
	));
	debug!("start by {}", MINIUPNPD_SERVER_STRING.get().unwrap());
}

fn print_usage(pid_file: &str, config_file: &str) {
	eprintln!(
		"Usage:
    \tminiupnpd --version
    \tminiupnpd --help
    \tminiupnpd [-f config_file] [-i ext_ifname] [-I ext_ifname6] [-4] [-o ext_ip]
    \t\t[-a listening_ip] [-p port] [-d] [-v] [-U] [-S0] [-N]
    \t\t[-u uuid] [-s serial] [-m model_number]
    \t\t[-t notify_interval] [-P pid_filename]
    \t\t[-B down up] [-w url] [-r clean_ruleset_interval]
    \t\t[-A \"permission rule\"] [-b BOOTID] [-1]
    \nNotes:
    \tThere can be one or several listening_ips.
    \tNotify interval is in seconds. Default is 900 seconds.
    \tDefault pid file is '{pid_file}'.
    \tDefault config file is '{config_file}'.
    \t-d starts miniupnpd in foreground in debug mode.
    \t-o argument is either an IPv4 address or \"STUN:host[:port]\".
    \t-4 disable IPv6
    \t-S0 disable \"secure\" mode so clients can add mappings to other ips
    \t-U causes miniupnpd to report system uptime instead of daemon uptime.
    \t-N enables NAT-PMP and PCP functionality.
    \t-B sets bitrates reported by daemon in bits per second.
    \t-w sets the presentation url. Default is http address on port 80
    \t-A use following syntax for permission rules :
    \t  (allow|deny) (external port range) ip/mask (internal port range
    \texamples :
    \t  \"allow 1024-65535 192.168.1.0/24 1024-65535
    \t  \"deny 0-65535 0.0.0.0/0 0-65535
    \t-b sets the value of BOOTID.UPNP.ORG SSDP header
    \t-1 force reporting IGDv1 in rootDesc *use with care*
    \t-v enables LOG_INFO messages, -vv LOG_DEBUG as well (default with -d)
    \t-h / --help prints this help and quits.
    "
	);
}

fn init(
	v: &mut Option<Options>,
	rt: &mut RtOptions,
	rtv: &mut runtime_vars,
	runtime_flags: &mut u32,
	pidfilename: &mut String,
) -> i32 {
	let mut debug_flag = false;
	let mut verbosity_level: i32 = 0;
	let mut openlog_option;
	let mut systemd_flag = false;

	let mut optionsfile = DEF_CONF_FILE;

	let args = std::env::args().collect::<Vec<String>>();
	for i in 1..args.len() {
		if !args[i].starts_with('-') {
			continue;
		}
		match args[i].as_str() {
			"-h" | "--help" => print_usage(pidfilename.as_str(), optionsfile),
			"-d" => debug_flag = true,
			"-D" => systemd_flag = true,
			"-f" => {
				optionsfile = args[i + 1].as_str();
			}
			"--version" | "version" => {
				println!(
					"miniupnpd version {} using {} backend ",
					env!("CARGO_PKG_VERSION"),
					env!("FW")
				);
				println!("build options: {}", env!("FEATURES"));
			}
			_ => {}
		}
	}

	openlog_option = libc::LOG_PID | libc::LOG_CONS;
	if debug_flag {
		openlog_option |= libc::LOG_PERROR;
	}
	log::openlog(c"miniupnpd", openlog_option, log::LOG_DAEMON);

	*runtime_flags |= ENABLEUPNPMASK | SECUREMODEMASK;

	let ret = options::readoptionsfile(&PathBuf::from(optionsfile), debug_flag);
	let mut option = match ret {
		Ok(o) => o,
		Err(_) => {
			error!("Error reading configuration file {}", optionsfile);
			return -1;
		}
	};
	if option.notify_interval == 0 {
		option.notify_interval = 900;
	}
	if option.clean_ruleset_interval == 0 {
		option.clean_ruleset_threshold = 20;
	}

	#[cfg(feature = "pcp")]
	if option.min_lifetime > option.max_lifetime {
		error!(
			"Minimum lifetime {} is greater than or equal to maximum lifetime {}. ",
			option.min_lifetime, option.max_lifetime
		);
		print_usage(pidfilename.as_str(), optionsfile);
		return -1;
	}

	let mut uuid_seted = false;
	let mut idx = 1usize;
	for i in 1..args.len() {
		if i != idx {
			continue;
		}
		if !args[i].starts_with('-') || args[i].len() <= 1 {
			idx += 1;
			continue;
		}
		match args[idx].as_bytes()[1] {
			b'v' => verbosity_level = args[idx][1..].len() as i32,
			b'4' => option.ipv6_disable = true,
			b'1' => option.force_igd_desc_v1 = true,
			b'b' => {
				match i32::from_str(&args[idx + 1]) {
					Ok(bootid) => {
						option.upnp_bootid = bootid as u32;
						// option.upnp_bootid = upnp_bootid.load(Relaxed);
						upnp_bootid.store(bootid as u32, Relaxed);
					}
					Err(_) => {
						print_usage(pidfilename.as_str(), optionsfile);
						return -1;
					}
				}
				idx += 1;
			}
			b'o' => {
				let s = args[idx + 1].as_str();
				if s.starts_with("STUN:") {
					match s.splitn(2, ':').collect::<Vec<&str>>().as_slice() {
						[_, host, port] => {
							option.ext_stun_host = Some(host.to_string());
							option.ext_stun_port = match u16::from_str(&port) {
								Ok(v) => v,
								Err(_) => {
									print_usage(pidfilename.as_str(), optionsfile);
									return -1;
								}
							}
						}
						[_, host] => {
							option.ext_stun_host = Some(host.to_string());
						}
						_ => {}
					}
				} else {
					let ip = Ipv4Addr::from_str(&args[idx + 1]).unwrap();
					if addr_is_reserved(&ip) {
						print_usage(pidfilename.as_str(), optionsfile);
						return -1;
					}
					rt.use_ext_ip_addr.replace(ip.into());
				}
				idx += 1;
			}
			b't' => {
				option.notify_interval = match u32::from_str(&args[idx + 1]) {
					Ok(v) => v,
					Err(_) => {
						print_usage(pidfilename.as_str(), optionsfile);
						return -1;
					}
				};
				idx += 1;
			}
			b'r' => {
				option.clean_ruleset_interval = match u32::from_str(&args[idx + 1]) {
					Ok(v) => v,
					Err(_) => {
						print_usage(pidfilename.as_str(), optionsfile);
						return -1;
					}
				};
				idx += 1;
			}
			b'u' => {
				option.uuid = match UUID::from_str(&args[idx + 1][5..]) {
					Ok(v) => v,
					Err(e) => {
						error!("Error parsing UUID: {}", e);
						print_usage(pidfilename.as_str(), optionsfile);
						return -1;
					}
				};
				complete_uuidvalues(&option);
				uuid_seted = true;
				idx += 1;
			}
			b's' => {
				option.serial = args[idx + 1].to_string();
				idx += 1;
			}
			b'm' => {
				option.model_number = args[idx + 1].to_string();
				idx += 1;
			}
			b'N' => {
				option.enable_natpmp = true;
			}
			b'U' => {
				option.system_uptime = true;
			}
			b'S' => {
				if args[idx].len() > 2 {
					print_usage(pidfilename.as_str(), optionsfile);
					return -1;
				}
				option.secure_mode = false;
			}
			b'i' => {
				let ifname = match IfName::from_str(args[idx + 1].as_str()) {
					Ok(v) => v,
					Err(e) => {
						eprintln!("cannot parse ifname {}", e);
						return -1;
					}
				};
				option.listening_ip.push(lan_addr_s { ifname: ifname, ..Default::default() });
				idx += 1;
			}
			#[cfg(feature = "ipv6")]
			b'I' => {
				option.ext_ifname6 = match IfName::from_str(args[idx + 1].as_str()) {
					Ok(v) => v,
					Err(e) => {
						error!("Error parsing ifname: {}", e);
						print_usage(pidfilename.as_str(), optionsfile);
						return -1;
					}
				};
				idx += 1;
			}
			b'p' => {
				option.http_port = u16::from_str(&args[idx + 1]).unwrap();
				idx += 1;
			}
			#[cfg(feature = "https")]
			b'H' => {
				option.https_port = u16::from_str(&args[idx + 1]).unwrap();
			}

			#[cfg(feature = "nfqueue")]
			b'Q' => {}
			#[cfg(feature = "nfqueue")]
			b'n' => {}
			b'P' => {
				pidfilename.clear();
				pidfilename.push_str(&args[idx + 1]);
				idx += 1;
			}
			b'd' => {}
			b'w' => {
				option.presentation_url = Some(args[idx + 1].to_string());
				idx += 1;
			}
			b'B' => {
				let up = usize::from_str(&args[idx + 1]).unwrap();
				let down = usize::from_str(&args[idx + 2]).unwrap();
				option.bitrate_up = Some(up);
				option.bitrate_down = Some(down);
				idx += 2;
			}
			b'a' => {
				option.listening_ip = vec![];
				let mut lan_addr = lan_addr_s::default();
				if parselanaddr(&mut lan_addr, args[idx + 1].as_str()) < 0 {
					print_usage(pidfilename.as_str(), optionsfile);
					return -1;
				}
				idx += 1;
			}
			b'A' => {
				let p = match options::read_permission_line(args[idx + 1].as_str()) {
					Ok(p) => p,
					Err(_) => {
						print_usage(pidfilename.as_str(), optionsfile);
						return -1;
					}
				};
				option.upnpperms.push(p);
				idx += 1;
			}
			b'f' => {}
			_ => {}
		}
		idx += 1;
	}
	if !uuid_seted {
		complete_uuidvalues(&option);
	}

	if option.ext_perform_stun {
		SETFLAG!(*runtime_flags, PERFORMSTUNMASK);
	}

	if !option.upnp_table_name.is_empty() {
		rt.nat_impl.set_rdr_name(RDR_TABLE_NAME, &option.upnp_table_name);
	}
	if !option.upnp_nat_table_name.is_empty() {
		rt.nat_impl.set_rdr_name(RDR_NAT_TABLE_NAME, &option.upnp_nat_table_name);
	}
	if !option.upnp_forward_chain.is_empty() {
		rt.nat_impl.set_rdr_name(RDR_FORWARD_CHAIN_NAME, &option.upnp_forward_chain);
	}
	if !option.upnp_nat_chain.is_empty() {
		rt.nat_impl.set_rdr_name(RDR_NAT_PREROUTING_CHAIN_NAME, &option.upnp_nat_chain);
	}
	if !option.upnp_nat_postrouting_chain.is_empty() {
		rt.nat_impl.set_rdr_name(RDR_NAT_POSTROUTING_CHAIN_NAME, &option.upnp_nat_postrouting_chain);
	}
	if option.upnp_nftables_family_split {
		rt.nat_impl.set_rdr_name(RDR_FAMILY_SPLIT, "yes");
	}
	if option.enable_natpmp {
		SETFLAG!(*runtime_flags, ENABLENATPMPMASK);
	}
	if option.system_uptime {
		SETFLAG!(*runtime_flags, SYSUPTIMEMASK);
	}
	if option.ext_ip.is_some() && rt.use_ext_ip_addr.is_none() {
		rt.use_ext_ip_addr = option.ext_ip.map(|x| x.into());
	}
	let _ = serialnumber.set(option.serial.clone());
	let _ = modelnumber.set(option.model_number.clone());
	let _ = if let Some(persurl) = &option.presentation_url {
		presentationurl.set(persurl.to_string())
	} else {
		presentationurl.set(format!("http://{}/", option.listening_ip[0].addr))
	};

	if option.ext_ifname.is_empty() || option.listening_ip.is_empty() {
		if option.ext_ifname.is_empty() {
			error!("Error: Option -i missing and ext_ifname is not set in config file");
		}
		if option.listening_ip.is_empty() {
			error!("Error: Option -a missing and listening_ip is not set in config file");
		}
		print_usage(pidfilename.as_str(), optionsfile);
		return -1i32;
	}
	#[cfg(feature = "ipv6")]
	if option.ext_ifname6.is_empty() {
		option.ext_ifname6 = option.ext_ifname;
	}
	if rt.use_ext_ip_addr.is_some() && option.ext_perform_stun {
		error!("Error: options ext_ip= and ext_perform_stun=yes cannot be specified together");
		return -1;
	}
	let pid = if debug_flag || systemd_flag {
		unsafe { libc::getpid() }
	} else {
		if unsafe { libc::daemon(0, 0) } < 0 {
			error!("daemon(): %m");
		}
		unsafe { libc::getpid() }
	};

	if debug_flag {
		match verbosity_level {
			0 => {
				setlogmask((1u32 << (log::LOG_NOTICE + 1)) - 1);
			}
			1 => {
				setlogmask((1u32 << (log::LOG_INFO + 1)) - 1);
			}
			2.. => {
				setlogmask((1u32 << (log::LOG_DEBUG + 1)) - 1);
			}
			_ => {}
		}
	}
	if checkforrunning(pidfilename.as_str()) < 0 {
		error!("MiniUPnPd is already running. EXITING");
		return 1;
	}
	set_startup_time(*runtime_flags);

	if setup_signal_handle() != 0 {
		return 1;
	}
	if rt.nat_impl.init_redirect() < 0 {
		error!("Failed to init redirection engine. EXITING");
		return 1;
	}

	rt.nat_impl.init_iptpinhole();

	let _ = daemonize::writepidfile(pidfilename.as_str(), pid);

	if systemd_flag {
		systemd_notify(rtv, "starting");
	}

	info!("Reloading rules from lease file");
	let _ = upnpredirect::reload_from_lease_file(rt, &option.lease_file);
	let _ = upnppinhole::reload_from_lease_file6(&mut rt.nat_impl, &option.lease_file6);
	trace!("load option {:?}", option);
	v.replace(option);
	0
}
fn main() {
	let mut i: i32 = 0;
	let mut shttpl: Option<Socket> = None;
	#[cfg(feature = "https")]
	let mut shttpsl: Option<Socket> = None;
	let mut sudp: Option<Rc<Socket>> = None;
	let mut sudpv6: Option<Rc<Socket>> = None;
	let mut snatpmp: Vec<Rc<Socket>> = vec![];
	let mut spcp_v6: Option<Rc<Socket>> = None;
	let mut sifacewatcher: Option<RawFd> = None;
	let mut snotify: Vec<Rc<Socket>> = vec![];
	let mut upnphttphead: Vec<upnphttp> = Vec::new();

	let mut readset = FdSet::default();
	let mut writeset = FdSet::default();
	let start_instant = Instant::now();
	let mut timeout;

	let mut lasttimeofday = Instant::now();
	let mut current_notify_interval;
	let mut max_fd: i32 = -1;

	let mut rule_list: Vec<rule_state> = Vec::new();
	let mut checktime: Instant = Instant::now();

	let mut next_pinhole_ts;
	let mut op = None;
	// let mut use_ext_ip_addr = None;
	let mut runtime_flags = 0u32;
	let mut disable_port_forwarding = false;
	let mut send_list = Vec::new();
	let fw_impl: nat_impl = nat_impl::init();
	let mut senderaddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
	let mut pidfilename = DEF_PID_FILE.to_string();
	let mut rtv = runtime_vars::default();
	let mut rt_options = RtOptions {
		use_ext_ip_addr: None,
		disable_port_forwarding,
		epoch_origin: Default::default(),
		nat_impl: fw_impl,
		nextruletoclean_timestamp: Instant::now(),
		subscriber_list: vec![],
		notify_list: vec![],
		os,
		#[cfg(feature = "https")]
		ssl_ctx: ptr::null_mut(),
	};
	if init(&mut op, &mut rt_options, &mut rtv, &mut runtime_flags, &mut pidfilename) != 0 {
		eprintln!("Failed to initialize miniupnpd.");
		return;
	}
	let mut rt = &mut rt_options;
	let mut v = op.unwrap();

	#[cfg(feature = "https")]
	if init_ssl(&mut v, rt) < 0 {
		return;
	}

	current_notify_interval = gen_current_notify_interval(v.notify_interval);

	info!(
		"version {} starting {} {} ext if {} BOOTID={}",
		env!("CARGO_PKG_VERSION"),
		if GETFLAG!(runtime_flags, ENABLENATPMPMASK) {
			"NAT-PMP/PCP"
		} else {
			" "
		},
		if GETFLAG!(runtime_flags, ENABLEUPNPMASK) {
			"UPnP-IGD "
		} else {
			""
		},
		v.ext_ifname,
		upnp_bootid.load(Relaxed),
	);
	if v.ext_ifname == v.ext_ifname6 {
		info!("specific IPv6 ext if {}", v.ext_ifname);
	}

	if GETFLAG!(runtime_flags, PERFORMSTUNMASK) {
		if update_ext_ip_addr_from_stun(&v, rt, true, &v.ext_ifname, &mut disable_port_forwarding) != 0 {
			error!("Performing STUN failed. EXITING");
			return;
		}
	} else if rt.use_ext_ip_addr.is_none() {
		// let mut if_addr: [libc::c_char; 16] = [0; 16];
		// let mut addr: in_addr = in_addr { s_addr: 0 };
		let mut addr = Ipv4Addr::UNSPECIFIED;
		let ext_if_name = &v.ext_ifname;

		if getifaddr(ext_if_name, &mut addr, None) < 0 {
			error!(
				"Cannot get IP address for ext interface {}. Network is down",
				ext_if_name
			);
			disable_port_forwarding = true;
		} else if addr_is_reserved(&addr) {
			info!(
				"Reserved / private IP address {} on ext interface {}: Port forwarding is impossible",
				addr, ext_if_name,
			);
			info!("You are probably behind NAT, enable option ext_perform_stun=yes to detect public IP address");
			info!("Or use ext_ip= / -o option to declare public IP address");
			info!("Public IP address is required by UPnP/PCP/PMP protocols and clients do not work without it");
			disable_port_forwarding = true;
		}
	}

	set_os_version();

	if GETFLAG!(runtime_flags, ENABLEUPNPMASK) {
		let mut listen_port: u16;
		listen_port = if v.port > 0 { v.port } else { 0 };
		shttpl = match OpenAndConfHTTPSocket(
			&v,
			&mut listen_port,
			!GETFLAG!(runtime_flags, IPV6DISABLEDMASK),
			&mut runtime_flags,
		) {
			Ok(s) => Some(s),
			Err(e) => {
				error!("Failed to open socket for HTTP. EXITING:{}", e);
				return;
			}
		};

		#[cfg(feature = "https")]
		{
			listen_port = if v.https_port > 0 { v.https_port } else { 0 };
			shttpsl = match OpenAndConfHTTPSocket(
				&v,
				&mut listen_port,
				!GETFLAG!(runtime_flags, IPV6DISABLEDMASK),
				&mut runtime_flags,
			) {
				Ok(s) => Some(s),
				Err(e) => {
					error!("Failed to open socket for HTTPS. EXITING:{}", e);
					return;
				}
			};
			notice!("HTTPS listening on port {}", v.https_port);
		}

		v.port = listen_port;
		notice!("HTTP listening on port {} ", v.port);
		#[cfg(feature = "ipv6")]
		if !GETFLAG!(runtime_flags, IPV6DISABLEDMASK) {
			match miniupnpd_rs::getifaddr::find_ipv6_addr(&v.listening_ip[0].ifname) {
				Some(addr) => {
					notice!("HTTP IPv6 address given to control points : {}", addr);
					let _ = ipv6_addr_for_http_with_brackets.set(addr);
				}
				None => {
					let _ = ipv6_addr_for_http_with_brackets.set(Ipv6Addr::LOCALHOST);
					warn!("no HTTP IPv6 address, disabling IPv6");
					SETFLAG!(runtime_flags, IPV6DISABLEDMASK);
				}
			}
		}
		sudp = match OpenAndConfSSDPReceiveSocket(&v, false) {
			Ok(s) => Some(Rc::new(s)),
			Err(e) => {
				notice!(
					"Failed to open socket for receiving SSDP. Trying to use MiniSSDPd: {}",
					e
				);
				if let Err(e) = SubmitServicesToMiniSSDPD(&v, v.listening_ip[0].addr, v.port) {
					error!("Failed to connect to MiniSSDPd. EXITING: {}", e);
					return;
				}
				None
			}
		};

		if !GETFLAG!(runtime_flags, IPV6DISABLEDMASK) {
			match OpenAndConfSSDPReceiveSocket(&v, true) {
				Ok(s) => sudpv6 = Some(Rc::new(s)),
				Err(_) => {
					warn!("Failed to open socket for receiving SSDP (IP v6).");
				}
			}
		}
		match OpenAndConfSSDPNotifySockets(&v, runtime_flags) {
			Ok(s) => snotify = s.into_iter().map(|x| Rc::new(x)).collect::<Vec<_>>(),
			Err(_) => {
				error!("Failed to open sockets for sending SSDP notify messages. EXITING");
				return;
			}
		}
		if sudp.is_some() {
			sifacewatcher = SYSTEM_OS.OpenAndConfInterfaceWatchSocket();
			if sifacewatcher.is_none() {
				error!("Failed to open socket for receiving network interface notifications");
			}
		}
	}
	if GETFLAG!(runtime_flags, ENABLENATPMPMASK) {
		match OpenAndConfNATPMPSockets(&v) {
			Err(e) => error!("Failed to open sockets for NAT-PMP/PCP.: {}", e),
			Ok(socks) => {
				notice!("Listening for NAT-PMP/PCP traffic on port {} ", NATPMP_PORT);
				snatpmp = socks.into_iter().map(|x| Rc::new(x)).collect::<Vec<_>>();
			}
		}
	}
	#[cfg(feature = "ipv6")]
	if GETFLAG!(runtime_flags, IPV6DISABLEDMASK) {
		spcp_v6 = OpenAndConfPCPv6Socket(&v).ok().map(|x| Rc::new(x));
	}
	v.runtime_flag = runtime_flags;
	let _ = global_option.set(v);

	if GETFLAG!(runtime_flags, ENABLENATPMPMASK) {
		PCPSendUnsolicitedAnnounce(rt, send_list.as_mut(), snatpmp.as_ref(), spcp_v6.as_ref());
	}

	if drop_privilege() != 0 {
		return;
	}
	#[cfg(use_systemd)]
	if rtv.systemd_notify {
		upnp_update_status(rt);
		systemd_notify(&mut rtv, "READY=1");
	}

	while quitting.load(Relaxed) == 0 {
		if upnp_bootid.load(Relaxed) < (60 * 60 * 24) && upnp_time() > Duration::from_secs(24 * 60 * 60) {
			upnp_bootid.store(upnp_time().as_secs() as u32, Relaxed);
		}
		if should_send_public_address_change_notif.load(Relaxed) {
			info!("should send external iface address change notification(s)");
			if GETFLAG!(runtime_flags, PERFORMSTUNMASK) {
				let op = global_option.get().unwrap();
				if update_ext_ip_addr_from_stun(op, rt, false, &op.ext_ifname, &mut disable_port_forwarding) != 0 {
					disable_port_forwarding = true;
				}
			} else if rt.use_ext_ip_addr.is_none() {
				let op = global_option.get().unwrap();
				let ext_if_name = &op.ext_ifname;
				let mut if_addr = Ipv4Addr::UNSPECIFIED;

				if getifaddr(ext_if_name, &mut if_addr, None) < 0 {
					warn!(
						"Cannot get IP address for ext interface {}. Network is down",
						ext_if_name
					);
					disable_port_forwarding = true;
				} else {
					let reserved = addr_is_reserved(&if_addr);
					if !disable_port_forwarding && reserved {
						info!(
							"Reserved / private IP address {} on ext interface {}: Port forwarding is impossible",
							if_addr, ext_if_name
						);
						info!(
							"You are probably behind NAT, enable option ext_perform_stun=yes to detect public IP address"
						);
						info!("Or use ext_ip= / -o option to declare public IP address");
						info!(
							"Public IP address is required by UPnP/PCP/PMP protocols and clients do not work without it"
						);
						disable_port_forwarding = true;
					} else if disable_port_forwarding && !reserved {
						info!(
							"Public IP address {} on ext interface {}: Port forwarding is enabled",
							if_addr, ext_if_name
						);
						disable_port_forwarding = false;
					}
				}
			}
			if GETFLAG!(runtime_flags, ENABLENATPMPMASK) {
				SendNATPMPPublicAddressChangeNotification(&mut send_list, rt, snatpmp.as_ref());
			}
			if GETFLAG!(runtime_flags, ENABLEUPNPMASK) {
				upnp_event_var_change_notify(&mut rt.subscriber_list, EWanIPC);
			}
			if GETFLAG!(runtime_flags, ENABLENATPMPMASK) {
				PCPPublicAddressChanged(rt, &mut send_list, snatpmp.as_ref(), spcp_v6.as_ref());
			}
			should_send_public_address_change_notif.store(false, std::sync::atomic::Ordering::Release);
		}
		let timeofday = upnp_gettimeofday();

		if timeofday >= lasttimeofday + Duration::from_secs(current_notify_interval as _) {
			let op = global_option.get().unwrap();
			if GETFLAG!(runtime_flags, ENABLEUPNPMASK) {
				SendSSDPNotifies2(&mut send_list, &snotify, op.port, op.notify_interval << 1);
			}
			current_notify_interval = gen_current_notify_interval(op.notify_interval);
			lasttimeofday = timeofday;
			timeout = Duration::from_secs(current_notify_interval as u64);
		} else {
			timeout = lasttimeofday + Duration::from_secs(current_notify_interval as _) - timeofday;
		}
		let op = global_option.get().unwrap();
		if op.clean_ruleset_interval != 0
			&& timeofday - checktime >= Duration::from_secs(op.clean_ruleset_interval as u64)
		{
			if !rule_list.is_empty() {
				remove_unused_rules(rt, &mut rule_list);
				rule_list.clear();
			} else {
				if let Some(l) = get_upnp_rules_state_list(rt, op.clean_ruleset_threshold as i32) {
					rule_list = l;
				}
			}
			checktime = timeofday;
		}
		if timeofday > rt.nextruletoclean_timestamp {
			debug!("cleaning expired Port Mappings");
			get_upnp_rules_state_list(rt, 0);
		}
		if timeout >= rt.nextruletoclean_timestamp - timeofday {
			timeout = rt.nextruletoclean_timestamp - timeofday;
			debug!("setting timeout to {} sec", timeout.as_secs());
		}
		next_pinhole_ts = Instant::now();
		let mut next_pinhole_times = 0;

		upnp_clean_expired_pinholes(&mut rt.nat_impl, &mut next_pinhole_times);

		let cur_time_dur = upnp_time().as_secs();
		if next_pinhole_times > cur_time_dur as u32 {
			next_pinhole_ts = next_pinhole_ts.add(Duration::from_secs(next_pinhole_times as u64 - cur_time_dur));
		} else {
			next_pinhole_ts = next_pinhole_ts.sub(Duration::from_secs(cur_time_dur - next_pinhole_times as u64));
		}

		if next_pinhole_times != 0 && timeout >= next_pinhole_ts - timeofday {
			timeout = next_pinhole_ts - timeofday;
		}

		readset.clean_up();
		writeset.clean_up();

		if let Some(sudpd) = &sudp {
			readset.set(sudpd.as_raw_fd());

			max_fd = max(max_fd, sudpd.as_raw_fd());
			if let Some(ifw) = &sifacewatcher {
				readset.set(ifw.as_raw_fd());
				max_fd = max(max_fd, ifw.as_raw_fd());
			}
		}
		if let Some(shttpld) = &shttpl {
			readset.set(shttpld.as_raw_fd());
			max_fd = max(max_fd, shttpld.as_raw_fd());
		}
		#[cfg(feature = "https")]
		if let Some(shttpsld) = &shttpsl {
			readset.set(shttpsld.as_raw_fd());
			max_fd = max(max_fd, shttpsld.as_raw_fd());
		}

		if let Some(sudpv6d) = sudpv6.as_ref() {
			readset.set(sudpv6d.as_raw_fd());
			max_fd = max(max_fd, sudpv6d.as_raw_fd());
		}

		for e in upnphttphead.iter() {
			if e.state <= EWaitingForHttpContent {
				readset.set(e.socket.as_raw_fd());
			} else if e.state == ESendingAndClosing {
				writeset.set(e.socket.as_raw_fd());
			} else {
				continue;
			}
			max_fd = max(max_fd, e.socket.as_raw_fd());
			i += 1;
		}
		if i > 1 {
			trace!("{} active incoming HTTP connections", i);
		}

		for snatpmpd in &snatpmp {
			readset.set(snatpmpd.as_raw_fd());
			max_fd = max(max_fd, snatpmpd.as_raw_fd());
		}
		if let Some(spcpv6d) = spcp_v6.as_ref() {
			readset.set(spcpv6d.as_raw_fd());
			max_fd = max(max_fd, spcpv6d.as_raw_fd());
		}
		upnpevents_selectfds(&mut rt.notify_list, &mut readset, &mut writeset, &mut max_fd);
		let mut next_send = start_instant;
		i = get_next_scheduled_send(&mut send_list, &mut next_send);
		if i > 0 {
			trace!("{} queued sendto", i);
			i = get_sendto_fds(&mut send_list, &mut writeset, &mut max_fd, timeofday);
			if timeofday > next_send {
				if i > 0 {
					timeout = Duration::new(0, 0);
				}
			} else {
				let tmp_timeout = next_send - timeofday;
				if timeout > tmp_timeout {
					timeout = tmp_timeout;
				}
			}
		}
		let mut select_timeout = make_timeval(timeout);

		if let Err(e) = select(
			max_fd as isize + 1,
			Some(&mut readset),
			Some(&mut writeset),
			None,
			Some(&mut select_timeout),
		) {
			if quitting.load(Relaxed) != 0 {
				break;
			}
			if e.kind() == ErrorKind::Interrupted {
				continue;
			}
			error!("select(all): {}", e);
			error!("Failed to select open sockets. EXITING");
			return;
		} else {
			i = try_sendto(&mut send_list, &mut writeset);
			if i < 0 {
				error!("try_sendto failed to send {} packets", -i);
			}
			upnpevents_processfds(rt, &mut readset, &mut writeset);
			i = 0;
			for snatpmps in snatpmp.iter() {
				if !readset.is_set(snatpmps.as_raw_fd()) {
					continue;
				}
				let mut msg_buff: [u8; 1100] = [0; 1100];

				if let Ok(n) = ReceiveNATPMPOrPCPPacket(snatpmps, &mut senderaddr, None, &mut msg_buff) {
					if n == 0 {
						continue;
					}
					#[cfg(feature = "pcp")]
					if msg_buff[0] == 0 {
						let lan_addr = get_lan_for_peer(op, &senderaddr);
						if lan_addr.is_none() {
							warn!("NAT-PMP packet sender {} not from a LAN, ignoring", senderaddr);
						} else {
							ProcessIncomingNATPMPPacket(
								op,
								rt,
								&mut send_list,
								snatpmps,
								&msg_buff,
								sockaddr_to_v4(senderaddr),
							);
						}
					} else {
						ProcessIncomingPCPPacket(rt, snatpmps, &mut msg_buff[..n], &senderaddr, None);
					}
					#[cfg(not(feature = "pcp"))]
					{
						let lan_addr = get_lan_for_peer(op, &senderaddr);
						if lan_addr.is_none() {
							warn!("NAT-PMP packet sender {} not from a LAN, ignoring", senderaddr);
							continue;
						}
						ProcessIncomingNATPMPPacket(
							op,
							rt,
							&mut send_list,
							snatpmps,
							&msg_buff[..n],
							sockaddr_to_v4(senderaddr),
						);
					}
				}
			}

			#[cfg(all(feature = "pcp", feature = "ipv6"))]
			if let Some(spcp6d) = &spcp_v6 {
				if readset.is_set(spcp6d.as_raw_fd()) {
					let mut msg_buff_0: [u8; 1100] = [0; 1100];

					let mut receiveraddr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
					if let Ok(_) =
						ReceiveNATPMPOrPCPPacket(spcp6d, &mut senderaddr, Some(&mut receiveraddr), &mut msg_buff_0)
					{
						ProcessIncomingPCPPacket(rt, spcp6d, &mut msg_buff_0, &senderaddr, Some(&receiveraddr));
					}
				}
			}
			if let Some(sudpd) = &sudp {
				if readset.is_set(sudpd.as_raw_fd()) {
					let op = global_option.get().unwrap();
					ProcessSSDPRequest(&mut send_list, sudpd, op.port);
				}
			}
			if let Some(sudp6d) = &sudpv6 {
				if readset.is_set(sudp6d.as_raw_fd()) {
					info!("Received UDP Packet (IPv6)");
					let op = global_option.get().unwrap();
					ProcessSSDPRequest(&mut send_list, sudp6d, op.port);
				}
			}
			if let Some(ifw) = &sifacewatcher {
				if readset.is_set(ifw.as_raw_fd()) {
					let mut need_change = false;
					os.ProcessInterfaceWatchNotify(&op.ext_ifname, *ifw, &mut need_change);
				}
			}

			for h in upnphttphead.iter_mut() {
				if readset.is_set(h.socket.as_raw_fd()) || writeset.is_set(h.socket.as_raw_fd()) {
					{
						h.rt_options = Some(rt);
						Process_upnphttp(h);

						rt = h.rt_options.take().unwrap();
					}
				}
			}
			if let Some(shttpld) = &shttpl {
				if readset.is_set(shttpld.as_raw_fd()) {
					let tmp = ProcessIncomingHTTP(op, shttpld, "HTTP");
					if let Ok(h) = tmp {
						upnphttphead.push(h);
					}
				}
			}
			#[cfg(feature = "https")]
			if let Some(shttpsld) = &shttpsl {
				if readset.is_set(shttpsld.as_raw_fd()) {
					let tmp = ProcessIncomingHTTP(op, shttpsld, "HTTPS");
					if let Ok(mut h) = tmp {
						if InitSSL_upnphttp(&mut h, rt) == 0 {
							upnphttphead.push(h);
						}
					}
				}
			}

			upnphttphead.retain(|x| x.state != EToDelete);

			#[cfg(use_systemd)]
			{
				if rtv.systemd_notify {
					upnp_update_status(rt);
				}
			}
		}
	}
	notice!("shutting down MiniUPnPd");

	#[cfg(use_systemd)]
	{
		if rtv.systemd_notify {
			systemd_notify(&mut rtv, "shutting down\nSTOPPING=1");
		}
	}

	if GETFLAG!(runtime_flags, ENABLEUPNPMASK) {
		if let Err(e) = SendSSDPGoodbye(&mut send_list, snotify.as_slice()) {
			error!("Failed to broadcast good-bye notifications: {}", e);
		}
	}
	finalize_sendto(&mut send_list);
	drop(upnphttphead);

	if GETFLAG!(runtime_flags, ENABLEUPNPMASK) {}
	if !pidfilename.is_empty() {
		if let Err(e) = fs::remove_file(pidfilename.as_str()) {
			error!("Failed to remove pidfile {}: {}", pidfilename, e);
		}
	}

	rt_options.nat_impl.shutdown_redirect();

	unsafe { libc::closelog() };
}
