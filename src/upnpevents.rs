use crate::log;
use crate::warp::FdSet;
use std::cell::RefCell;
use std::cmp::PartialEq;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::rc::Rc;
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{io, mem};

type SubscriberList = Vec<Rc<RefCell<subscriber>>>;

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum subscriber_service_enum {
	EWanCFG = 1,
	EWanIPC = 2,
	EL3F = 3,
	#[cfg(feature = "ipv6")]
	E6FC = 4,
	#[cfg(feature = "dp_service")]
	EDP = 5,
}
use socket2::Socket;
use subscriber_service_enum::*;

#[repr(C)]
pub struct subscriber {
	pub notify: Option<upnp_event_notify>,
	pub timeout: Instant,
	pub seq: u32,
	pub service: subscriber_service_enum,
	pub uuid: UUID,
	pub callback: Rc<str>,
}

pub struct upnp_event_notify {
	pub s: Socket,
	pub state: event_state,
	pub sub: Rc<RefCell<subscriber>>,
	pub buffer: Vec<u8>,
	// pub buffersize: i32,
	pub tosend: i32,
	pub sent: i32,
	pub path: Option<Rc<str>>,
	// pub ipv6: i32,
	pub addr: SocketAddr,
	// pub portstr: u16,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum event_state {
	ECreated = 1,
	EConnecting = 2,
	ESending = 3,
	EWaitingForResponse = 4,
	EFinished = 5,
	EError = 6,
}
use crate::debug;
use crate::miniupnpdpath::*;
use crate::upnpdescgen::*;

use crate::options::RtOptions;
use crate::uuid::UUID;
use event_state::*;

fn newSubscriber(eventurl: &str, callback: &str) -> Option<subscriber> {
	if callback.is_empty() || eventurl.is_empty() {
		return None;
	}

	let state = match eventurl {
		WANCFG_EVENTURL => EWanCFG,
		WANIPC_EVENTURL => EWanIPC,
		L3F_EVENTURL => EL3F,
		#[cfg(feature = "ipv6")]
		WANIP6FC_EVENTURL => E6FC,
		#[cfg(feature = "dp_service")]
		DP_EVENTURL => EDP,
		_ => return None,
	};

	let uuid = UUID::generate();
	Some(subscriber {
		notify: None,
		timeout: Instant::now(),
		seq: 0,
		service: state,
		uuid,
		callback: Rc::from(callback),
	})
}

pub fn upnpevents_addSubscriber<'a>(
	subscriberlist: &'a mut SubscriberList,
	eventurl: &'a str,
	callback: &'a str,
	timeout: i32,
) -> Option<UUID> {
	// let mut tmp: *mut subscriber = 0 as *mut subscriber;
	debug!("addSubscriber({}, {}, {})", eventurl, callback, timeout);
	let mut tmp = newSubscriber(eventurl, callback)?;

	if timeout != 0 {
		tmp.timeout += Duration::from_secs(timeout as u64);
	}
	let uuid = tmp.uuid;
	subscriberlist.push(Rc::from(RefCell::new(tmp)));
	Some(uuid)
}

pub fn upnpevents_renewSubscription<'a>(
	subscriberlist: &mut SubscriberList,
	sid: &'a UUID,
	timeout: i32,
) -> Option<&'a UUID> {
	if let Some(sub) = subscriberlist.iter_mut().find(|sub| sub.borrow().uuid.eq(sid)) {
		sub.borrow_mut().timeout += Duration::from_secs(timeout as u64);
		return Some(sid);
	}
	None
}

pub fn upnpevents_removeSubscriber(subscriberlist: &mut SubscriberList, sid: &UUID) -> i32 {
	if let Some(i) = subscriberlist.iter().position(|sub| sub.borrow().uuid.eq(sid)) {
		subscriberlist.swap_remove(i);
		0
	} else {
		-1
	}
}

pub fn upnp_event_var_change_notify(subscriberlist: &mut SubscriberList, service: subscriber_service_enum) {
	if let Some(sub) = subscriberlist
		.iter_mut()
		.find(|sub| sub.borrow().service == service && sub.borrow().notify.is_none())
	{
		upnp_event_create_notify(sub);
	}
}

fn upnp_event_create_notify(sub: &mut Rc<RefCell<subscriber>>) {
	let ipv6 = sub.borrow().callback.contains('[');
	let sock = if cfg!(feature = "ipv6") {
		match Socket::new(
			if ipv6 {
				socket2::Domain::IPV6
			} else {
				socket2::Domain::IPV4
			},
			socket2::Type::STREAM,
			None,
		) {
			Ok(sock) => sock,
			Err(e) => {
				error!("Failed to create socket: {}", e);
				return;
			}
		}
	} else {
		match Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None) {
			Ok(sock) => sock,
			Err(e) => {
				error!("Failed to create socket: {}", e);
				return;
			}
		}
	};
	if let Err(e) = sock.set_nonblocking(true) {
		error!("upnp_event_create_notify: set_non_blocking(): {}", e);
		return;
	}

	sub.borrow_mut().notify.replace(upnp_event_notify {
		s: sock,
		state: ECreated,
		sub: sub.clone(),
		buffer: Vec::new(),
		tosend: 0,
		sent: 0,
		path: None,
		addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into(),
	});
}

fn upnp_event_notify_connect(obj: &mut upnp_event_notify) {
	let sub = obj.sub.borrow_mut();
	let callback = sub.callback.as_str();
	if callback.len() < 7 {
		obj.state = EError;
		return;
	}

	// skip "http://"
	let p = &callback[7..];

	let parse_host = |host: &str| -> Option<SocketAddr> {
		let port = 80;
		let ipv6 = host.starts_with('[');

		if (ipv6 && host.ends_with(']')) || (!ipv6 && host.rfind(':').is_none()) {
			if let Ok(addr) = IpAddr::from_str(host) {
				Some(SocketAddr::new(addr, port))
			} else {
				None
			}
		} else if let Ok(addr) = SocketAddr::from_str(host) {
			return Some(addr);
		} else {
			return None;
		}
	};

	let (socket, path) = p
		.split_once('/')
		.map(|(host, path)| (parse_host(host), Some(path)))
		.unwrap_or_else(|| (parse_host(p), None));
	if socket.is_none() {
		obj.state = EError;
		return;
	}
	let sock = socket.unwrap();

	obj.addr = sock;
	obj.path = path.map(|p| p.into());

	debug!("upnp_event_notify_connect: '{}' '{}'", sock, path.unwrap_or_default());

	obj.state = EConnecting;
	if let Err(e) = obj.s.connect(&sock.into())
		&& e.kind() != io::ErrorKind::WouldBlock
	{
		error!(
			"upnp_event_notify_connect: connect({}, {}): {}",
			obj.s.as_raw_fd(),
			sock,
			e
		);
		obj.state = EError;
	}
}

fn upnp_event_prepare(rt: &mut RtOptions, index: usize) {
	let service = rt.notify_list[index].sub.borrow().service;
	let xml = match service {
		EWanCFG => getVarsWANCfg(rt),
		EWanIPC => getVarsWANIPCn(rt),
		// #[cfg(feature = "l3f_service")]
		EL3F => getVarsL3F(rt),
		#[cfg(feature = "ipv6")]
		E6FC => getVars6FC(rt),
		#[cfg(feature = "dp_service")]
		EDP => getVarsDP(rt),
		#[cfg(not(any(feature = "ipv6", feature = "dp_service")))]
		_ => {
			rt.notify_list[index].state = EError;
			return;
		}
	};
	let obj = &mut rt.notify_list[index];
	if xml.is_none() {
		obj.state = EError;
		return;
	}
	let xml = xml.unwrap();

	let path = obj.path.as_deref().unwrap_or("/");
	obj.buffer.reserve(1024);
	obj.buffer.clear();
	let _ = obj.buffer.write_fmt(format_args!(
		"NOTIFY {path} HTTP/1.1\r\n\
        Host: {}\r\n\
        Content-Type: text/xml; charset=\"utf-8\"\r\n\
        Content-Length: {}\r\n\
        NT: upnp:event\r\n\
        NTS: upnp:propchange\r\n\
        SID: {}\r\n\
        SEQ: {}\r\n\
        Connection: close\r\n\
        Cache-Control: no-cache\r\n\
        \r\n\
        {xml}\r\n",
		obj.addr,
		xml.len() + 2,
		obj.sub.borrow().uuid,
		obj.sub.borrow().seq,
	));

	obj.tosend = obj.buffer.len() as i32;
	obj.state = ESending;
}
fn upnp_event_send(obj: &mut upnp_event_notify) {
	debug!("upnp_event_send: sending event notify message to {}", obj.addr);
	debug!(
		"upnp_event_send: msg: {}",
		str::from_utf8(&obj.buffer[obj.sent as usize..]).unwrap()
	);

	match obj.s.send(&obj.buffer[obj.sent as usize..obj.tosend as usize]) {
		Err(e) => {
			if e.kind() != io::ErrorKind::WouldBlock && e.kind() != io::ErrorKind::Interrupted {
				error!("upnp_event_send: send({}): {}", obj.addr, e);
				obj.state = EError;
			}
			// EAGAIN/EWOULDBLOCK/EINTR: 没有数据发送
		}
		Ok(i) => {
			if i as i32 != obj.tosend - obj.sent {
				warn!("upnp_event_send: {} bytes send out of {}", i, obj.tosend - obj.sent);
			}
			obj.sent += i as i32;
			if obj.sent == obj.tosend {
				obj.state = EWaitingForResponse;
			}
		}
	}
}
fn upnp_event_recv(obj: &mut upnp_event_notify) {
	if obj.buffer.len() < 1024 {
		obj.buffer.resize(1024, 0);
	} else {
		obj.buffer.resize(obj.buffer.capacity(), 0);
	}

	match obj.s.recv(unsafe { mem::transmute(obj.buffer.as_mut_slice()) }) {
		Err(e) => {
			if e.kind() != io::ErrorKind::WouldBlock && e.kind() != io::ErrorKind::Interrupted {
				error!("upnp_event_recv: recv(): {}", e);
				obj.state = EError;
			};
		}
		Ok(n) => {
			debug!(
				"upnp_event_recv: ({} bytes) {}",
				n,
				str::from_utf8(&obj.buffer[..n]).unwrap()
			);

			// TODO: 可能需要接收更多字节
			// 目前接收的字节数n被忽略了
			unsafe { obj.buffer.set_len(n) };
			obj.state = EFinished;
			obj.sub.borrow_mut().seq += 1;
		}
	}
}
fn upnp_event_process_notify(rt: &mut RtOptions, index: usize) {
	// let mut obj= &mut rt.notify_list[index];
	let state = rt.notify_list[index].state;
	match state {
		EConnecting => {
			let sock_state = rt.notify_list[index].s.take_error();
			match sock_state {
				Err(e) => {
					error!("upnp_event_process_notify: getsockopt: {}", e);
					rt.notify_list[index].state = EError;
					return;
				}
				Ok(Some(e)) => {
					let obj = &mut rt.notify_list[index];
					error!("upnp_event_process_notify: connect({}): {}", obj.addr, e);
					obj.state = EError;
					return;
				}
				Ok(None) => {
					// 连接成功,准备发送数据
					upnp_event_prepare(rt, index);
					let obj = &mut rt.notify_list[index];
					if obj.state == ESending {
						upnp_event_send(obj);
					}
				}
			}
		}
		ESending => {
			upnp_event_send(&mut rt.notify_list[index]);
		}
		EWaitingForResponse => {
			upnp_event_recv(&mut rt.notify_list[index]);
		}
		EFinished => {
			rt.notify_list[index].s.shutdown(std::net::Shutdown::Both).ok();
		}
		_ => {
			error!("upnp_event_process_notify: unknown state");
		}
	}
}

pub fn upnpevents_selectfds(
	notifylist: &mut Vec<upnp_event_notify>,
	readset: &mut FdSet,
	writeset: &mut FdSet,
	max_fd: &mut i32,
) {
	for obj in notifylist.iter_mut() {
		let fd = obj.s.as_raw_fd();
		debug!("upnpevents_selectfds: {:p} {} {}", obj, obj.state as u32, fd);

		match obj.state {
			ECreated => {
				upnp_event_notify_connect(obj);
				if obj.state != EConnecting {
					continue;
				}
				writeset.set(fd);
				if fd > *max_fd {
					*max_fd = fd;
				}
			}
			EConnecting | ESending => {
				writeset.set(fd);
				if fd > *max_fd {
					*max_fd = fd;
				}
			}
			EWaitingForResponse => {
				readset.set(fd);
				if fd > *max_fd {
					*max_fd = fd;
				}
			}
			_ => {}
		}
	}
}

pub fn upnpevents_processfds(rt: &mut RtOptions, readset: &mut FdSet, writeset: &mut FdSet) {
	let mut i = 0;
	while i < rt.notify_list.len() {
		let fd = rt.notify_list[i].s.as_raw_fd();
		debug!(
			"upnpevents_processfds: {:p} {} {} {} {}",
			&rt.notify_list[i],
			rt.notify_list[i].state as u32,
			fd,
			readset.is_set(fd),
			writeset.is_set(fd)
		);

		if fd >= 0 && (readset.is_set(fd) || writeset.is_set(fd)) {
			upnp_event_process_notify(rt, i);
		}
		i += 1;
	}

	i = 0;
	while i < rt.notify_list.len() {
		let obj = &mut rt.notify_list[i];

		if obj.state == EError || obj.state == EFinished {
			obj.sub.borrow_mut().notify = None;

			// 如果是错误状态,同时移除subscriber
			if obj.state == EError {
				error!(
					"upnpevents_processfds: {:p}, remove subscriber {} after an ERROR cb: {}",
					obj,
					obj.sub.borrow().uuid,
					obj.sub.borrow().callback
				);
				rt.subscriber_list.retain(|s| s.borrow().uuid == obj.sub.borrow().uuid);
			}

			rt.notify_list.swap_remove(i);
			continue;
		}
		i += 1;
	}

	// 清理超时的订阅者
	let curtime = Instant::now();
	rt.subscriber_list.retain(|sub| {
		if curtime > sub.borrow().timeout && sub.borrow().notify.is_none() {
			// info!("subscriber timeouted : {} > {} SID={}", curtime, sub.borrow().timeout, sub.borrow().uuid);
			false
		} else {
			true
		}
	});
}

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
pub fn upnp_update_status(rt: &mut RtOptions) {
	use crate::getconnstatus::get_wan_connection_status_str;
	use crate::getifaddr::{addr_is_reserved, getifaddr};
	use crate::upnpglobalvars::global_option;
	use crate::upnpredirect::upnp_get_portmapping_number_of_entries;
	use systemd::*;
	let op = global_option.get().unwrap();
	let wan_ip = if let Some(ext_ip) = rt.use_ext_ip_addr.as_ref() {
		format!("{}", ext_ip)
	} else {
		let mut addr = Ipv4Addr::UNSPECIFIED;
		if getifaddr(&op.ext_ifname, &mut addr, None) < 0 {
			"(unknown)".to_string()
		} else if addr_is_reserved(&addr) {
			"invalid".to_string()
		} else {
			format!("{}", addr)
		}
	};

	unsafe {
		sd_notifyf(
			0,
			format!(
				"STATUS={} on {}, IP: {}, active redirects: {}\n\0",
				get_wan_connection_status_str(&op.ext_ifname),
				op.ext_ifname,
				wan_ip,
				upnp_get_portmapping_number_of_entries(&rt.nat_impl)
			)
			.as_ptr() as _,
		);
	}
}
