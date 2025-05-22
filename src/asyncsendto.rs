use crate::log;
use crate::warp::{FdSet, make_timeval, select};
use crate::{error, warn};
use libc::{c_int, c_uint};
use socket2::Socket;
use std::io;
use std::io::ErrorKind;
use std::net::{SocketAddr, SocketAddrV6};
use std::ops::Add;
use std::os::fd::AsRawFd;
use std::rc::Rc;
use std::time::{Duration, Instant};

#[derive(Eq, PartialEq)]
pub enum send_state {
	EINIT = 0,
	ESCHEDULED = 1,
	EWAITREADY = 2,
	ESENDNOW = 3,
}

pub struct scheduled_send {
	pub state: send_state,
	pub ts: Instant,
	pub socket: Rc<Socket>,
	pub flags: i32,
	pub dest_addr: SocketAddr,
	pub src_addr: Option<SocketAddrV6>,
	pub buf: Vec<u8>,
}

pub fn send_from_to(
	socket: &Socket,
	buf: &[u8],
	flags: i32,
	src_addr: Option<&SocketAddrV6>,
	dest_addr: &SocketAddr,
) -> io::Result<usize> {
	if let Some(addr) = src_addr {
		let iovs = [io::IoSlice::new(buf)];
		let daddr = socket2::SockAddr::from(*dest_addr);
		let mut c = [0u8; unsafe { libc::CMSG_SPACE(size_of::<libc::in6_pktinfo>() as c_uint) } as usize];

		unsafe {
			let cmsg_ptr = c.as_mut_ptr() as *mut libc::cmsghdr;
			let ipi6 = (cmsg_ptr.add(1) as *mut libc::in6_pktinfo).as_mut().unwrap();
			let cmsg = cmsg_ptr.as_mut().unwrap();
			cmsg.cmsg_level = libc::IPPROTO_IPV6;
			cmsg.cmsg_type = libc::IPV6_PKTINFO;
			cmsg.cmsg_len = libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as _) as _;
			ipi6.ipi6_addr.s6_addr = *addr.ip().as_octets();
			ipi6.ipi6_ifindex = addr.scope_id();
		}
		let msg = socket2::MsgHdr::new().with_addr(&daddr).with_buffers(&iovs).with_flags(flags).with_control(&c);
		socket.sendmsg(&msg, flags)
	} else {
		socket.send_to_with_flags(buf, &socket2::SockAddr::from(*dest_addr), flags as c_int)
	}
}

pub fn sendto_schedule2(
	send_list: &mut Vec<scheduled_send>,
	sockfd: &Rc<Socket>,
	buf: &[u8],
	flags: i32,
	dest_addr: SocketAddr,
	src_addr: Option<SocketAddrV6>,
	delay: u32, //ms
) -> io::Result<usize> {
	let state;

	if delay == 0 {
		match send_from_to(sockfd, buf, flags, src_addr.as_ref(), &dest_addr) {
			Ok(n) => return Ok(n),
			Err(e) => match e.kind() {
				ErrorKind::WouldBlock => state = send_state::EWAITREADY,
				ErrorKind::Interrupted => state = send_state::ESENDNOW,
				_ => return Err(e),
			},
		}
	} else {
		state = send_state::ESCHEDULED;
	}

	let elt = scheduled_send {
		state,
		ts: Instant::now().add(Duration::from_millis(delay as u64)),
		socket: sockfd.clone(),
		flags,
		dest_addr,
		src_addr,
		buf: buf.to_vec(),
	};

	send_list.push(elt);

	Ok(0)
}

pub fn sendto_or_schedule(
	send_list: &mut Vec<scheduled_send>,
	sockfd: &Rc<Socket>,
	buf: &[u8],
	flags: i32,
	dest_addr: SocketAddr,
) -> io::Result<usize> {
	sendto_schedule2(send_list, sockfd, buf, flags, dest_addr, None, 0)
}

pub fn sendto_or_schedule2(
	send_list: &mut Vec<scheduled_send>,
	sockfd: &Rc<Socket>,
	buf: &[u8],
	flags: i32,
	dest_addr: SocketAddr,
	src_addr: Option<SocketAddrV6>,
) -> io::Result<usize> {
	sendto_schedule2(send_list, sockfd, buf, flags, dest_addr, src_addr, 0)
}

pub fn get_next_scheduled_send(send_list: &[scheduled_send], next_send: &mut Instant) -> i32 {
	if send_list.is_empty() {
		return 0;
	}
	if let Some(elt) = send_list.first() {
		let instant = elt.ts;
		if instant < *next_send {
			*next_send = elt.ts;
		}
	}
	send_list.len() as i32
}

pub fn get_sendto_fds(
	send_list: &mut [scheduled_send],
	writefds: &mut FdSet,
	_max_fd: &mut i32,
	now: Instant,
) -> i32 {
	let mut n = 0;
	for elt in send_list {
		if elt.state == send_state::EWAITREADY {
			writefds.set(elt.socket.as_raw_fd());
			n += 1;
		} else if elt.ts < now {
			elt.state = send_state::ESENDNOW;
			n += 1;
		}
	}
	n
}

pub fn try_sendto(send_list: &mut Vec<scheduled_send>, writefds: &FdSet) -> i32 {
	let mut idx = 0;
	let mut err_num = 0;

	while idx < send_list.len() {
		let elt = send_list.get_mut(idx).unwrap();

		if !(elt.state == send_state::ESENDNOW
			|| elt.state == send_state::EWAITREADY && writefds.is_set(elt.socket.as_raw_fd()))
		{
			idx += 1;
			continue;
		}
		trace!(
			"try_sendto: {} bytes on socket {}",
			elt.buf.len(),
			elt.socket.as_raw_fd()
		);
		match send_from_to(&elt.socket, &elt.buf, elt.flags, elt.src_addr.as_ref(), &elt.dest_addr) {
			Ok(n) => {
				if n != elt.buf.len() {
					warn!("try_sendto: {} bytes sent out of {}", n, elt.buf.len());
				}
				send_list.swap_remove(idx);
				continue;
			}
			Err(e) => match e.kind() {
				ErrorKind::WouldBlock => {
					elt.state = send_state::EWAITREADY;
				}
				ErrorKind::Interrupted => {
					elt.state = send_state::ESENDNOW;
				}
				_ => {
					error!(
						"try_sendto: (sock={}, len={}, dest={}): sendto: {}",
						elt.socket.as_raw_fd(),
						elt.buf.len(),
						elt.dest_addr,
						e
					);
					err_num += 1;
					send_list.swap_remove(idx);
					continue;
				}
			},
		}
		idx += 1;
	}

	-err_num
}

// maximum execution time for finalize_sendto() in milliseconds
const FINALIZE_SENDTO_DELAY: u64 = 500;

pub fn finalize_sendto(send_list: &mut Vec<scheduled_send>) {
	let deadline = Instant::now().add(Duration::from_millis(FINALIZE_SENDTO_DELAY));
	let mut write_fds = FdSet::default();
	let mut max_fd = -1i32;

	while !send_list.is_empty() {
		let mut idx = 0;
		while idx < send_list.len() {
			let elt = send_list.get_mut(idx).unwrap();
			match send_from_to(&elt.socket, &elt.buf, elt.flags, elt.src_addr.as_ref(), &elt.dest_addr) {
				Ok(_) => {
					send_list.swap_remove(idx);
				}
				Err(e) => match e.kind() {
					ErrorKind::WouldBlock => {
						if elt.socket.as_raw_fd() > max_fd {
							max_fd = elt.socket.as_raw_fd();
						}
						write_fds.set(elt.socket.as_raw_fd());
						idx += 1;
					}
					_ => {
						warn!("finalize_sendto(): socket={} sendto: {}", elt.socket.as_raw_fd(), e);
						send_list.swap_remove(idx);
					}
				},
			}
		}
		if Instant::now() > deadline {
			send_list.clear();
			return;
		}
		let timeout = deadline.duration_since(Instant::now());

		if let Err(e) = select(
			max_fd as isize,
			None,
			Some(&mut write_fds),
			None,
			Some(&mut make_timeval(timeout)),
		) {
			error!("select: {}", e);
			return;
		}
	}
}
