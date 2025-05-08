use libc;

use crate::upnputils::upnp_time;
use libc::{c_int, c_uint, in_addr};
use std::cmp::min;
use std::ffi::CStr;
use std::fmt::{Display, Formatter};
use std::io::Read;
use std::mem::MaybeUninit;
#[cfg(feature = "ipv6")]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{io, mem, ptr};

pub struct FdSet(libc::fd_set);

impl Default for FdSet {
	fn default() -> Self {
		unsafe {
			let mut raw_fd_set = MaybeUninit::<libc::fd_set>::uninit();
			libc::FD_ZERO(raw_fd_set.as_mut_ptr());
			FdSet(raw_fd_set.assume_init())
		}
	}
}

impl FdSet {
	pub fn clear(&mut self, fd: RawFd) {
		unsafe { libc::FD_CLR(fd, &mut self.0) }
	}
	pub fn set(&mut self, fd: RawFd) {
		unsafe { libc::FD_SET(fd, &mut self.0) }
	}
	pub fn is_set(&self, fd: RawFd) -> bool {
		unsafe { libc::FD_ISSET(fd, &self.0) }
	}
	pub fn clean_up(&mut self) {
		unsafe { libc::FD_ZERO(&mut self.0) };
	}
}

fn to_fdset_ptr(opt: Option<&mut FdSet>) -> *mut libc::fd_set {
	match opt {
		None => ptr::null_mut(),
		Some(&mut FdSet(ref mut raw_fd_set)) => raw_fd_set,
	}
}

fn to_ptr<T>(opt: Option<&T>) -> *const T {
	match opt {
		None => ptr::null::<T>(),
		Some(p) => p,
	}
}
fn to_mut_ptr<T>(opt: Option<&mut T>) -> *mut T {
	match opt {
		None => ptr::null_mut::<T>(),
		Some(p) => p,
	}
}

#[cfg(any(
	target_os = "haiku",
	target_os = "illumos",
	target_os = "solaris",
	target_os = "cygwin"
))]
#[derive(Default, Clone, Debug, Eq, PartialEq, Hash)]
pub struct IfName(Rc<str>);
#[cfg(any(
	target_os = "haiku",
	target_os = "illumos",
	target_os = "solaris",
	target_os = "cygwin"
))]
impl FromStr for IfName {
	type Err = io::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if !s.is_ascii() || s.is_empty() {
			return Err(io::ErrorKind::InvalidInput.into());
		}
		let mut d = String::with_capacity(s.len() + 1);
		d.push_str(s);
		d.push_str("\0");

		let buf: Rc<str> = Rc::from(d);

		Ok(IfName(buf))
	}
}

#[cfg(any(
	target_os = "haiku",
	target_os = "illumos",
	target_os = "solaris",
	target_os = "cygwin"
))]
impl Display for IfName {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		f.write_str(self.as_str())
	}
}
#[cfg(any(
	target_os = "haiku",
	target_os = "illumos",
	target_os = "solaris",
	target_os = "cygwin"
))]
impl IfName {
	pub fn as_str(&self) -> &str {
		self.0.as_str().trim_ascii_end()
	}
	pub fn as_ptr(&self) -> *const libc::c_char {
		self.0.as_ptr() as *const libc::c_char
	}
	pub fn as_cstr(&self) -> &CStr {
		let len = self.len();
		unsafe { CStr::from_bytes_with_nul_unchecked(&self.0.as_bytes()) }
	}
	#[inline]
	pub fn len(&self) -> usize {
		self.0.len() - 1
	}
	#[inline]
	pub const fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
	pub fn index(&self) -> u32 {
		unsafe { libc::if_nametoindex(self.as_ptr()) }
	}
}

#[derive(Default, Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg(not(any(
	target_os = "haiku",
	target_os = "illumos",
	target_os = "solaris",
	target_os = "cygwin"
)))]
pub struct IfName([u8; libc::IF_NAMESIZE]);
#[cfg(not(any(
	target_os = "haiku",
	target_os = "illumos",
	target_os = "solaris",
	target_os = "cygwin"
)))]
impl FromStr for IfName {
	type Err = io::Error;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.len() >= (libc::IF_NAMESIZE) {
			return Err(io::ErrorKind::ArgumentListTooLong.into());
		}
		if !s.is_ascii() || s.is_empty() {
			return Err(io::ErrorKind::InvalidInput.into());
		}
		let bytes = s.as_bytes();
		if bytes[0].is_ascii_digit() {
			return Err(io::ErrorKind::InvalidInput.into());
		}
		let mut d = [0u8; libc::IF_NAMESIZE];
		let len = min(libc::IF_NAMESIZE - 1, bytes.len());
		d[..len].copy_from_slice(&bytes[..len]);
		Ok(IfName(d))
	}
}
#[cfg(not(any(
	target_os = "haiku",
	target_os = "illumos",
	target_os = "solaris",
	target_os = "cygwin"
)))]
impl Display for IfName {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		f.write_str(self.as_str())
	}
}
#[cfg(not(any(
	target_os = "haiku",
	target_os = "illumos",
	target_os = "solaris",
	target_os = "cygwin"
)))]
impl IfName {
	pub fn as_str(&self) -> &str {
		let len = unsafe { libc::strnlen(self.0.as_ptr() as _, size_of_val(self)) };
		unsafe { str::from_utf8_unchecked(&self.0[0..len]) }
	}
	pub fn as_ptr(&self) -> *const libc::c_char {
		self.0.as_ptr() as *const libc::c_char
	}
	pub fn as_cstr(&self) -> &CStr {
		let len = self.len();
		unsafe { CStr::from_bytes_with_nul_unchecked(&self.0[0..len + 1]) }
	}
	pub fn as_bytes(&self) -> &[u8] {
		&self.0[0..self.len() + 1]
	}
	#[inline]
	pub fn len(&self) -> usize {
		unsafe { libc::strnlen(self.0.as_ptr() as _, size_of_val(self)) }
	}
	#[inline]
	pub const fn is_empty(&self) -> bool {
		self.0[0] == 0
	}
	pub fn index(&self) -> u32 {
		unsafe { libc::if_nametoindex(self.as_ptr()) }
	}
	pub fn from_index(i: u32) -> Option<Self> {
		let mut ifname = Self::default();
		if unsafe { libc::if_indextoname(i, ifname.0.as_mut_ptr() as _) }.is_null() {
			None
		} else {
			Some(ifname)
		}
	}
}

pub fn pselect(
	nfds: c_int,
	readfds: Option<&mut FdSet>,
	writefds: Option<&mut FdSet>,
	errorfds: Option<&mut FdSet>,
	timeout: Option<&libc::timespec>,
	sigmask: Option<&libc::sigset_t>,
) -> io::Result<usize> {
	match unsafe {
		libc::pselect(
			nfds,
			to_fdset_ptr(readfds),
			to_fdset_ptr(writefds),
			to_fdset_ptr(errorfds),
			to_ptr(timeout),
			to_ptr(sigmask),
		)
	} {
		-1 => Err(io::Error::last_os_error()),
		res => Ok(res as usize),
	}
}
pub fn select(
	nfds: isize,
	readfds: Option<&mut FdSet>,
	writefds: Option<&mut FdSet>,
	errorfds: Option<&mut FdSet>,
	timeval: Option<&mut libc::timeval>,
) -> io::Result<isize> {
	match unsafe {
		libc::select(
			nfds as libc::c_int,
			to_fdset_ptr(readfds),
			to_fdset_ptr(writefds),
			to_fdset_ptr(errorfds),
			to_mut_ptr(timeval),
		)
	} {
		-1 => Err(io::Error::last_os_error()),
		res => Ok(res as isize),
	}
}

pub fn make_timespec(duration: Duration) -> libc::timespec {
	libc::timespec { tv_sec: duration.as_secs() as i64, tv_nsec: duration.subsec_nanos() as i64 }
}
pub fn make_timeval(duration: Duration) -> libc::timeval {
	libc::timeval { tv_sec: duration.as_secs() as i64, tv_usec: duration.subsec_micros() as _ }
}

#[cfg(any(
	target_os = "linux",
	target_os = "android",
	target_os = "macos",
	target_os = "ios",
	target_os = "freebsd",
	target_os = "tvos",
	target_os = "watchos",
	target_os = "netbsd",
	target_os = "openbsd",
	target_os = "solaris",
	target_family = "unix"
))]
pub fn recv_from_if(s: &impl AsRawFd, buf: &mut [u8]) -> io::Result<(SocketAddr, Option<IpAddr>, u32, usize)> {
	#[cfg(feature = "ipv6")]
	let mut sender_name: MaybeUninit<libc::sockaddr_storage> = MaybeUninit::uninit();
	#[cfg(not(feature = "ipv6"))]
	let mut sender_name: MaybeUninit<libc::sockaddr_in> = MaybeUninit::uninit();

	#[cfg(feature = "ipv6")]
	let mut cmbuf: MaybeUninit<[u8; unsafe { libc::CMSG_SPACE(size_of::<libc::in6_pktinfo>() as c_uint) as usize }]> =
		MaybeUninit::uninit();
	#[cfg(not(feature = "ipv6"))]
	let mut cmbuf: MaybeUninit<[u8; unsafe { libc::CMSG_SPACE(size_of::<libc::in_pktinfo>() as c_uint) as usize }]> =
		MaybeUninit::uninit();

	let mut iovec = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };

	let mut mh: libc::msghdr = unsafe { mem::zeroed() };

	mh.msg_name = sender_name.as_mut_ptr() as *mut _;
	mh.msg_namelen = size_of_val(&sender_name) as u32;
	mh.msg_iov = (&mut iovec) as *mut _ as *mut _;
	mh.msg_iovlen = 1;
	mh.msg_control = cmbuf.as_mut_ptr() as *mut _;
	mh.msg_controllen = size_of_val(&cmbuf) as _;
	mh.msg_flags = 0;

	let n = unsafe { libc::recvmsg(s.as_raw_fd() as c_int, &mut mh, 0) };
	if n < 0 {
		return Err(io::Error::last_os_error());
	}
	let senderaddr: SocketAddr;
	let mut recveraddr: IpAddr = Ipv4Addr::UNSPECIFIED.into();
	let mut ifindex = 0;

	let mut cmptr: *const libc::cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&mh) };
	while !cmptr.is_null() {
		let cm_ref = unsafe { cmptr.as_ref().unwrap() };

		debug!("level={} type={}", cm_ref.cmsg_level, cm_ref.cmsg_type);

		match (cm_ref.cmsg_level, cm_ref.cmsg_type) {
			#[cfg(target_os = "macos")]
			(libc::IPPROTO_IP, libc::IP_RECVIF) => {
				let pi_ptr = unsafe { libc::CMSG_DATA(cmptr) as *const libc::sockaddr_dl };
				let pi_ref = unsafe { pi_ptr.as_ref().unwrap() };
				ifindex = pi_ref.sdl_index as u32;
				recveraddr = Ipv4Addr::UNSPECIFIED.into();
				debug!("ifindex = {} {}", ifindex, senderaddr);
			}
			(libc::IPPROTO_IP, libc::IP_PKTINFO) => {
				let pi_ptr = unsafe { libc::CMSG_DATA(cmptr) as *const libc::in_pktinfo };
				let pi_ref = unsafe { pi_ptr.as_ref().unwrap() };

				debug!("ifindex = {} {}", pi_ref.ipi_ifindex, pi_ref.ipi_spec_dst.s_addr);
				ifindex = pi_ref.ipi_ifindex as u32;
				recveraddr = Ipv4Addr::from(pi_ref.ipi_addr.s_addr).into();
			}
			#[cfg(feature = "ipv6")]
			(libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO) => {
				let pi_ptr = unsafe { libc::CMSG_DATA(cmptr) as *const libc::in6_pktinfo };
				let pi_ref = unsafe { pi_ptr.as_ref().unwrap() };
				recveraddr = Ipv6Addr::from(pi_ref.ipi6_addr.s6_addr).into();
				ifindex = pi_ref.ipi6_ifindex as u32;
				debug!("ifindex = {}", ifindex);
			}
			(level, t) => {
				debug!("unknown level={} type={}", level, t);
				return Err(io::Error::new(
					io::ErrorKind::Other,
					format!("unknown level={} type={}", level, t),
				));
			}
		}
		cmptr = unsafe { libc::CMSG_NXTHDR(&mh, cmptr) };
	}
	let sendr = unsafe { sender_name.assume_init() };
	let family_ptr = ptr::from_ref(&sendr) as *const u16;
	let family = unsafe { ptr::read(family_ptr) };
	match family as c_int {
		libc::AF_INET => {
			let in4 = unsafe { (&sendr as *const _ as *const libc::sockaddr_in).as_ref().unwrap() };
			senderaddr = SocketAddrV4::new(Ip4Addr::from(in4.sin_addr).into(), u16::from_be(in4.sin_port)).into()
		}
		libc::AF_INET6 => {
			let in6 = unsafe { (&sendr as *const _ as *const libc::sockaddr_in6).as_ref().unwrap() };
			senderaddr = SocketAddrV6::new(
				in6.sin6_addr.s6_addr.into(),
				u16::from_be(in6.sin6_port),
				in6.sin6_flowinfo,
				in6.sin6_scope_id,
			)
			.into()
		}
		_ => {
			unreachable!();
		}
	}

	Ok((senderaddr, Some(recveraddr), ifindex, n as usize))
}

/// params: addr: this T *cannot* include pointer struct,
///
/// some nice usage:
/// ```
/// use std::mem::MaybeUninit;
/// use std::net::Ipv6Addr;
/// use miniupnpd_rs::warp::copy_from_slice;
/// let mut addr:MaybeUninit<Ipv6Addr> = MaybeUninit::uninit();
/// let buf = [0xff;16];
/// /// this operation saves one memcpy
/// copy_from_slice(unsafe {addr.assume_init_mut()}, &buf);
/// let addr = unsafe {addr.assume_init()};
/// ```
/// *cannot* for example:
/// ```
/// use miniupnpd_rs::warp::copy_from_slice;
/// let mut buf = [0;8];
/// let data = [0xff;8];
/// let mut buf_ref = buf.as_mut_slice();
/// /// this will be panic when access buf_ref, the pointer is overwritten
/// copy_from_slice(&mut buf_ref, &data);
/// panic!();
/// ```
#[inline]
pub fn copy_from_slice<T>(addr: &mut T, buf: &[u8])
where
	T: Sized,
{
	unsafe { (ptr::from_mut(addr) as *mut u8).copy_from_nonoverlapping(buf.as_ptr(), min(buf.len(), size_of::<T>())) };
}

#[inline]
pub fn sockaddr_to_v4(addr: SocketAddr) -> SocketAddrV4 {
	match addr {
		SocketAddr::V4(v4) => v4,
		SocketAddr::V6(v6) => {
			if v6.ip().is_ipv4_mapped() {
				SocketAddrV4::new(v6.ip().to_ipv4().unwrap(), v6.port())
			} else {
				SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, addr.port())
			}
		}
	}
}
pub fn ip_is_ipv4_mapped(addr: &IpAddr) -> bool {
	match addr {
		IpAddr::V4(_) => false,
		IpAddr::V6(v6) => v6.is_ipv4_mapped(),
	}
}
pub fn timestamp_to_instant(ts: u64) -> Instant {
	let cur = upnp_time().as_secs();
	if cur > ts {
		Instant::now().checked_add(Duration::from_secs((cur - ts) as _)).unwrap()
	} else {
		Instant::now().checked_sub(Duration::from_secs((ts - cur) as _)).unwrap()
	}
}

macro_rules! impl_from_into {
	($source:ty, $target:ty) => {
		impl From<$source> for $target {
			#[inline]
			fn from(value: $source) -> Self {
				unsafe { std::mem::transmute(value) }
			}
		}

		impl Into<$source> for $target {
			#[inline]
			fn into(self) -> $source {
				unsafe { std::mem::transmute(self) }
			}
		}
	};
}

/// helper for bridge Ipv4Addr with in_addr using zerocopy
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Ip4Addr([u8; 4]);

impl_from_into!(in_addr, Ip4Addr);
impl_from_into!(Ipv4Addr, Ip4Addr);
impl_from_into!(u32, Ip4Addr);

impl<'a> From<&'a Ipv4Addr> for &'a Ip4Addr {
	#[inline]
	fn from(addr: &'a Ipv4Addr) -> &'a Ip4Addr {
		unsafe { &*(addr as *const _ as *const Ip4Addr) }
	}
}

/// replace [io::BufRead], the BufRead always alloc 8K heap buffer,
/// mostly we only need read small string ,
/// this is wapper for file read on stack
pub struct StackBufferReader<'a> {
	buf: &'a mut [u8],
	pos: u16,
	cap: u16,
	use_pos: u16,
	ended: bool,
}

impl<'a> StackBufferReader<'a> {
	pub fn new(buf: &'a mut [u8]) -> Self {
		let cap = buf.len() as u16;
		Self { buf, pos: 0, cap, use_pos: 0, ended: false }
	}

	pub fn read_line(&mut self, reader: &mut impl Read) -> Option<io::Result<&[u8]>> {
		loop {
			if self.use_pos < self.pos {
				if let Some(offset) =
					self.buf[self.use_pos as usize..self.pos as usize].iter().position(|&c| c == b'\n')
				{
					let cur_pos = self.use_pos;
					self.use_pos += offset as u16 + 1; // move and skip "\n"
					if offset == 0 {
						continue;
					}
					return Some(Ok::<&[u8], io::Error>(
						&self.buf[cur_pos as usize..cur_pos as usize + offset],
					));
				} else if self.ended {
					let cur_pos = self.use_pos;
					self.use_pos = self.pos;
					return Some(Ok(&self.buf[cur_pos as usize..self.pos as usize]));
				}
			}
			if self.use_pos == self.pos && self.ended {
				self.use_pos = 0;
				self.pos = 0;
				self.ended = false;
				return None;
			}
			if self.use_pos < self.pos && self.pos == self.cap {
				let len = self.pos - self.use_pos;
				let buf_p = self.buf.as_mut_ptr();
				// move data to start of buffer
				unsafe { ptr::copy(buf_p.add(self.use_pos as usize), buf_p, len as usize) };
				self.use_pos = 0;
				self.pos = len;
			}
			if !self.ended {
				if self.use_pos == self.pos && self.pos == self.cap {
					self.pos = 0;
					self.use_pos = 0;
				}
				let cap = self.cap - self.pos;
				if cap == 0 && self.use_pos == 0 {
					return Some(Err(io::ErrorKind::OutOfMemory.into()));
				}
				let len = match reader.read(&mut self.buf[self.pos as usize..]) {
					Ok(len) => len,
					Err(e) => return Some(Err(e)),
				};
				self.pos += len as u16;
				if len == 0 || cap != len as u16 {
					self.ended = true;
				}
				continue;
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn test_ifname() {
		let ifname = IfName::from_str("eth0");

		assert!(ifname.is_ok());

		let ifname = ifname.unwrap();
		assert_eq!(ifname.as_str(), "eth0");
		assert_eq!(ifname.as_str().len(), ifname.len());
		assert!(IfName::from_str("ifname").is_ok());
		assert!(IfName::from_str("br1234567890abc").is_ok());
		assert!(IfName::from_str("br1234567890abcd").is_err());
	}
	#[test]
	fn test_read_line() {
		let mut cursor = io::Cursor::new(b"hello\nworld\n");

		let mut buf = [0u8; 128];
		let mut reader = StackBufferReader::new(&mut buf);

		assert_eq!(reader.read_line(&mut cursor).unwrap().unwrap(), b"hello");
		assert_eq!(reader.read_line(&mut cursor).unwrap().unwrap(), b"world");
		assert!(reader.read_line(&mut cursor).is_none());
	}

	#[test]
	fn test_read_line_empty() {
		let mut cursor = io::Cursor::new(b"\n\n\n\n\n");

		let mut buf = [0u8; 128];
		let mut reader = StackBufferReader::new(&mut buf);
		assert!(reader.read_line(&mut cursor).is_none());
	}
}
