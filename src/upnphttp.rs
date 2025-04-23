#![allow(
	dead_code,
	mutable_transmutes,
	non_camel_case_types,
	non_snake_case,
	non_upper_case_globals,
	unused_assignments,
	unused_mut
)]
use crate::miniupnpdpath::*;
use crate::options::*;
use crate::upnpdescgen::*;
use crate::upnpevents::{upnpevents_addSubscriber, upnpevents_removeSubscriber, upnpevents_renewSubscription};
use crate::upnpglobalvars::{FORCEIGDDESCV1MASK, global_option, os_version};
use crate::upnpsoap::ExecuteSoapAction;
use crate::{GETFLAG, debug, info, log};
use crate::{error, notice, warn};
use once_cell::sync::OnceCell;
use socket2::Socket;
#[cfg(feature = "https")]
use std::ffi::{CStr, c_int};
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{io, mem};

use std::str::FromStr;

#[cfg(feature = "https")]
use openssl_sys::{
	CONF_modules_unload, ERR_error_string, ERR_get_error, OPENSSL_INIT_LOAD_SSL_STRINGS, OPENSSL_VERSION,
	OPENSSL_init_ssl, OpenSSL_version, SSL, SSL_CTX, SSL_CTX_check_private_key, SSL_CTX_free, SSL_CTX_new,
	SSL_CTX_set_verify, SSL_CTX_use_PrivateKey_file, SSL_CTX_use_certificate_file, SSL_ERROR_WANT_READ,
	SSL_ERROR_WANT_WRITE, SSL_FILETYPE_PEM, SSL_VERIFY_NONE, SSL_accept, SSL_free, SSL_new, SSL_read, SSL_set_fd,
	TLS_server_method, X509_STORE_CTX,
};
use openssl_sys::{SSL_get_error, SSL_write};
#[cfg(feature = "https")]
use std::ptr::NonNull;

pub static MINIUPNPD_SERVER_STRING: OnceCell<String> = OnceCell::new();

use crate::upnpdescstrings::OS_NAME;
use crate::uuid::UUID;
/// Include the "Timeout:" header in response
const FLAG_TIMEOUT: u32 = 0x01;
/// Include the "SID:" header in response
const FLAG_SID: u32 = 0x02;

/// If set, the POST request included a "Expect: 100-continue" header
const FLAG_CONTINUE: u32 = 0x40;

/// If set, the Content-Type is set to text/xml, otherwise it is text/xml
const FLAG_HTML: u32 = 0x80;

/// If set, the corresponding Allow: header is set
const FLAG_ALLOW_POST: u32 = 0x100;
const FLAG_ALLOW_SUB_UNSUB: u32 = 0x200;

/// If set, the User-Agent: contains "microsoft"
const FLAG_MS_CLIENT: u32 = 0x400;

pub type httpStates = u32;
pub const EWaitingForHttpRequest: httpStates = 0;
pub const EWaitingForHttpContent: httpStates = 1;
pub const ESendingContinue: httpStates = 2;
pub const ESendingAndClosing: httpStates = 3;
pub const EToDelete: httpStates = 100;

pub enum httpCommands {
	EUnknown = 0,
	EGet = 1,
	EPost = 2,
	ESubscribe = 3,
	EUnSubscribe = 4,
}
use self::httpCommands::*;

pub trait SubsliceOffset {
	/**
	Returns the byte offset of an inner slice relative to an enclosing outer slice.

	Examples

	```ignore
	let string = "a\nb\nc";
	let lines: Vec<&str> = string.lines().collect();
	assert!(string.subslice_offset_stable(lines[0]) == Some(0)); // &"a"
	assert!(string.subslice_offset_stable(lines[1]) == Some(2)); // &"b"
	assert!(string.subslice_offset_stable(lines[2]) == Some(4)); // &"c"
	assert!(string.subslice_offset_stable("other!") == None);
	```
	*/
	fn subslice_offset_stable(&self, inner: &Self) -> OffLen;
}

impl SubsliceOffset for str {
	fn subslice_offset_stable(&self, inner: &str) -> OffLen {
		let self_beg = self.as_ptr() as usize;
		let inner_ptr = inner.as_ptr() as usize;
		if inner_ptr < self_beg || inner_ptr > self_beg.wrapping_add(self.len()) {
			0.into()
		} else {
			(((inner_ptr.wrapping_sub(self_beg) & 0xffff) << 16) as u32 | (inner.len() & 0xffff) as u32).into()
		}
	}
}
#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct OffLen(pub u32);
impl OffLen {
	pub(super) fn len(&self) -> u16 {
		(self.0 & 0xFFFF) as u16
	}
	pub(super) fn off(&self) -> u16 {
		(self.0 >> 16) as u16
	}
	pub(super) fn set_len(&mut self, len: u16) {
		self.0 |= len as u32;
	}
}
impl From<u32> for OffLen {
	fn from(off: u32) -> Self {
		OffLen(off)
	}
}

#[derive(Default)]
#[repr(transparent)]
#[cfg(feature = "https")]
pub struct Raw_SSL(pub Option<NonNull<SSL>>);
#[cfg(feature = "https")]
impl Drop for Raw_SSL {
	fn drop(&mut self) {
		if self.0.is_none() {
			return;
		}
		unsafe {
			SSL_free(self.0.unwrap().as_ptr());
		}
	}
}
#[cfg(feature = "https")]
impl Raw_SSL {
	#[inline]
	pub fn is_none(&self) -> bool {
		self.0.is_none()
	}
	#[inline]
	pub fn as_ptr(&self) -> *const SSL {
		self.0.as_ref().unwrap().as_ptr()
	}
	#[inline]
	pub fn as_mut_ptr(&mut self) -> *mut SSL {
		self.0.as_mut().unwrap().as_ptr()
	}
}

pub struct upnphttp<'a> {
	pub socket: Socket,
	pub clientaddr: IpAddr,
	pub ipv6: bool,
	// pub clientaddr_v6: Ipv6Addr,
	// pub clientaddr_str: [libc::c_char; 64],
	pub state: httpStates,
	pub HttpVer: OffLen,
	pub req_buf: String,
	pub accept_language: OffLen,
	// pub req_buflen: i32,
	pub req_contentlen: u32,
	pub req_contentoff: OffLen,
	pub req_command: httpCommands,
	pub req_soapActionOff: OffLen,
	// pub req_soapActionLen: i32,
	pub req_HostOff: OffLen,
	// pub req_HostLen: i32,
	pub req_CallbackOff: OffLen,
	// pub req_CallbackLen: i32,
	pub req_Timeout: u32,
	pub req_SIDOff: OffLen,

	pub req_NTOff: OffLen,
	// pub req_SIDLen: i32,
	pub res_SID: UUID,
	pub respflags: u32,
	pub res_buf: Vec<u8>,
	pub res_sent: i32,
	pub rt_options: Option<&'a mut RtOptions>,
	#[cfg(feature = "https")]
	pub ssl: Raw_SSL,
}
impl upnphttp<'_> {
	pub fn get_req_str_from(&self, off: OffLen) -> &str {
		let buf_off = off.off() as u32;
		let buf_len = off.len() as u32;
		if (buf_off + buf_len) > self.req_buf.len() as u32 || buf_off > self.req_buf.len() as u32 {
			""
		} else {
			unsafe {
				std::str::from_utf8_unchecked(std::slice::from_raw_parts(
					self.req_buf.as_str().as_ptr().wrapping_add(buf_off as usize),
					buf_len as usize,
				))
			}
		}
	}
	fn recv(&mut self, buf: &mut [MaybeUninit<u8>]) -> io::Result<usize> {
		#[cfg(feature = "https")]
		if self.ssl.is_none() {
			self.socket.recv(buf)
		} else {
			let n = unsafe { SSL_read(self.ssl.as_mut_ptr(), buf.as_mut_ptr() as _, buf.len() as _) };
			if n < 0 {
				Err(io::Error::last_os_error())
			} else {
				Ok(n as usize)
			}
		}
		#[cfg(not(feature = "https"))]
		{
			self.socket.recv(buf)
		}
	}
	fn send(&self, buf: &[u8]) -> io::Result<usize> {
		#[cfg(feature = "https")]
		if self.ssl.is_none() {
			self.socket.send(buf)
		} else {
			let n = unsafe { SSL_write(self.ssl.as_ptr().cast_mut(), buf.as_ptr() as _, buf.len() as _) };
			if n < 0 {
				Err(io::Error::last_os_error())
			} else {
				Ok(n as usize)
			}
		}
		#[cfg(not(feature = "https"))]
		{
			self.socket.send(buf)
		}
	}
}

pub fn New_upnphttp<'a>(mut s: Socket, peeraddr: IpAddr) -> upnphttp<'a> {
	if let Err(e) = s.set_nonblocking(true) {
		warn!("New_upnphttp::set_non_blocking(): {}", e);
	}
	let ss = String::new();

	upnphttp {
		socket: s,

		clientaddr: peeraddr,
		ipv6: false,
		// clientaddr_v6: Ipv6Addr::UNSPECIFIED,
		// clientaddr_str: [],
		state: EWaitingForHttpRequest,
		HttpVer: Default::default(),
		req_HostOff: Default::default(),

		accept_language: Default::default(),
		// req_buflen: 0,
		req_contentlen: 0,
		req_contentoff: Default::default(),
		req_command: EUnknown,
		req_soapActionOff: Default::default(),
		// req_soapActionLen: 0,

		// req_HostLen: 0,
		req_CallbackOff: Default::default(),
		// req_CallbackLen: 0,
		req_Timeout: 0,
		req_SIDOff: Default::default(),
		// req_SIDLen: 0,
		req_NTOff: Default::default(),
		res_SID: UUID::default(),
		respflags: 0,
		res_buf: Vec::new(),
		req_buf: ss,
		// res_buflen: 0,
		res_sent: 0,
		rt_options: None,
		#[cfg(feature = "https")]
		ssl: Default::default(),
	}
}
#[cfg(feature = "https")]
fn syslogsslerr() {
	let mut buf = [0; 256];
	unsafe {
		while let err = ERR_get_error()
			&& err != 0
		{
			let c = CStr::from_ptr(ERR_error_string(err, buf.as_mut_ptr()));
			error!("{}", c.to_str().unwrap());
		}
	}
}
#[cfg(feature = "https")]
extern "C" fn verify_callback(preverify_ok: c_int, ctx: *mut X509_STORE_CTX) -> c_int {
	debug!("verify_callback({}, {:p})", preverify_ok, ctx);
	preverify_ok
}
#[cfg(feature = "https")]
pub fn init_ssl(op: &mut Options, rt: &mut RtOptions) -> i32 {
	use libc::ENOENT;
	use openssl_sys::OPENSSL_INIT_LOAD_CRYPTO_STRINGS;
	use std::ptr;

	if op.https_cert.is_empty() || op.https_key.is_empty() {
		return -ENOENT;
	}

	unsafe {
		OPENSSL_init_ssl(0, ptr::null_mut());
		OPENSSL_init_ssl(
			OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
			ptr::null_mut(),
		);

		let method = TLS_server_method();
		if method.is_null() {
			error!("TLS_server_method() failed");
			syslogsslerr();
			return -1;
		}
		let ssl_ctx = SSL_CTX_new(method);
		if ssl_ctx.is_null() {
			error!("SSL_CTX_new() failed");
			syslogsslerr();
			return -1;
		}
		if SSL_CTX_use_certificate_file(ssl_ctx, op.https_cert.as_ptr(), SSL_FILETYPE_PEM) == 0 {
			error!(
				"SSL_CTX_use_certificate_file({}) failed",
				op.https_cert.to_str().unwrap()
			);
			syslogsslerr();
			return -1;
		}
		if SSL_CTX_use_PrivateKey_file(ssl_ctx, op.https_key.as_ptr(), SSL_FILETYPE_PEM) == 0 {
			error!(
				"SSL_CTX_use_private_key_file({}) failed",
				op.https_key.to_str().unwrap()
			);
			syslogsslerr();
			return -1;
		}
		if SSL_CTX_check_private_key(ssl_ctx) == 0 {
			error!("SSL_CTX_check_private_key() failed");
			syslogsslerr();
			return -1;
		}
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, Some(verify_callback));
		info!(
			"using {}",
			CStr::from_ptr(OpenSSL_version(OPENSSL_VERSION)).to_str().unwrap()
		);
		rt.ssl_ctx = ssl_ctx;
	}

	0
}
#[cfg(feature = "https")]
fn free_ssl(ssl_ctx: *mut SSL_CTX) {
	unsafe {
		if !ssl_ctx.is_null() {
			SSL_CTX_free(ssl_ctx);
		}
		CONF_modules_unload(1);
	}
}

#[cfg(feature = "https")]
pub fn InitSSL_upnphttp(h: &mut upnphttp, rt: &mut RtOptions) -> i32 {
	use std::os::fd::AsRawFd;
	unsafe {
		let ssl = SSL_new(rt.ssl_ctx);
		if ssl.is_null() {
			error!("SSL_new() failed");
			syslogsslerr();
			return -1;
		}
		if SSL_set_fd(ssl, h.socket.as_raw_fd()) == 0 {
			error!("SSL_set_fd() failed");
			syslogsslerr();
			return -1;
		}
		let r = SSL_accept(ssl);
		if r < 0 {
			let err = SSL_get_error(ssl, r);
			debug!("SSL_accept() returned {}, SSL_get_error() {}", r, err);
			if err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE {
				error!("SSL_accept() failed");
				syslogsslerr();
				return r;
			}
		}
		h.ssl = Raw_SSL(NonNull::new(ssl));
	}
	0
}

pub fn CloseSocket_upnphttp(h: &mut upnphttp) {
	h.state = EToDelete;
}

pub fn Delete_upnphttp(h: upnphttp) {
	drop(h);
}
fn ParseHttpHeaders(h: &mut upnphttp) {
	let str = h.req_buf.as_str();

	if let Some(headroff) = str.find("\r\n\r\n") {
		let headers = &str[0..headroff];

		for line in headers.split("\r\n") {
			if !line.contains(':') {
				continue;
			}
			if let Some((k, v)) = line.split_once(&[' ', '\t']) {
				if k.eq_ignore_ascii_case("Content-Length:") {
					if let Ok(v) = v.parse::<u32>() {
						h.req_contentlen = v;
					} else {
						warn!("ParseHttpHeaders() invalid Content-Length {}", v)
					}
				} else if k.eq_ignore_ascii_case("accept-language:") {
					h.accept_language = h.req_buf.subslice_offset_stable(v);
				} else if k.eq_ignore_ascii_case("expect:") {
					if v == "100-continue" {
						h.respflags = FLAG_CONTINUE;
					}
				} else if k.eq_ignore_ascii_case("host:") {
					h.req_HostOff = h.req_buf.subslice_offset_stable(v);
				} else if k.eq_ignore_ascii_case("SOAPAction:") {
					h.req_soapActionOff = h.req_buf.subslice_offset_stable(v);
				} else if k.eq_ignore_ascii_case("SID:") {
					h.req_SIDOff = h.req_buf.subslice_offset_stable(v);
				} else if k.eq_ignore_ascii_case("user-agent:") {
					if v.trim() == "microsoft" || v.trim() == "FDSSDP" {
						h.respflags |= FLAG_MS_CLIENT;
					}
				} else if k.eq_ignore_ascii_case("Callback:") {
					h.req_CallbackOff = h.req_buf.subslice_offset_stable(v);
				} else if k.eq_ignore_ascii_case("Timeout:") {
					if v[..7].eq_ignore_ascii_case("Second-") {
						if let Ok(v) = v[7..v.len()].parse::<i32>() {
							h.req_Timeout = v as u32;
						}
					}
				} else if k.eq_ignore_ascii_case("nt:") {
					h.req_NTOff = h.req_buf.subslice_offset_stable(v);
				}
			}
		}
	}
}
fn Send404(h: &mut upnphttp) {
	const  body404: &[u8; 134] =
            b"<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>Not Found</H1>The requested URL was not found on this server.</BODY></HTML>\r\n";
	h.respflags = FLAG_HTML;
	BuildResp2_upnphttp(h, 404i32, "Not Found", Some(body404));
	SendRespAndClose_upnphttp(h);
}
fn Send405(h: &mut upnphttp) {
	const body405: &[u8; 153] =
        b"<HTML><HEAD><TITLE>405 Method Not Allowed</TITLE></HEAD><BODY><H1>Method Not Allowed</H1>The HTTP Method is not allowed on this resource.</BODY></HTML>\r\n";
	h.respflags |= FLAG_HTML;
	BuildResp2_upnphttp(h, 405i32, "Method Not Allowed", Some(body405));
	SendRespAndClose_upnphttp(h);
}
fn Send501(h: &mut upnphttp) {
	const body501: &[u8; 149] = b"<HTML><HEAD><TITLE>501 Not Implemented</TITLE></HEAD><BODY><H1>Not Implemented</H1>The HTTP Method is not implemented by this server.</BODY></HTML>\r\n";
	h.respflags = FLAG_HTML;
	BuildResp2_upnphttp(h, 501i32, "Not Implemented", Some(body501));
	SendRespAndClose_upnphttp(h);
}

fn sendXMLdesc(h: &mut upnphttp, f: fn(bool) -> String, runtime_flags: u32) {
	#[cfg(feature = "igd2")]
	if (h.respflags & FLAG_MS_CLIENT) != 0 {
		trace!("MS Client, forceing IGD v1");
	}

	let desc = f(GETFLAG!(runtime_flags, FORCEIGDDESCV1MASK) || ((h.respflags & FLAG_MS_CLIENT) != 0));

	if desc.is_empty() {
		const err500: &[u8; 86] =
			b"<HTML><HEAD><TITLE>Error 500</TITLE></HEAD><BODY>Internal Server Error</BODY></HTML>\r\n";
		error!("Failed to generate XML description");

		h.respflags = FLAG_HTML;
		BuildResp2_upnphttp(h, 500, "Internal Server Error", Some(err500));
	} else {
		BuildResp_upnphttp(h, Some(desc.as_bytes()));
	}
	SendRespAndClose_upnphttp(h);
}
fn ProcessHTTPPOST_upnphttp(h: &mut upnphttp) {
	if h.req_buf.len() as u32 - h.req_contentoff.off() as u32 >= h.req_contentlen {
		h.req_contentoff.set_len(h.req_contentlen as _);
		if h.req_soapActionOff.0 != 0 {
			info!("SOAPAction: {}", h.get_req_str_from(h.req_soapActionOff));
			ExecuteSoapAction(h);
		} else {
			const err400str: &[u8; 38] = b"<html><body>Bad request</body></html>\0";
			info!("No SOAPAction in HTTP headers");
			h.respflags = FLAG_HTML;
			BuildResp2_upnphttp(h, 400, "Bad Request", Some(err400str));
			SendRespAndClose_upnphttp(h);
		}
	} else if GETFLAG!(h.respflags, FLAG_CONTINUE) {
		h.res_buf
			.extend_from_slice(format!("{}  100 Continue\r\n\r\n", h.get_req_str_from(h.HttpVer)).as_bytes());
		h.res_sent = 0;
		h.state = ESendingContinue;
		if SendResp_upnphttp(h) != 0 {
			h.state = EWaitingForHttpContent;
		}
	} else {
		h.state = EWaitingForHttpContent;
	};
}
fn checkCallbackURL(h: &mut upnphttp) -> bool {
	let off = h.req_buf.subslice_offset_stable(h.get_req_str_from(h.req_CallbackOff).trim_matches(&['<', '>']));
	h.req_CallbackOff = off;
	let u = h.get_req_str_from(h.req_CallbackOff);

	if !u.starts_with("http://") {
		return false;
	}
	let u = &u[7..];
	// let ipv6;

	if cfg!(feature = "ipv6") && u.starts_with("[") {
		// ipv6 = true;
		if let Some(i) = u[1..].find("]") {
			if let Ok(addr) = Ipv6Addr::from_str(&u[1..i]) {
				if let Some(v4addr) = addr.to_ipv4_mapped() {
					match &h.clientaddr {
						IpAddr::V4(v4) => v4 == &v4addr,
						IpAddr::V6(v6) => &v6.as_octets()[12..16] == v4addr.as_octets(),
					}
				} else {
					false
				}
			} else {
				false
			}
		} else {
			false
		}
	} else {
		// ipv6 = false;
		if let Some(i) = u.find(":") {
			if let Ok(addr) = Ipv4Addr::from_str(&u[0..i]) {
				if h.clientaddr.is_ipv4()
					&& match h.clientaddr {
						IpAddr::V4(v4) => v4.to_bits() == addr.to_bits(),
						IpAddr::V6(_) => false,
					} {
					true
				} else {
					false
				}
			} else {
				false
			}
		} else {
			false
		}
	}
}
fn ProcessHTTPSubscribe_upnphttp(h: &mut upnphttp, path_off: OffLen) {
	debug!("ProcessHTTPSubscribe {}", h.get_req_str_from(path_off));
	debug!("Callback '{}' Timeout={}", h.req_CallbackOff.0, h.req_Timeout);
	debug!("SID '{}'", h.req_SIDOff.0);
	if h.req_Timeout < 1800 {
		/* Second-infinite is forbidden with UDA v1.1 and later :
		 * (UDA 1.1 : 4.1.1 Subscription)
		 * UPnP 1.1 control points MUST NOT subscribe using keyword infinite,
		 * UPnP 1.1 devices MUST NOT set actual subscription durations to
		 * "infinite". The presence of infinite in a request MUST be silently
		 * ignored by a UPnP 1.1 device (the presence of infinite is handled
		 * by the device as if the TIMEOUT header field in a request was not
		 * present) . The keyword infinite MUST NOT be returned by a UPnP 1.1
		 * device.
		 * Also the device must return a value of minimum 1800 seconds in the
		 * response, according to UDA 1.1 (4.1.2 SUBSCRIBE with NT and CALLBACK):
		 * TIMEOUT
		 *   REQUIRED. Field value contains actual duration until subscription
		 *   expires. Keyword "Second-" followed by an integer (no space).
		 *   SHOULD be greater than or equal to 1800 seconds (30 minutes).*/
		h.req_Timeout = 1800; /* default to 30 minutes */
	}
	if h.req_CallbackOff.0 == 0 && h.req_SIDOff.0 == 0 {
		BuildResp2_upnphttp(h, 412, "Precondition Failed", None);
		SendRespAndClose_upnphttp(h);
		return;
	} else if h.req_CallbackOff.0 != 0 {
		if checkCallbackURL(h) {
			let path = h.get_req_str_from(path_off).to_owned();
			let cb = h.get_req_str_from(h.req_CallbackOff).to_owned();
			let rt = h.rt_options.as_mut().unwrap();
			let sid = upnpevents_addSubscriber(
				&mut rt.subscriber_list,
				path.as_str(),
				cb.as_str(),
				h.req_Timeout as i32,
			);
			h.respflags = FLAG_TIMEOUT;
			if sid.is_some() {
				debug!("generated sid={}", sid.unwrap());
				h.respflags |= FLAG_SID;
				h.res_SID = sid.unwrap();
			}
			BuildResp_upnphttp(h, None);
		} else {
			warn!(
				"Invalid Callback in SUBSCRIBE {}",
				h.get_req_str_from(h.req_CallbackOff)
			);
			BuildResp2_upnphttp(h, 412, "Precondition Failed", None);
		}
	} else if let Ok(uuid) = UUID::from_str(h.get_req_str_from(h.req_SIDOff)) {
		let rt = h.rt_options.as_mut().unwrap();
		let sid = upnpevents_renewSubscription(&mut rt.subscriber_list, &uuid, h.req_Timeout as i32);
		if sid.is_none() {
			BuildResp2_upnphttp(h, 412, "Precondition Failed", None);
		} else {
			h.respflags = FLAG_TIMEOUT | FLAG_SID;
			h.res_SID = uuid;
		}
	}
	SendRespAndClose_upnphttp(h);
}
fn ProcessHTTPUnSubscribe_upnphttp(h: &mut upnphttp, path_off: OffLen) {
	debug!("ProcessHTTPUnSubscribe {}", h.get_req_str_from(path_off));
	debug!("SID '{}'", h.req_SIDOff.0);

	let sid = if let Ok(sid) = UUID::from_str(h.get_req_str_from(h.req_SIDOff)) {
		sid
	} else {
		return;
	};
	let rt = h.rt_options.as_mut().unwrap();
	if upnpevents_removeSubscriber(&mut rt.subscriber_list, &sid) < 0 {
		BuildResp2_upnphttp(h, 412, "Precondition Failed", None);
	} else {
		BuildResp_upnphttp(h, None);
	}
	SendRespAndClose_upnphttp(h);
}

fn ProcessHttpQuery_upnphttp(h: &mut upnphttp) {
	let (command_off, path_off, version_off) = {
		let str = h.req_buf.as_str();
		if let Some((first_line, _)) = str.split_once("\r\n") {
			let mut headers = first_line.split_whitespace();
			let http_command = headers.next();
			let http_path = headers.next();
			let http_version = headers.next();
			if http_command.is_none() || http_path.is_none() || http_version.is_none() {
				Send501(h);
				return;
			}
			(
				h.req_buf.subslice_offset_stable(http_command.unwrap()),
				h.req_buf.subslice_offset_stable(http_path.unwrap()),
				h.req_buf.subslice_offset_stable(http_version.unwrap()),
			)
		} else {
			Send501(h);
			return;
		}
	};
	h.HttpVer = version_off;
	ParseHttpHeaders(h);
	if h.req_HostOff.0 != 0 {
		let req_HostOff = h.get_req_str_from(h.req_HostOff);
		if req_HostOff.as_bytes()[0] == b'[' {
			if let Some(i) = req_HostOff.find(']') {
				h.req_HostOff = h.req_buf.subslice_offset_stable(&req_HostOff[1..i]);
			} else {
				notice!("DNS rebinding attack suspected (Host: {})", h.req_HostOff.0);
				Send404(h);
				return;
			}
		} else if !req_HostOff.chars().all(|x| x.is_ascii_digit() || x == '.' || x == ':') {
			notice!("DNS rebinding attack suspected (Host: {})", req_HostOff);
			Send404(h);
			return;
		}
	}
	let runtime_flags = global_option.get().unwrap().runtime_flag;
	let http_command = h.get_req_str_from(command_off);

	match http_command {
		"POST" => {
			h.req_command = EPost;
			ProcessHTTPPOST_upnphttp(h);
		}
		"GET" => {
			h.req_command = EGet;
			let http_path = h.get_req_str_from(path_off);
			if http_path.len() >= 5 {
				match &http_path[0..5] {
					"/ctl/" => {
						h.respflags = FLAG_ALLOW_POST;
						Send405(h);
						return;
					}
					"/evt/" => {
						/* 405 Method Not Allowed
						 * Allow: SUBSCRIBE, UNSUBSCRIBE */
						h.respflags = FLAG_ALLOW_SUB_UNSUB;
						Send405(h);
						return;
					}
					_ => {}
				}
			}

			match http_path {
				ROOTDESC_PATH => {
					sendXMLdesc(h, genRootDesc, runtime_flags);
				}
				WANIPC_PATH => {
					sendXMLdesc(h, genWANIPCn, runtime_flags);
				}
				WANCFG_PATH => {
					sendXMLdesc(h, genWANCfg, runtime_flags);
				}
				DUMMY_PATH => {}
				L3F_PATH => {
					sendXMLdesc(h, genL3F, runtime_flags);
				}
				#[cfg(feature = "ipv6")]
				WANIP6FC_PATH => {
					sendXMLdesc(h, gen6FC, runtime_flags);
				}
				#[cfg(feature = "_dp_service")]
				DP_PATH => {
					sendXMLdesc(h, genDP, runtime_flags);
				}
				_ => {
					notice!("{} not found, responding ERROR 404", http_path);
					Send404(h);
				}
			};
		}
		"SUBSCRIBE" => {
			h.req_command = ESubscribe;
			ProcessHTTPSubscribe_upnphttp(h, path_off);
		}

		"UNSUBSCRIBE" => {
			h.req_command = EUnSubscribe;
			ProcessHTTPUnSubscribe_upnphttp(h, path_off);
		}
		_ => {
			notice!("Unsupported HTTP command: {}", http_command);
			Send501(h);
		}
	}
}

pub fn Process_upnphttp(h: &mut upnphttp) {
	let mut buf = [MaybeUninit::uninit(); 2048];

	match h.state {
		EWaitingForHttpRequest => {
			let n = match h.recv(&mut buf) {
				Err(e) => {
					if e.kind() != ErrorKind::WouldBlock && e.kind() != ErrorKind::Interrupted {
						error!("recv (state0): {}", e);
						h.state = EToDelete;
					}
					return;
				}
				Ok(n) => {
					if n == 0 {
						warn!("HTTP Connection from {} closed unexpectedly", h.clientaddr);
						h.state = EToDelete;
						return;
					}
					n
				}
			};
			let body = unsafe { mem::transmute::<&[MaybeUninit<u8>], &[u8]>(&buf[..n]) };
			let req_buf = String::from_utf8_lossy(body).to_string();
			if let Some(headerendoff) = req_buf.find("\r\n\r\n") {
				// h.req_contentoff = req_buf.as_str()[headerendoff+4..].trim_start();
				h.req_buf = req_buf;
				// let req_ref = ;

				h.req_contentoff = h.req_buf.subslice_offset_stable(&h.req_buf[headerendoff + 4..]);
				ProcessHttpQuery_upnphttp(h);
			}
		}
		EWaitingForHttpContent => {
			let n = match h.recv(&mut buf) {
				Err(e) => {
					if e.kind() != ErrorKind::WouldBlock && e.kind() != ErrorKind::Interrupted {
						error!("recv (state1): {}", e);
						h.state = EToDelete;
					}
					return;
				}
				Ok(n) => {
					if n == 0 {
						warn!("HTTP Connection from {} closed unexpectedly", h.clientaddr);
						h.state = EToDelete;
						return;
					}
					n
				}
			};
			let data = unsafe { mem::transmute::<&[MaybeUninit<u8>], &[u8]>(&buf[..n]) };
			h.req_buf.push_str(unsafe { str::from_utf8_unchecked(data) });
			if h.req_buf.len() - h.req_contentoff.len() as usize >= h.req_contentlen as usize {
				ProcessHTTPPOST_upnphttp(h);
			}
		}
		ESendingContinue => {
			if SendResp_upnphttp(h) != 0 {
				h.state = EWaitingForHttpContent;
			}
		}
		ESendingAndClosing => SendRespAndClose_upnphttp(h),
		_ => {
			warn!("Unexpected state: {}", h.state);
		}
	}
}

pub fn BuildHeader_upnphttp(h: &mut upnphttp, respcode: i32, respmsg: &str, bodylen: i32) -> i32 {
	h.res_buf.reserve(128 + 256 + bodylen as usize);
	let _ = h.res_buf.extend_from_slice(
		format!(
			"{} {} {}\r\nContent-Type: {}\r\nConnection: close\r\nContent-Length: {}\r\nServer: {}\r\nExt:\r\n",
			h.get_req_str_from(h.HttpVer),
			respcode,
			respmsg,
			if GETFLAG!(h.respflags, FLAG_HTML) {
				"text/html"
			} else {
				"text/xml; charset=\"utf-8\""
			},
			bodylen,
			os_version.get().unwrap_or(&OS_NAME.to_owned())
		)
		.as_bytes(),
	);
	if GETFLAG!(h.respflags, FLAG_TIMEOUT) {
		if h.req_Timeout != 0 {
			h.res_buf.extend_from_slice(format!("{}\r\n", h.req_Timeout).as_bytes());
		} else {
			h.res_buf.extend_from_slice(b"infinite\r\n");
		}
	}
	if GETFLAG!(h.respflags, FLAG_SID) {
		h.res_buf.extend_from_slice(format!("SID: {}", h.res_SID).as_bytes());
	}
	if GETFLAG!(h.respflags, FLAG_ALLOW_POST) {
		h.res_buf.extend_from_slice(b"Allow: SUBSCRIBE, UNSUBSCRIBE\r\n");
	}
	if !h.get_req_str_from(h.accept_language).is_empty() {
		h.res_buf
			.extend_from_slice(format!("Content-Language: {}\r\n", h.get_req_str_from(h.accept_language)).as_bytes());
	}
	h.res_buf.extend_from_slice(b"\r\n");

	0
}

pub fn BuildResp2_upnphttp(h: &mut upnphttp, respcode: i32, respmsg: &str, body: Option<&[u8]>) {
	if let Some(body) = body {
		BuildHeader_upnphttp(h, respcode, respmsg, body.len() as i32);
		h.res_buf.extend_from_slice(body);
	} else {
		BuildHeader_upnphttp(h, respcode, respmsg, 0);
	}
}

pub fn BuildResp_upnphttp(h: &mut upnphttp, body: Option<&[u8]>) {
	BuildResp2_upnphttp(h, 200, "OK", body);
}

pub fn SendResp_upnphttp(h: &mut upnphttp) -> i32 {
	while h.res_sent < (h.res_buf.len() as i32) {
		match h.send(&h.res_buf.as_slice()[h.res_sent as usize..]) {
			Ok(n) => {
				if n == 0 {
					error!("send(res_buf): {} bytes sent (out of {})", h.res_sent, h.res_buf.len());
					break;
				}
				h.res_sent += n as i32;
			}
			Err(e) => {
				if e.kind() == ErrorKind::Interrupted {
					/* try again immediately */
					continue;
				}
				if e.kind() == ErrorKind::WouldBlock {
					/* try again later */
					return 0;
				}
				error!("send(res_buf): {}", e);
				break; /* avoid infinite loop */
			}
		}
	}
	1 /* finished */
}

pub fn SendRespAndClose_upnphttp(h: &mut upnphttp) {
	if SendResp_upnphttp(h) != 0 {
		CloseSocket_upnphttp(h);
	} else {
		h.state = ESendingAndClosing;
	};
}
#[cfg(test)]
mod tests {

	use super::*;
	#[test]
	fn test_checkCallbackURL() {
		let clientaddr = Ipv4Addr::new(192, 168, 1, 2).into();
		let mut h = New_upnphttp(
			socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap(),
			clientaddr,
		);

		h.req_buf = "<http://192.168.1.2:1820/xxxx>".to_string();

		h.req_CallbackOff = h.req_buf.as_str().subslice_offset_stable(h.req_buf.as_str());
		assert_ne!(h.req_CallbackOff.0, 0);
		assert!(checkCallbackURL(&mut h))
	}
}
