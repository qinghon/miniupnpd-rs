use crate::linux::netfilter::mnl::{mnl_socket, mnl_socket_bind, mnl_socket_get_portid};
use std::ptr::NonNull;

#[cfg(conntrack = "nfct")]
pub(crate) mod netfilter_conntrack {
	#![allow(
		dead_code,
		mutable_transmutes,
		non_camel_case_types,
		non_snake_case,
		non_upper_case_globals,
		unused_assignments,
		unused_mut,
		unsafe_op_in_unsafe_fn
	)]
	use libc::nlmsghdr;
	include!(concat!(env!("OUT_DIR"), "/libnetfilter_conntrack.rs"));
}

use self::netfilter_conntrack::*;
#[cfg(conntrack = "nfct")]
pub(crate) mod nfnetlink {
	#![allow(
		dead_code,
		mutable_transmutes,
		non_camel_case_types,
		non_snake_case,
		non_upper_case_globals,
		unused_assignments,
		unused_mut,
		unsafe_op_in_unsafe_fn
	)]
	use libc::{iovec, nlmsghdr};
	include!(concat!(env!("OUT_DIR"), "/libnfnetlink.rs"));
}

pub mod mnl {
	#![allow(
		dead_code,
		mutable_transmutes,
		non_camel_case_types,
		non_snake_case,
		non_upper_case_globals,
		unused_assignments,
		unused_mut
	)]
	include!(concat!(env!("OUT_DIR"), "/mnl.rs"));
}
#[cfg(conntrack = "nfct")]
pub(crate) struct NfConntrack(NonNull<nf_conntrack>);
#[cfg(conntrack = "nfct")]
impl NfConntrack {
	pub fn new() -> Option<Self> {
		unsafe {
			let conn = nfct_new();
			if conn.is_null() {
				None
			} else {
				Some(NfConntrack(NonNull::new_unchecked(conn)))
			}
		}
	}
	pub fn set_attr_u32(&self, attr: u32, val: u32) {
		unsafe { nfct_set_attr_u32(self.0.as_ptr(), attr, val) }
	}
	pub fn set_attr_u16(&self, attr: u32, val: u16) {
		unsafe { nfct_set_attr_u16(self.0.as_ptr(), attr, val) }
	}
	pub fn set_attr_u8(&self, attr: u32, val: u8) {
		unsafe { nfct_set_attr_u8(self.0.as_ptr(), attr, val) }
	}
	pub fn set_attr(&self, attr: u32, val: *const u8) {
		unsafe { nfct_set_attr(self.0.as_ptr(), attr, val as _) }
	}
	pub fn as_ptr(&self) -> *mut nf_conntrack {
		self.0.as_ptr()
	}
	pub fn get_attr_u32(&self, attr: u32) -> u32 {
		unsafe { nfct_get_attr_u32(self.0.as_ptr(), attr) }
	}
	pub fn get_attr_u16(&self, attr: u32) -> u16 {
		unsafe { nfct_get_attr_u16(self.0.as_ptr(), attr) }
	}
}
#[cfg(conntrack = "nfct")]
impl Drop for NfConntrack {
	fn drop(&mut self) {
		unsafe {
			nfct_destroy(self.0.as_ptr());
		}
	}
}
#[repr(transparent)]
pub(crate) struct MnlSocket(NonNull<mnl_socket>);
impl MnlSocket {
	pub fn open(bus: libc::c_int) -> Option<Self> {
		unsafe {
			let sock = mnl::mnl_socket_open(bus);
			if sock.is_null() {
				None
			} else {
				Some(MnlSocket(NonNull::new_unchecked(sock)))
			}
		}
	}
	pub fn bind(&self, groups: libc::c_uint, pid: libc::pid_t) -> i32 {
		unsafe { mnl_socket_bind(self.0.as_ptr(), groups, pid) }
	}
	pub fn get_portid(&self) -> u32 {
		unsafe { mnl_socket_get_portid(self.0.as_ptr()) }
	}
	pub fn as_ptr(&self) -> *const mnl_socket {
		self.0.as_ptr()
	}
}
impl Drop for MnlSocket {
	fn drop(&mut self) {
		unsafe {
			mnl::mnl_socket_close(self.0.as_ptr());
		}
	}
}
