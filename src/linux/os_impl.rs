#[cfg(feature = "portinuse")]
use super::portinuse::port_in_use;
use crate::getifstats::ifdata;
use crate::linux::getifstats::getifstats;
use crate::*;
use std::cmp::min;

use crate::linux::netfilter::mnl::{MNL_CB_OK, MNL_CB_STOP, mnl_cb_run, mnl_socket_recvfrom, mnl_socket_sendto};
use libc::{NFNETLINK_V0, NFNL_SUBSYS_CTNETLINK, NLM_F_ACK, NLM_F_REQUEST, nlmsghdr};

use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::RawFd;
use std::ptr;
use std::time::Duration;

pub fn page_size() -> usize {
	static mut PAGE_SIZE: usize = 0;
	unsafe {
		if PAGE_SIZE == 0 {
			let size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
			PAGE_SIZE = size;
		}
	}
	unsafe { PAGE_SIZE }
}

pub struct linux;

impl Default for linux {
    fn default() -> Self {
        Self::new()
    }
}

impl linux {
	pub const fn new() -> Self {
		Self {}
	}
}

impl OS for linux {
	fn os_type(&self) -> &'static str {
		todo!()
	}

	fn os_version(&self) -> &'static str {
		todo!()
	}
	#[inline(never)]
	fn uptime(&self) -> Duration {
		let f = unsafe { libc::fopen(c"/proc/uptime".as_ptr(), c"r".as_ptr()) };
		if !f.is_null() {
			let mut uptime = 0;
			if unsafe { libc::fscanf(f, c"%lu".as_ptr(), &mut uptime) } < 0 {
				error!("fscanf(\"/proc/uptime\") : %m");
			} else {
				info!("system uptime is {} seconds", uptime);
			}
			unsafe { libc::fclose(f) };
			return Duration::from_secs(uptime);
		}

		Duration::new(0, 0)
	}

	fn OpenAndConfInterfaceWatchSocket(&self) -> Option<RawFd> {
		self.OpenAndConfInterfaceWatchSocket_()
	}

	fn ProcessInterfaceWatchNotify(&self, ifname: &IfName, fd: RawFd, need_change: &mut bool) {
		self.ProcessInterfaceWatchNotify_(ifname, fd, need_change);
	}

	fn getifstats(&self, if_name: &IfName, data: &mut ifdata) -> i32 {
		getifstats(if_name, data)
	}
	#[cfg(feature = "portinuse")]
	fn port_in_use(
		&self,
		nat: &nat_impl,
		if_name: &IfName,
		eport: u16,
		proto: u8,
		iaddr: &Ipv4Addr,
		iport: u16,
	) -> i32 {
		port_in_use(nat, if_name, eport, proto, iaddr, iport)
	}

	fn get_nat_ext_addr(src: Option<SocketAddr>, dst: Option<SocketAddr>, proto: u8) -> Option<SocketAddr> {
		get_nat_ext_addr(src, dst, proto)
	}
}

#[cfg(conntrack = "proc")]
pub(crate) fn get_nat_ext_addr(src: Option<SocketAddr>, dst: Option<SocketAddr>, proto: u8) -> Option<SocketAddr> {
	use std::fs::File;
	use std::io::{BufRead, BufReader};
	use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

	const DST: &str = "dst=";
	const DST_PORT: &str = "dport=";
	const SRC: &str = "src=";
	const SRC_PORT: &str = "sport=";
	const IP_CONNTRACK_LOCATION: &str = "/proc/net/ip_conntrack";
	const NF_CONNTRACK_LOCATION: &str = "/proc/net/nf_conntrack";

	let src = src?;
	let af = match src.ip() {
		IpAddr::V4(_) => libc::AF_INET,
		IpAddr::V6(_) => libc::AF_INET6,
	};

	let file = File::open(NF_CONNTRACK_LOCATION).or_else(|_| File::open(IP_CONNTRACK_LOCATION)).ok()?;
	let reader = BufReader::new(file);

	for line in reader.lines().flatten() {
		let mut tokens = line.split_whitespace();
		if tokens.nth(1).and_then(|t| t.parse::<i32>().ok()) != Some(af) {
			continue;
		}
		if tokens.nth(1).and_then(|t| t.parse::<u8>().ok()) != Some(proto) {
			continue;
		}

		let mut src_f = false;
		let mut src_port_f = false;
		let mut dst_f = false;
		let mut dst_port_f = false;
		let mut ret_ext: Option<SocketAddr> = None;

		for token in tokens {
			if let Some(src_ip) = token.strip_prefix(SRC) {
				if src.ip().to_string() == src_ip {
					src_f = true;
				}
			} else if let Some(src_port) = token.strip_prefix(SRC_PORT) {
				if src.port().to_string() == src_port {
					src_port_f = true;
				}
			} else if let Some(dst_ip) = token.strip_prefix(DST) {
				if let Ok(ip) = dst_ip.parse::<Ipv4Addr>() {
					if let Some(dst) = dst {
						if dst.ip() == IpAddr::V4(ip) {
							dst_f = true;
						} else {
							ret_ext = Some(SocketAddr::new(IpAddr::V4(ip), 0));
						}
					}
				}
			} else if let Some(dst_port) = token.strip_prefix(DST_PORT) {
				if let Ok(port) = dst_port.parse::<u16>() {
					if let Some(dst) = dst {
						if dst.port() == port {
							dst_port_f = true;
						} else if let Some(ref mut ret_ext) = ret_ext {
							*ret_ext = SocketAddr::new(ret_ext.ip(), port);
						}
					}
				}
			}
		}

		if src_f && src_port_f && dst_f && dst_port_f {
			return ret_ext;
		}
	}

	None
}

#[cfg(conntrack = "nfct")]
struct data_cb_s {
	pub ext: Option<SocketAddr>,
}
#[cfg(conntrack = "nfct")]
unsafe extern "C" fn data_cb(nlh_ptr: *const nlmsghdr, data_ptr: *mut libc::c_void) -> i32 {
	use super::netfilter::NfConntrack;
	use super::netfilter::netfilter_conntrack::*;
	let ct = match NfConntrack::new() {
		None => return MNL_CB_OK as _,
		Some(v) => v,
	};
	unsafe { nfct_nlmsg_parse(nlh_ptr, ct.as_ptr()) };
	if !data_ptr.is_null() {
		let data = unsafe { &mut *(data_ptr as *mut data_cb_s) };
		data.ext.replace(
			SocketAddrV4::new(
				ct.get_attr_u32(ATTR_REPL_IPV4_DST).into(),
				ct.get_attr_u16(ATTR_REPL_PORT_DST),
			)
			.into(),
		);
	}

	MNL_CB_OK as _
}

#[cfg(conntrack = "nfct")]
pub(crate) fn get_nat_ext_addr(src: Option<SocketAddr>, dst: Option<SocketAddr>, proto: u8) -> Option<SocketAddr> {
	use super::netfilter::netfilter_conntrack::*;
	use super::netfilter::nfnetlink::nfgenmsg;
	use super::netfilter::{MnlSocket, NfConntrack, mnl};
	let nl = MnlSocket::open(libc::NETLINK_NETFILTER)?;

	if nl.bind(0, mnl::MNL_SOCKET_AUTOPID as libc::pid_t) < 0 {
		return None;
	}
	let port_id = nl.get_portid();
	let src = src?;
	let dst = dst?;
	let af = if src.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };

	unsafe {
		let seq = libc::time(ptr::null_mut());
		let mut buf = vec![0u8; min(page_size(), 8192)];
		let nlh_ptr = mnl::mnl_nlmsg_put_header(buf.as_mut_ptr() as _);
		let nlh = &mut *nlh_ptr;
		nlh.nlmsg_type = (((NFNL_SUBSYS_CTNETLINK as u32) << 8) | IPCTNL_MSG_CT_GET) as u16;
		nlh.nlmsg_flags = (NLM_F_REQUEST | NLM_F_ACK) as _;
		nlh.nlmsg_seq = seq as _;

		let nfh_ptr = mnl::mnl_nlmsg_put_extra_header(nlh_ptr, size_of::<nfgenmsg>()) as *mut nfgenmsg;
		let nfh = &mut *nfh_ptr;
		nfh.nfgen_family = af as _;
		nfh.version = NFNETLINK_V0 as _;
		nfh.res_id = 0;

		let ct = NfConntrack::new()?;

		ct.set_attr_u8(ATTR_L3PROTO, af as _);
		match (&src, &dst) {
			(SocketAddr::V4(sv4), SocketAddr::V4(dv4)) => {
				ct.set_attr_u32(ATTR_IPV4_SRC, sv4.ip().to_bits().to_be());
				ct.set_attr_u32(ATTR_IPV4_DST, dv4.ip().to_bits().to_be());
				ct.set_attr_u16(ATTR_PORT_SRC, sv4.port());
				ct.set_attr_u16(ATTR_PORT_DST, dv4.port());
			}
			(SocketAddr::V6(sv6), SocketAddr::V6(dv6)) => {
				ct.set_attr(ATTR_IPV6_SRC, sv6.ip().as_octets().as_ptr());
				ct.set_attr(ATTR_IPV6_DST, dv6.ip().as_octets().as_ptr());
				ct.set_attr_u16(ATTR_PORT_SRC, sv6.port());
				ct.set_attr_u16(ATTR_PORT_DST, dv6.port());
			}
			_ => {}
		}
		ct.set_attr_u8(ATTR_L4PROTO, proto);
		nfct_nlmsg_build(nlh_ptr, ct.as_ptr());

		let mut ret = mnl_socket_sendto(nl.as_ptr(), nlh_ptr as _, nlh.nlmsg_len as _);

		if ret == -1 {
			return None;
		}
		ret = mnl_socket_recvfrom(nl.as_ptr(), buf.as_mut_ptr() as _, buf.capacity());
		let mut data = data_cb_s { ext: None };
		while ret > 0 {
			ret = mnl_cb_run(
				buf.as_ptr() as _,
				ret as _,
				seq as _,
				port_id,
				Some(data_cb),
				ptr::from_mut(&mut data) as _,
			) as _;
			if ret <= MNL_CB_STOP as _ {
				break;
			}
			ret = mnl_socket_recvfrom(nl.as_ptr(), buf.as_mut_ptr() as _, buf.capacity());
		}
	}

	None
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::OS;

	#[test]
	fn test_uptime() {
		let l = linux {};
		assert_ne!(l.uptime(), Duration::new(0, 0));
	}
}
