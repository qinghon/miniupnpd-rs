use crate::*;
use once_cell::sync::OnceCell;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicU32;
use std::time::Duration;
use uuid::UUID;
#[derive(Clone, Debug)]
#[repr(C)]
pub struct lan_addr_s {
	pub ifname: IfName,
	pub index: u32,
	pub addr: Ipv4Addr,
	pub mask: Ipv4Addr,
	#[cfg(feature = "multiple_ext_ip")]
	pub ext_ip_addr: Ipv4Addr,

	pub add_indexes: u64,
}
impl Default for lan_addr_s {
	fn default() -> Self {
		Self {
			ifname: Default::default(),
			index: 0,
			addr: Ipv4Addr::UNSPECIFIED,
			mask: Ipv4Addr::UNSPECIFIED,
			add_indexes: 0,
			#[cfg(feature = "multiple_ext_ip")]
			ext_ip_addr: Ipv4Addr::UNSPECIFIED,
		}
	}
}

pub static startup_time: OnceCell<Duration> = OnceCell::new();

pub const LOGPACKETSMASK: u32 = 0x0001;
pub const SYSUPTIMEMASK: u32 = 0x0002;
pub const ENABLENATPMPMASK: u32 = 0x0004;
pub const CHECKCLIENTIPMASK: u32 = 0x0008;
pub const SECUREMODEMASK: u32 = 0x0010;
pub const ENABLEUPNPMASK: u32 = 0x0020;
pub const PFNOQUICKRULESMASK: u32 = 0x0040;
pub const IPV6DISABLEDMASK: u32 = 0x0080;
pub const IPV6FCFWDISABLEDMASK: u32 = 0x0100;
pub const IPV6FCINBOUNDDISALLOWEDMASK: u32 = 0x0200;
pub const PCP_ALLOWTHIRDPARTYMASK: u32 = 0x0400;
pub const FORCEIGDDESCV1MASK: u32 = 0x0800;
pub const PERFORMSTUNMASK: u32 = 0x1000;
pub const ALLOWPRIVATEIPV4MASK: u32 = 0x2000;
pub const ALLOWFILTEREDSTUNMASK: u32 = 0x4000;

#[macro_export]
macro_rules! SETFLAG {
	($flag:expr, $mask:expr) => {
		$flag |= $mask
	};
}
#[macro_export]
macro_rules! DELFLAG {
    ($flag:expr, $mask:expr) => {
        $flag &= ~$mask
    };
}
#[macro_export]
macro_rules! GETFLAG {
	($flag:expr, $mask:expr) => {
		$flag & $mask != 0
	};
}

pub static uuidvalue_igd: OnceCell<UUID> = OnceCell::new();
pub static uuidvalue_wan: OnceCell<UUID> = OnceCell::new();
pub static uuidvalue_wcd: OnceCell<UUID> = OnceCell::new();

pub static modelnumber: OnceCell<Box<str>> = OnceCell::new();
pub static serialnumber: OnceCell<Box<str>> = OnceCell::new();
pub static presentationurl: OnceCell<Box<str>> = OnceCell::new();

#[cfg(feature = "randomurl")]
pub static random_url: OnceCell<Box<str>> = OnceCell::new();

pub static ipv6_addr_for_http_with_brackets: OnceCell<Ipv6Addr> = OnceCell::new();

pub static ipv6_bind_addr: Ipv6Addr = Ipv6Addr::UNSPECIFIED;

/// BOOTID.UPNP.ORG and CONFIGID.UPNP.ORG
/// See UPnP Device Architecture v1.1 section 1.2 Advertisement :
/// The field value of the BOOTID.UPNP.ORG header field MUST be increased
/// each time a device (re)joins the network and sends an initial announce
/// (a "reboot" in UPnP terms), or adds a UPnP-enabled interface.
///
/// Unless the device explicitly announces a change in the BOOTID.UPNP.ORG
/// field value using an SSDP message, as long as the device remains
/// continuously available in the network, the same BOOTID.UPNP.ORG field
/// value MUST be used in all repeat announcements, search responses,
/// update messages and eventually bye-bye messages.
pub static upnp_bootid: AtomicU32 = AtomicU32::new(1); /* BOOTID.UPNP.ORG */

/// The field value of the CONFIGID.UPNP.ORG header field identifies the
/// current set of device and service descriptions; control points can
/// parse this header field to detect whether they need to send new
/// description query messages.
///
/// UPnP 1.1 devices MAY freely assign configid numbers from 0 to
/// 16777215 (2^24-1). Higher numbers are reserved for future use, and
/// can be assigned by the Technical Committee. The configuration of a
/// root device consists of the following information: the DDD of the
/// root device and all its embedded devices, and the SCPDs of all the
/// contained services. If any part of the configuration changes, the
/// CONFIGID.UPNP.ORG field value MUST be changed.
/// DDD = Device Description Document
/// SCPD = Service Control Protocol Description
pub const upnp_configid: u32 = 1337; /* CONFIGID.UPNP.ORG */

pub static os_version: OnceCell<Box<str>> = OnceCell::new();

pub static global_option: OnceCell<options::Options> = OnceCell::new();
