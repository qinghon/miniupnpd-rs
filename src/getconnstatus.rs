use crate::getifaddr::*;
use crate::warp::IfName;
use std::net::Ipv4Addr;

pub(crate) const STATUS_UNCONFIGURED:u8 = 0;
pub(crate) const STATUS_CONNECTING:u8 = 1;
pub(crate) const STATUS_CONNECTED:u8 = 2;
pub(crate) const STATUS_PENDINGDISCONNECT:u8 = 3;
pub(crate) const STATUS_DISCONNECTING:u8 = 4;
pub(crate) const STATUS_DISCONNECTED:u8 = 5;


pub fn get_wan_connection_status(ifname: &IfName) -> u8 {
	let mut addr = Ipv4Addr::UNSPECIFIED;
	match getifaddr(ifname, &mut addr, None) as _ {
		GETIFADDR_OK =>  STATUS_CONNECTED,
		GETIFADDR_NO_ADDRESS|GETIFADDR_IF_DOWN => STATUS_DISCONNECTED,
		_ => STATUS_UNCONFIGURED
	}
}

pub fn get_wan_connection_status_str(ifname: &IfName) -> &'static str {
	match get_wan_connection_status(ifname) {
		STATUS_UNCONFIGURED => "Unconfigured",
		STATUS_CONNECTING => "Connecting",
		STATUS_CONNECTED => "Connected",
		STATUS_DISCONNECTED => "Disconnected",
		STATUS_DISCONNECTING => "Disconnecting",
		STATUS_PENDINGDISCONNECT => "PendingDisconnect",
		_ => "Unknown"
		
	}
}
