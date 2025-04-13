use crate::getifaddr::getifaddr;
use crate::warp::IfName;
use std::net::Ipv4Addr;

pub fn get_wan_connection_status(ifname: &IfName) -> bool {
	let mut addr = Ipv4Addr::UNSPECIFIED;
	getifaddr(ifname, &mut addr, None) == 0
}

pub fn get_wan_connection_status_str(ifname: &IfName) -> &'static str {
	if get_wan_connection_status(ifname) {
		"Connected"
	} else {
		"Disconnected"
	}
}
