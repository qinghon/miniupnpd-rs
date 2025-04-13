// use crate::log;
use std::net::SocketAddr;
use std::time;
use std::time::{Duration, Instant, UNIX_EPOCH};
// use crate::debug;
use crate::linux::getroute::get_src_for_route_to;
use crate::options::Options;
use crate::upnpglobalvars::{lan_addr_s, startup_time};

pub fn get_lan_for_peer<'a>(v: &'a Options, peer: &SocketAddr) -> Option<&'a lan_addr_s> {
	match peer {
		SocketAddr::V4(v4) => v
			.listening_ip
			.iter()
			.find(|x| (x.mask.to_bits() & v4.ip().to_bits()) == (x.addr.to_bits() & x.mask.to_bits())),
		SocketAddr::V6(v6) => {
			if let Some(v4) = v6.ip().to_ipv4_mapped() {
				v.listening_ip
					.iter()
					.find(|x| (x.mask.to_bits() & v4.to_bits()) == (x.addr.to_bits() & x.mask.to_bits()))
			} else {
				let index = if v6.scope_id() > 0 {
					v6.scope_id()
				} else {
					let i = get_src_for_route_to(&peer.ip(), None);
					if i < 0 {
						return None;
					}
					i as u32
				};
				debug!("get_lan_for_peer() looking for LAN interface index={}", index);
				v.listening_ip.iter().find(|x| x.index == index)
			}
		}
	}
}

pub fn upnp_time() -> Duration {
	time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

pub fn upnp_get_uptime() -> Duration {
	upnp_time() - *startup_time.get().unwrap()
}

pub fn upnp_gettimeofday() -> Instant {
	Instant::now()
}
