use crate::{IfName, nat_impl};
use std::net::Ipv4Addr;

fn port_in_use(_nat: &nat_impl, if_name: &IfName, eport: u16, proto: u8, iaddr: &Ipv4Addr, iport: u16) -> i32 {
	unimplemented!()
}
