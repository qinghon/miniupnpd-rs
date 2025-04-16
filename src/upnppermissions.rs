#![allow(unused_variables)]

#[derive(Clone, PartialEq, Debug)]
#[repr(C)]
pub struct upnpperm {
	pub type_0: UPNPPERM,
	pub eport_min: u16,
	pub eport_max: u16,
	pub address: Ipv4Addr,
	pub mask: Ipv4Addr,
	pub iport_min: u16,
	pub iport_max: u16,
	#[cfg(feature = "re")]
	pub re: String,
}
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum UPNPPERM {
	UPNPPERM_ALLOW,
	UPNPPERM_DENY,
}

impl FromStr for upnpperm {
	type Err = io::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let tokens = s.split_whitespace().collect::<Vec<_>>();
		match tokens.as_slice() {
			[ad, port_range, ip_mask, ext_port_range, ..] => {
				let action = match ad {
					&"allow" => UPNPPERM_ALLOW,
					&"deny" => UPNPPERM_DENY,
					_ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid upnpperm")),
				};
				let (imin_str, imax_str) = port_range.split_once('-').ok_or(io::Error::new(
					io::ErrorKind::InvalidInput,
					"invalid upnpperm port range",
				))?;
				let (emin_str, emax_str) = ext_port_range.split_once('-').ok_or(io::Error::new(
					io::ErrorKind::InvalidInput,
					"invalid upnpperm port range",
				))?;

				let eport_min = emin_str
					.parse::<u16>()
					.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid upnpperm port range min"))?;
				let eport_max = emax_str
					.parse::<u16>()
					.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid upnpperm port range max"))?;

				let iport_min = imin_str
					.parse::<u16>()
					.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid upnpperm port range min"))?;
				let iport_max = imax_str
					.parse::<u16>()
					.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid upnpperm port range max"))?;

				let ipmask = ipnet::Ipv4Net::from_str(ip_mask)
					.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid upnpperm ipmask"))?;

				let r = Self {
					type_0: action,

					eport_min,
					eport_max,
					address: ipmask.addr(),
					mask: ipmask.netmask(),
					iport_min,
					iport_max,
					#[cfg(feature = "re")]
					re: "".to_string(),
				};
				trace!("perm rule added: {:?}", r);
				Ok(r)
			}
			_ => Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid upnpperm")),
		}
	}
}

use crate::debug;
use UPNPPERM::*;
use std::cmp::PartialEq;
use std::io;
use std::net::Ipv4Addr;
use std::str::FromStr;

pub fn read_permission_line(p: &str) -> Result<upnpperm, io::Error> {
	upnpperm::from_str(p)
}

pub fn free_permission_line(_perm: upnpperm) {}
fn match_permission(perm: &upnpperm, eport: u16, address: Ipv4Addr, iport: u16, desc: &str) -> bool {
	if eport < perm.eport_min || perm.eport_max < eport {
		return false;
	}
	if iport < perm.iport_min || (perm.iport_max) < iport {
		return false;
	}
	if address & perm.mask != perm.address & perm.mask {
		return false;
	}
	true
}

pub fn check_upnp_rule_against_permissions(
	permarys: &[upnpperm],
	eport: u16,
	address: Ipv4Addr,
	iport: u16,
	desc: &str,
) -> bool {
	let mut i = 0;
	for permary in permarys {
		if match_permission(permary, eport, address, iport, desc) {
			debug!(
				"UPnP permission rule {} matched : port mapping {}",
				i,
				if permary.type_0 == UPNPPERM_ALLOW {
					"accepted"
				} else {
					"rejected"
				}
			);
			return permary.type_0 == UPNPPERM_ALLOW;
		}
		i += 1;
	}
	debug!(
		"no permission rule matched : accept by default (n_perms={})",
		permarys.len()
	);
	true /* Default : accept */
}

pub struct AllowBitMap([u32; 65536 / 32]);
impl Default for AllowBitMap {
	#[inline]
	fn default() -> Self {
		Self([0; 65536 / 32])
	}
}
impl AllowBitMap {
	#[inline]
	pub fn set(&mut self, index: u16) {
		self.0[index as usize / 32] |= 1 << (index % 32);
	}
	#[inline]
	pub fn get(&mut self, index: u16) -> bool {
		self.0[index as usize / 32] & (1 << (index % 32)) != 0
	}
	#[inline]
	pub fn clear(&mut self, index: u16) {
		self.0[index as usize / 32] &= !(1 << (index % 32));
	}
}

pub fn get_permitted_ext_ports(allowed: &mut AllowBitMap, permary: &[upnpperm], addr: Ipv4Addr, iport: u16) {
	for perm in permary {
		if addr & perm.mask != perm.address & perm.mask {
			continue;
		}
		if iport < perm.iport_min || (perm.iport_max < iport) {
			continue;
		}
		for j in perm.eport_min..=perm.eport_max {
			if perm.type_0 == UPNPPERM_ALLOW {
				allowed.set(j);
			} else {
				allowed.clear(j);
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn test_upnpperm_parse() {
		let allow = upnpperm::from_str("allow 1024-65535 0.0.0.0/0 1024-65535");
		let deny = upnpperm::from_str("deny 0-65535 0.0.0.0/0 0-65535");
		assert!(allow.is_ok());
		assert!(deny.is_ok());
		let allow = allow.unwrap();
		let deny = deny.unwrap();

		assert_eq!(
			allow,
			upnpperm {
				type_0: UPNPPERM_ALLOW,
				eport_min: 1024,
				eport_max: 65535,
				address: Ipv4Addr::UNSPECIFIED,
				mask: Ipv4Addr::UNSPECIFIED,
				iport_min: 1024,
				iport_max: 65535,
				#[cfg(feature = "re")]
				re: "".to_string(),
			}
		);
		assert_eq!(
			deny,
			upnpperm {
				type_0: UPNPPERM_DENY,
				eport_min: 0,
				eport_max: 65535,
				address: Ipv4Addr::UNSPECIFIED,
				mask: Ipv4Addr::UNSPECIFIED,
				iport_min: 0,
				iport_max: 65535,
				#[cfg(feature = "re")]
				re: "".to_string(),
			}
		);
		assert!(upnpperm::from_str("allow 1024- 0.0.0.0/0 1024-65535").is_err());
		assert!(upnpperm::from_str("allow -65535 0.0.0.0/0 1024-65535").is_err());
		assert!(upnpperm::from_str("allow 1024-65535 0.0.0.0/0 1024-").is_err());
		assert!(upnpperm::from_str("allow 1024-65535 0.0.0.0/0 -65535").is_err());
		assert!(upnpperm::from_str("allow 1024-65535 0.0.0.0/33 1024-65535").is_err());
		assert!(upnpperm::from_str("allow 1024-65535x 0.0.0.0/0 1024-65535").is_err());
		assert!(upnpperm::from_str("allowed 1024-65535 0.0.0.0/0 1024-65535").is_err());
		assert!(upnpperm::from_str("allow 1024-65535 [::]/0 1024-65535").is_err());
		assert!(upnpperm::from_str("deay 1024-65535 0.0.0.0/0 1024-65535").is_err());
	}
	#[test]
	fn test_upnpperm_match() {
		let perms = [
			upnpperm {
				type_0: UPNPPERM_ALLOW,
				eport_min: 1024,
				eport_max: 65535,
				address: Ipv4Addr::UNSPECIFIED,
				mask: Ipv4Addr::UNSPECIFIED,
				iport_min: 0,
				iport_max: 65535,
				#[cfg(feature = "re")]
				re: "".to_string(),
			},
			upnpperm {
				type_0: UPNPPERM_DENY,
				eport_min: 0,
				eport_max: 65535,
				address: Ipv4Addr::UNSPECIFIED,
				mask: Ipv4Addr::UNSPECIFIED,
				iport_min: 0,
				iport_max: 65535,
				#[cfg(feature = "re")]
				re: "".to_string(),
			},
		];
		assert_eq!(
			check_upnp_rule_against_permissions(&perms, 1684, "192.168.1.2".parse().unwrap(), 1684, ""),
			true
		);
		assert_eq!(
			check_upnp_rule_against_permissions(&perms, 1000, "192.168.1.2".parse().unwrap(), 1684, ""),
			false
		);
	}
}
