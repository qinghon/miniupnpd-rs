use crate::getifstats::ifdata;
use crate::linux::getifstats::getifstats;
use crate::*;
#[cfg(feature = "portinuse")]
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use std::time::Duration;

pub struct linux;

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
		todo!()
	}
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
