use crate::OS;
use std::time::Instant;

pub struct solaris;

impl OS for solaris {
	fn os_type(&self) -> &'static str {
		todo!()
	}

	fn os_version(&self) -> &'static str {
		todo!()
	}

	fn uptime(&self) -> Instant {
		todo!()
	}
}
