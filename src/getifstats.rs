#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct ifdata {
	pub opackets: u64,
	pub ipackets: u64,
	pub obytes: u64,
	pub ibytes: u64,
	pub baudrate: u64,
}
