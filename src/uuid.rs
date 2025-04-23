#[cfg(uuid = "libuuid")]
use libc::c_int;
use std::fmt::{Display, Formatter};
use std::mem::MaybeUninit;
use std::str::FromStr;
use std::{io, ptr};
#[cfg(uuid = "libuuid")]
unsafe extern "C" {
	pub(super) fn uuid_parse(buf: *const u8, uu: *mut UUID) -> c_int;
	pub(super) fn uuid_unparse(uu: *const UUID, buf: *mut u8);
	pub(super) fn uuid_generate(out: *mut u8);
}

#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
#[repr(C)]
pub struct UUID(pub [u8; 16]);

impl FromStr for UUID {
	type Err = io::Error;
	#[cfg(uuid = "native")]
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.len() != 36 {
			return Err(io::ErrorKind::InvalidInput.into());
		}
		let mut u = [0u8; 16];
		fn fill_buf_from_str(s: Option<&str>, buf: &mut [u8]) -> io::Result<()> {
			if let Some(s) = s {
				for i in 0..s.len() / 2 {
					buf[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| io::ErrorKind::InvalidInput)?;
				}
			} else {
				return Err(io::ErrorKind::InvalidInput.into());
			}
			Ok(())
		}
		let mut ss = s.split('-');
		fill_buf_from_str(ss.next(), &mut u[0..4])?;
		fill_buf_from_str(ss.next(), &mut u[4..6])?;
		fill_buf_from_str(ss.next(), &mut u[6..8])?;
		fill_buf_from_str(ss.next(), &mut u[8..10])?;
		fill_buf_from_str(ss.next(), &mut u[10..16])?;

		Ok(Self(u))
	}
	#[cfg(uuid = "libuuid")]
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.len() != 36 {
			return Err(io::ErrorKind::InvalidInput.into());
		}
		let mut buf: MaybeUninit<[u8; 37]> = MaybeUninit::uninit();
		let mut u: MaybeUninit<Self> = MaybeUninit::uninit();

		unsafe {
			ptr::copy_nonoverlapping(s.as_ptr(), buf.as_mut_ptr() as *mut u8, s.len());
			let mut buf = buf.assume_init();
			buf[36] = 0;
			if uuid_parse(buf.as_ptr(), u.as_mut_ptr() as _) == -1 {
				return Err(io::Error::last_os_error());
			}
		}
		Ok(unsafe { u.assume_init() })
	}
}
impl Display for UUID {
	#[cfg(uuid = "native")]
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut buf: [u8; 36] = [0; 36];
		buf[8] = b'-';
		buf[13] = b'-';
		buf[18] = b'-';
		buf[23] = b'-';
		const hex_table: [u8; 16] = [
			b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f',
		];
		let mut j: usize = 0;
		for x in 0..16 {
			if x == 4 || x == 6 || x == 8 || x == 10 {
				j += 1;
			}
			buf[j + x * 2] = hex_table[(self.0[x] >> 4) as usize];
			buf[j + x * 2 + 1] = hex_table[(self.0[x] & 0xF) as usize];
		}

		f.write_str(unsafe { str::from_utf8_unchecked(&buf) })
	}
	#[cfg(uuid = "libuuid")]
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		use std::mem::MaybeUninit;
		let mut buf: MaybeUninit<[u8; 37]> = MaybeUninit::uninit();
		unsafe {
			uuid_unparse(self as _, buf.as_mut_ptr() as *mut _);
		}
		let buf = unsafe { buf.assume_init() };
		f.write_str(unsafe { str::from_utf8_unchecked(&buf[0..36]) })
	}
}

impl From<[u8; 16]> for UUID {
	#[inline]
	fn from(u: [u8; 16]) -> Self {
		Self(u)
	}
}

impl UUID {
	#[cfg(uuid = "libuuid")]
	pub fn generate() -> Self {
		let mut u: MaybeUninit<[u8; 16]> = MaybeUninit::uninit();
		unsafe {
			uuid_generate(u.as_mut_ptr() as *mut u8);
		}
		let u = unsafe { u.assume_init() };
		Self(u)
	}
	#[cfg(uuid = "native")]
	pub fn generate() -> Self {
		let mut u: [u8; 16] = random();
		u[6] = (u[6] & 0xF) | 0x40;
		Self(u)
	}
}
#[cfg(test)]
mod tests {
	use super::UUID;
	use std::str::FromStr;

	#[test]
	fn test_uuid() {
		let uuid_str = "6b4ce055-2ef2-45a9-ac7b-260154a10502";
		let uuid = UUID::from_str(uuid_str).unwrap();
		assert_eq!(uuid.0[0], 0x6b);
		assert_eq!(format!("{}", uuid), uuid_str);
	}
	#[test]
	fn test_uuid_generate() {
		let uuid = UUID::generate();
		println!("{}", uuid);
	}
}
