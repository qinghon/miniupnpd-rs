pub use libc::LOG_ALERT;
pub use libc::LOG_CRIT;
pub use libc::LOG_DEBUG;
pub use libc::LOG_EMERG;
pub use libc::LOG_ERR;
pub use libc::LOG_INFO;
pub use libc::LOG_NOTICE;
pub use libc::LOG_WARNING;
use libc::c_int;
use std::ffi::CStr;

pub use libc::LOG_DAEMON;
#[macro_export]
macro_rules! log {

    // log!(Level::Info, "a {} event", "log");
    ($lvl:expr, $format:tt, $($arg:tt)+) => ({
		// if let Some(s) =  {
		#[allow(unused_unsafe)]
		unsafe {
			libc::syslog($lvl,
				std::fmt::format(
					format_args!(concat!($format, "\0"), $($arg)+)).as_ptr()
				as *const libc::c_char)
		}
		// }
    });
	// log!(Level::Info, "a event");
    ($lvl:expr, $format:tt) => ({
	    #[allow(unused_unsafe)]
	    unsafe {libc::syslog($lvl, concat!($format, "\0").as_ptr() as *const libc::c_char)}
    });
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)+) => {
	    #[cfg(debug_assertions)]
	    println!($($arg)+);
    };
}

#[macro_export]
macro_rules! emerg {
    ($($arg:tt)+) => (log!(libc::LOG_EMERG, $($arg)+))
}
#[macro_export]
macro_rules! alert {
    ($($arg:tt)+) => (log!(libc::LOG_ALERT, $($arg)+))
}

#[macro_export]
macro_rules! error {
    // error!("a {} event", "log")
    ($($arg:tt)+) => (log!(libc::LOG_ERR, $($arg)+))
}
#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => (log!(libc::LOG_WARNING, $($arg)+))
}
#[macro_export]
macro_rules! notice {
    ($($arg:tt)+) => (log!(libc::LOG_NOTICE, $($arg)+))
}
#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => (log!(libc::LOG_INFO, $($arg)+))
}
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => (log!(libc::LOG_DEBUG, $($arg)+))
}

pub fn setlogmask(mask: u32) -> i32 {
	unsafe { libc::setlogmask(mask as c_int) }
}
pub fn openlog(ident: &CStr, logopt: i32, facility: c_int) {
	unsafe { libc::openlog(ident.as_ptr() as *const libc::c_char, logopt as c_int, facility) }
}
