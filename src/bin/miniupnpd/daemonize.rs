use libc::kill;
use std::fmt::Write;
use std::fs::File;
use std::io::Read;

pub fn writepidfile(fname: &str, pid: i32) -> std::io::Result<()> {
	use arrayvec;
	let mut p = arrayvec::ArrayString::<12>::new();
	let _ = p.write_fmt(format_args!("{pid}\n"));
	std::fs::write(fname, p.as_bytes())
}

pub fn checkforrunning(fname: &str) -> i32 {
	let mut file = match File::open(fname) {
		Ok(file) => file,
		Err(_) => return 0,
	};
	let mut buffer = [0u8; 64];

	match file.read(buffer.as_mut()) {
		Ok(_l) => {
			let mut pid = arrayvec::ArrayString::<60>::new();
			for c in &buffer[0.._l] {
				if c.is_ascii() {
					pid.push(char::from(*c))
				}
			}
			if let Ok(pid) = pid.trim().parse::<i32>() {
				unsafe {
					if kill(pid, 0) == 0 {
						return -2;
					}
				}
			}
		}
		Err(_) => return 0,
	};

	0
}
