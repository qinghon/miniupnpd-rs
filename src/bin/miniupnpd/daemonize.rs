use libc::kill;
use std::fs::File;
use std::io::Read;

pub fn writepidfile(fname: &str, pid: i32) -> std::io::Result<()> {
	std::fs::write(fname, format!("{}", pid))
}

pub fn checkforrunning(fname: &str) -> i32 {
	let mut buffer = [0u8; 64];
	let mut file = match File::open(fname) {
		Ok(file) => file,
		Err(_) => return 0,
	};

	match file.read(&mut buffer) {
		Ok(_l) => {
			if let Ok(pid) = String::from_utf8(buffer.to_vec()) {
				if let Ok(pid) = pid.trim().parse::<i32>() {
					unsafe {
						// let cname = CString::new("").unwrap();
						if kill(pid, 0) == 0 {
							return -2;
						}
					}
				}
			}
		}
		Err(_) => return 0,
	};

	0
}
