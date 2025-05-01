use std::rc::Rc;

#[derive(Debug, Default)]
pub(crate) struct dscp_value {
	pub(crate) app_name: Rc<str>,
	pub(crate) delay: u8,
	pub(crate) loss: u8,
	pub(crate) jitter: u8,
	pub(crate) value: u8,
}

/// parse like `set_learn_dscp "Webex" 1 1 1 34`
///
pub(crate) fn read_learn_dscp_line(dscp_values: &mut dscp_value, p: &str) -> i32 {
	let mut p = p.trim_start();
	if !p.starts_with("set_learn_dscp") {
		return -1;
	}

	p = p[15..].trim_start();
	if p.is_empty() || !p.starts_with('"') {
		return -1;
	}
	p = &p[1..];
	// app name
	if let Some(index) = p.find('"') {
		dscp_values.app_name = (&p[..index]).trim_end().into();
		p = p[(index + 1)..].trim_start();
	} else {
		return -1;
	}
	if p.is_empty() {
		return -1;
	}
	let mut tokens = p.split_ascii_whitespace();
	// delay
	let delay = match tokens.next() {
		None => {
			return -1;
		}
		Some(d) => match d.as_bytes()[0] {
			b'0' | b'1' | b'2' => d.as_bytes()[0] - b'0',
			_ => {
				error!("Wrong delay value {}", d);
				error!("Delay can be from set {0,1,2} 0=low delay, 1=medium delay, 2=high delay");
				return -1;
			}
		},
	};
	dscp_values.delay = delay;
	// loss
	let loss = match tokens.next() {
		None => {
			return -1;
		}
		Some(d) => match d.as_bytes()[0] {
			b'0' | b'1' | b'2' => d.as_bytes()[0] - b'0',
			_ => {
				error!("Wrong loss value {}", d);
				error!("Delay can be from set {0,1,2} 0=low loss, 1=medium loss, 2=high loss");
				return -1;
			}
		},
	};
	dscp_values.loss = loss;
	// jitter
	let jitter = match tokens.next() {
		None => {
			return -1;
		}
		Some(d) => match d.as_bytes()[0] {
			b'0' | b'1' | b'2' => d.as_bytes()[0] - b'0',
			_ => {
				error!("Wrong jitter value {}", d);
				error!("Delay can be from set {0,1,2} 0=low jitter, 1=medium jitter, 2=high jitter ");
				return -1;
			}
		},
	};
	dscp_values.jitter = jitter;
	let dscp_value = match tokens.next() {
		None => {
			return -1;
		}
		Some(d) => {
			if !d.as_bytes()[0].is_ascii_digit()
				&& (d.len() >= 2 && !matches!(&d[0..2], "AF" | "CS" | "EF" | "af" | "cs" | "ef"))
			{
				return -1;
			}
			if d.len() > 2 && d[0..2].eq_ignore_ascii_case("AF") {
				// https://en.wikipedia.org/wiki/Differentiated_services#Assured_Forwarding
				let v = d[2..].parse::<u8>().unwrap_or(0);
				if (11..=43).contains(&v) && v % 10 <= 3 {
					10 + (v / 10 - 1) * 8 + (v % 10 - 1) * 2
				} else {
					error!("Unknown AF value {}", v);
					return -1;
				}
			} else if d.len() > 2 && d[0..2].eq_ignore_ascii_case("CS") {
				match d[2..].parse::<u8>().unwrap_or(0) {
					cs @ 1..=7 => cs * 8,
					v => {
						error!("Unknown CS value {} ", v);
						return -1;
					}
				}
			} else if d == "EF" {
				46
			} else {
				let v = d.parse::<u8>().unwrap_or(0);
				if v > 63 {
					error!("Unknown value more than 63 {}", v);
					return -1;
				}
				v
			}
		}
	};
	dscp_values.value = dscp_value;
	0
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn test_read_learn_dscp_line() {
		let mut d = dscp_value::default();
		assert_eq!(read_learn_dscp_line(&mut d, ""), -1);

		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex" 0 1 2 34"#), 0);
		assert_eq!(d.app_name.as_str(), "Webex");
		assert_eq!(d.delay, 0);
		assert_eq!(d.loss, 1);
		assert_eq!(d.jitter, 2);
		assert_eq!(d.value, 34);

		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex" 1 1 1 AF11"#), 0);
		assert_eq!(d.value, 10);
		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex" 1 1 1 AF22"#), 0);
		assert_eq!(d.value, 20);
		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex" 1 1 1 AF33"#), 0);
		assert_eq!(d.value, 30);
		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex" 1 1 1 AF42"#), 0);
		assert_eq!(d.value, 36);

		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex" 1 1 1 CS1"#), 0);
		assert_eq!(d.value, 8);
		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex" 1 1 1 CS7"#), 0);
		assert_eq!(d.value, 56);

		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex" 1 1 1 EF"#), 0);
		assert_eq!(d.value, 46);

		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex 1 1 1 34"#), -1);
		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp Webex" 1 1 1 34"#), -1);

		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex" 3 2 1 34"#), -1);
		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex" 1 3 2 34"#), -1);
		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex" 2 1 3 34"#), -1);

		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex" 1 1 1 KFC"#), -1);
		assert_eq!(read_learn_dscp_line(&mut d, r#"set_learn_dscp "Webex" 1 1 1 78"#), -1);
		assert_eq!(read_learn_dscp_line(&mut d, "set_learn_dscp \"\""), -1);
	}
}
