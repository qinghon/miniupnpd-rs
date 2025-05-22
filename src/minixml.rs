use crate::upnpreplyparse::NameValueParserData;

type XmlCbFn = fn(&mut NameValueParserData, &str);
pub(crate) type XmlCbAttFn = fn(&mut NameValueParserData, &str, &str);

pub struct xmlparser<'a> {
	pub xmlstart: &'a str,
	// pub xmlend: *const libc::c_char,
	pub xml: &'a str,
	// pub xmlsize: i32,
	pub data: &'a mut NameValueParserData,
	pub starteltfunc: XmlCbFn,
	pub endeltfunc: XmlCbFn,
	pub datafunc: XmlCbFn,
	pub attfunc: Option<XmlCbAttFn>,
}
fn parseatt(p: &mut xmlparser) -> i32 {
	let mut xml = p.xml;
	let mut sep;
	let mut attvalue;
	let mut attvaluelen;
	while !xml.is_empty() {
		if xml.as_bytes()[0] == b'/' || xml.as_bytes()[0] == b'>' {
			p.xml = xml;
			return 0;
		}
		xml = xml.trim_start();

		let mut attname = xml;
		let mut attnamelen = 0;

		while xml.as_bytes()[0] != b'=' && !xml.as_bytes()[0].is_ascii_whitespace() {
			attnamelen += 1;
			if xml.len() <= 1 {
				return -1;
			}
			xml = &xml[1..];
		}
		while xml.as_bytes()[0] != b'=' {
			if xml.len() <= 1 {
				return -1;
			}
			xml = &xml[1..];
		}
		xml = &xml[1..];
		sep = xml.as_bytes()[0];
		if sep == b'\'' || sep == b'"' {
			if xml.len() <= 1 {
				return -1;
			}
			xml = &xml[1..];
			attvalue = xml;
			attvaluelen = 0;
			while xml.as_bytes()[0] != sep {
				attvaluelen += 1;
				if xml.is_empty() {
					return -1;
				}
				xml = &xml[1..];
			}
		} else {
			attvalue = xml;
			attvaluelen = 0;
			let mut xx;
			xx = xml.as_bytes()[0];
			while !xx.is_ascii_whitespace() && xx != b'>' && xx != b'/' {
				attvaluelen += 1;
				if xml.len() <= 1 {
					return -1;
				}
				xml = &xml[1..];
				xx = xml.as_bytes()[0];
			}
		}
		attname = &attname[..attnamelen];
		attvalue = &attvalue[..attvaluelen];
		if let Some(attfunc) = p.attfunc.as_mut() {
			attfunc(p.data, attname, attvalue);
		}

		xml = &xml[1..]
	}
	-1
}
fn parseelt(p: &mut xmlparser) {
	let mut xml = p.xml;

	while !xml.is_empty() {
		if xml.starts_with("<!--") {
			if let Some(x) = xml.find("-->") {
				xml = &xml[x + 3..];
			} else {
				// xml not close
				return;
			}
		} else if &xml[0..1] == "<" && &xml[1..2] != "?" {
			let mut i = 0;
			let mut elementname = &xml[1..];
			xml = elementname;
			while !xml.as_bytes()[0].is_ascii_whitespace() && xml.as_bytes()[0] != b'>' && xml.as_bytes()[0] != b'/' {
				i += 1;
				if xml.len() <= 1 {
					return;
				}
				xml = &xml[1..];
				if xml.as_bytes()[0] == b':' {
					i = 0;
					elementname = &xml[1..];
				}
			}
			if i > 0 {
				p.xml = xml;
				(p.starteltfunc)(p.data, &elementname[..i]);
				if parseatt(p) != 0 {
					return;
				}
				xml = p.xml;
				if xml.as_bytes()[0] != b'/' {
					i = 0;
					if xml.len() <= 1 {
						return;
					}
					let mut data = &xml[1..];
					xml = data;
					xml = xml.trim_start();
					if xml.starts_with("<![CDATA[") {
						xml = &xml[9..];
						data = xml;

						while !xml.starts_with("]]>") {
							i += 1;
							if xml.len() < 4 {
								return;
							}
							xml = &xml[1..];
						}
						if i > 0 {
							p.xml = xml;
							(p.datafunc)(p.data, &data[..i]);
						}

						while xml.as_bytes()[0] != b'<' {
							if xml.len() <= 1 {
								return;
							}
							xml = &xml[1..];
						}
					} else {
						while xml.as_bytes()[0] != b'<' {
							i += 1;
							if xml.len() <= 1 {
								return;
							}
							xml = &xml[1..];
						}
						if xml.len() < 2 {
							return;
						}
						if i > 0 && &xml[1..2] == "/" {
							p.xml = xml;
							(p.datafunc)(p.data, &data[..i]);
						}
					}
				}
			} else if xml.as_bytes()[0] == b'/' {
				let mut i = 0;
				elementname = &xml[1..];
				xml = &xml[1..];
				if xml.len() <= 1 {
					return;
				}
				while xml.as_bytes()[0] != b'>' {
					i += 1;
					if xml.len() <= 1 {
						return;
					}
					xml = &xml[1..];
				}
				(p.endeltfunc)(p.data, &elementname[..i]);
				xml = &xml[1..]
			}
		} else {
			xml = &xml[1..]
		}
	}
}

pub fn parsexml(parser: &mut xmlparser) {
	parser.xml = parser.xmlstart;
	// parser.xmlend = ((*parser).xmlstart).offset((*parser).xmlsize as isize);
	parseelt(parser);
}
