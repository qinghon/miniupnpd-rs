use crate::minixml::{parsexml, xmlparser};
use std::cmp::min;
use std::ptr;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct NameValue {
	namelen: u8,
	pub name: [u8; 63],
	valuelen: u8,
	pub value: [u8; 127],
}
impl NameValue {
	pub(crate) fn name(&self) -> &str {
		unsafe { str::from_utf8_unchecked(self.name[..self.namelen as usize].as_ref()) }
	}
	pub(crate) fn value(&self) -> &str {
		if self.valuelen == 0 {
			""
		} else {
			unsafe { str::from_utf8_unchecked(self.value[..self.valuelen as usize].as_ref()) }
		}
	}
	pub(crate) const fn default() -> Self {
		Self { namelen: 0, name: [0u8; 63], valuelen: 0, value: [0u8; 127] }
	}
}

#[derive(Clone)]
#[repr(C)]
pub struct NameValueParserData {
	pub l_head: Vec<NameValue>,
	pub curelt_len: u8,
	pub curelt: [u8; 63],
	// pub portListing: Option<String>,
	pub portListingLength: i32,
	pub topelt: bool,
	pub cdata: String,
}
impl Default for NameValueParserData {
	fn default() -> NameValueParserData {
		Self {
			l_head: vec![],
			curelt_len: 0,
			curelt: [0; 63],
			// portListing: None,
			portListingLength: 0,
			topelt: false,
			cdata: String::new(),
		}
	}
}

fn NameValueParserStartElt(d: &mut NameValueParserData, name: &str) {
	d.topelt = true;
	let name = if name.len() > 62 { &name[0..62] } else { name };
	d.curelt[0..name.len()].copy_from_slice(name.as_bytes());
	d.curelt_len = name.len() as u8;
}
fn NameValueParserEndElt(d: &mut NameValueParserData, _name: &str) {
	if !d.topelt {
		return;
	}
	if &d.curelt[0..14] != b"NewPortListing" {
		let mut nv = NameValue::default();
		let l = min(d.cdata.len(), size_of_val(&nv.value));

		unsafe {
			ptr::copy_nonoverlapping(
				d.curelt.as_mut_ptr(),
				nv.name.as_mut_ptr(),
				min(d.curelt.len(), nv.name.len()),
			);
			nv.namelen = d.curelt_len;
		}
		if !d.cdata.is_empty() {
			nv.value[0..l].copy_from_slice(&d.cdata.as_bytes()[0..l]);
			nv.valuelen = l as u8;
		}
		d.l_head.push(nv);
	}
	d.cdata.clear();
	d.topelt = false;
}
fn NameValueParserGetData(d: &mut NameValueParserData, datas: &str) {
	if &d.curelt[0..14] == b"NewPortListing" {
		// d.portListing = None;
		// d.portListing = Some(String::from(datas));
	} else {
		d.cdata = String::from(datas);
	}
}

pub fn ParseNameValue(buffer: &str, data: &mut NameValueParserData) {
	let mut parser = xmlparser {
		xmlstart: buffer,
		xml: buffer,
		data,
		starteltfunc: NameValueParserStartElt,
		endeltfunc: NameValueParserEndElt,
		datafunc: NameValueParserGetData,
		attfunc: None::<fn(&mut NameValueParserData, &str, &str)>,
	};

	parsexml(&mut parser);
}

pub fn ClearNameValueList(pdata: &mut NameValueParserData) {
	// pdata.portListing = None;
	pdata.l_head.clear();
	pdata.l_head.shrink_to_fit();
}

pub fn GetValueFromNameValueList<'a>(pdata: &'a NameValueParserData, Name: &str) -> Option<&'a str> {
	if let Some(v) = pdata.l_head.iter().find(|x| x.name() == Name) {
		Some(v.value())
	} else {
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::upnpreplyparse::NameValueParserData;
	#[test]
	fn test_parse_name_value() {
		let buffer = "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
			<s:Body>\
			<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
			<NewRemoteHost></NewRemoteHost>\
			<NewExternalPort>80</NewExternalPort>\
			<NewProtocol>TCP</NewProtocol>\
			<NewInternalPort>8000</NewInternalPort>\
			<NewInternalClient>192.168.1.3</NewInternalClient>\
			<NewEnabled>1</NewEnabled>\
			<NewPortMappingDescription>Test port mapping entry from UPnPy.</NewPortMappingDescription>\
			<NewLeaseDuration>0</NewLeaseDuration>\
			</u:AddPortMapping>\
			</s:Body>\
			</s:Envelope>";

		let mut data = NameValueParserData::default();
		ParseNameValue(buffer, &mut data);
		let r_host = GetValueFromNameValueList(&data, "NewRemoteHost");
		let eport = GetValueFromNameValueList(&data, "NewExternalPort");
		let proto = GetValueFromNameValueList(&data, "NewProtocol");
		let iport = GetValueFromNameValueList(&data, "NewInternalPort");
		let ihost = GetValueFromNameValueList(&data, "NewInternalClient");
		let enable = GetValueFromNameValueList(&data, "NewEnabled");
		let desc = GetValueFromNameValueList(&data, "NewPortMappingDescription");
		let lease = GetValueFromNameValueList(&data, "NewLeaseDuration");

		assert_eq!(r_host, Some(""));
		assert_eq!(eport, Some("80"));
		assert_eq!(proto, Some("TCP"));
		assert_eq!(iport, Some("8000"));
		assert_eq!(ihost, Some("192.168.1.3"));
		assert_eq!(enable, Some("1"));
		assert_eq!(desc, Some("Test port mapping entry from UPnPy."));
		assert_eq!(lease, Some("0"));
	}	
	#[test]
	fn test_parse_name_value1() {
		let buffer = "<s:Envelope \
			xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
			s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
			<s:Body>\
			<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:2\">\
			<NewRemoteHost></NewRemoteHost>\
			<NewExternalPort>80</NewExternalPort>\
			<NewProtocol>TCP</NewProtocol>\
			<NewInternalPort>8000</NewInternalPort>\
			<NewInternalClient>172.18.0.2</NewInternalClient>\
			<NewEnabled>1</NewEnabled>\
			<NewPortMappingDescription>Test port mapping entry from UPnPy.</NewPortMappingDescription>\
			<NewLeaseDuration>0</NewLeaseDuration>\
			</u:AddPortMapping>\
			</s:Body>\
			</s:Envelope>";

		let mut data = NameValueParserData::default();
		ParseNameValue(buffer, &mut data);
		let r_host = GetValueFromNameValueList(&data, "NewRemoteHost");
		let eport = GetValueFromNameValueList(&data, "NewExternalPort");
		let proto = GetValueFromNameValueList(&data, "NewProtocol");
		let iport = GetValueFromNameValueList(&data, "NewInternalPort");
		let ihost = GetValueFromNameValueList(&data, "NewInternalClient");
		let enable = GetValueFromNameValueList(&data, "NewEnabled");
		let desc = GetValueFromNameValueList(&data, "NewPortMappingDescription");
		let lease = GetValueFromNameValueList(&data, "NewLeaseDuration");

		assert_eq!(r_host, Some(""));
		assert_eq!(eport, Some("80"));
		assert_eq!(proto, Some("TCP"));
		assert_eq!(iport, Some("8000"));
		assert_eq!(ihost, Some("172.18.0.2"));
		assert_eq!(enable, Some("1"));
		assert_eq!(desc, Some("Test port mapping entry from UPnPy."));
		assert_eq!(lease, Some("0"));
	}
}
