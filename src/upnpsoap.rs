#![allow(unused_mut)]

use crate::getconnstatus::get_wan_connection_status_str;
#[cfg(not(feature = "multiple_ext_ip"))]
use crate::getifaddr::addr_is_reserved;
use crate::getifaddr::getifaddr;
use crate::getifstats::ifdata;
use crate::upnpglobalvars::*;
use crate::upnphttp::{BuildHeader_upnphttp, BuildResp2_upnphttp, SendRespAndClose_upnphttp, upnphttp};
use crate::upnppermissions::{AllowBitMap, get_permitted_ext_ports};
use crate::upnppinhole::*;
use crate::upnpredirect::*;
use crate::upnpreplyparse::{GetValueFromNameValueList, NameValueParserData, ParseNameValue};
use crate::upnpurns::SERVICE_ID_WANIPC;
use crate::upnputils::{proto_atoi, upnp_get_uptime, upnp_time};
use crate::{Backend, OS, PinholeEntry, TCP, UDP};
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::random::random;

pub const UPNP_UI4_MAX: u32 = u32::MAX;

type SoapAction = fn(&mut upnphttp, &str, &str);

pub struct soapMethod {
	pub methodName: &'static str,
	pub methodImpl: SoapAction,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct NameValue {
	pub l_next: *mut NameValue,
	pub name: [libc::c_char; 64],
	pub value: [libc::c_char; 128],
}

pub fn hide_pcp_nonce(desc: &mut [u8]) {
	if !desc.starts_with(b"PCP ") || desc.len() < 5 {
		return;
	}
	if let Some(off) = desc[4..].iter().position(|&x| x == b' ') {
		for i in &mut desc[off + 1..] {
			*i = b'x';
		}
	}
}
fn BuildSendAndCloseSoapResp(h: &mut upnphttp, body: &[u8]) {
	const beforebody: &str = "<?xml version=\"1.0\"?>\r\n\
    <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
    s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
    <s:Body>";
	const afterbody: &str = "</s:Body></s:Envelope>\r\n";

	BuildHeader_upnphttp(h, 200, "OK", (beforebody.len() + afterbody.len() + body.len()) as i32);

	h.res_buf.extend_from_slice(beforebody.as_bytes());
	h.res_buf.extend_from_slice(body);
	h.res_buf.extend_from_slice(afterbody.as_bytes());

	SendRespAndClose_upnphttp(h);
}
fn GetConnectionTypeInfo(h: &mut upnphttp, action: &str, ns: &str) {
	let mut body = arrayvec::ArrayString::<508>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response xmlns:u=\"{ns}\">\
        <NewConnectionType>IP_Routed</NewConnectionType>\
        <NewPossibleConnectionTypes>IP_Routed</NewPossibleConnectionTypes>\
        </u:{action}Response>"
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes());
}

fn fmt_upnp_ui4_strict(r: i32, v: u64) -> u64 {
	if r < 0 {
		0
	} else if cfg!(feature = "strict") {
		(v as u32 & UPNP_UI4_MAX) as u64
	} else {
		v
	}
}

fn GetTotalBytesSent(h: &mut upnphttp, action: &str, ns: &str) {
	let mut data: ifdata = Default::default();
	let op = global_option.get().unwrap();
	let ext_if_name = &op.ext_ifname;
	let rt = h.rt_options.as_ref().unwrap();
	let r = rt.os.getifstats(ext_if_name, &mut data);
	let total_bytes_sent = fmt_upnp_ui4_strict(r, data.obytes);
	let mut body = arrayvec::ArrayString::<252>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response xmlns:u=\"{ns}\">\
            <NewTotalBytesSent>{total_bytes_sent}</NewTotalBytesSent>\
            </u:{action}Response>",
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes())
}

fn GetTotalBytesReceived(h: &mut upnphttp, action: &str, ns: &str) {
	let mut data: ifdata = Default::default();
	let op = global_option.get().unwrap();
	let ext_if_name = &op.ext_ifname;
	let rt = h.rt_options.as_ref().unwrap();
	let r = rt.os.getifstats(ext_if_name, &mut data);
	let total_bytes_received = fmt_upnp_ui4_strict(r, data.ibytes);
	let mut body = arrayvec::ArrayString::<252>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response xmlns:u=\"{ns}\">\
        <NewTotalBytesReceived>{total_bytes_received}</NewTotalBytesReceived>\
        </u:{action}Response>"
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes())
}

fn GetTotalPacketsSent(h: &mut upnphttp, action: &str, ns: &str) {
	let mut data: ifdata = Default::default();
	let op = global_option.get().unwrap();
	let ext_if_name = &op.ext_ifname;
	let rt = h.rt_options.as_ref().unwrap();
	let r = rt.os.getifstats(ext_if_name, &mut data);
	let total_packets_sent = fmt_upnp_ui4_strict(r, data.opackets);
	let mut body = arrayvec::ArrayString::<252>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response xmlns:u=\"{ns}\">\
        <NewTotalPacketsSent>{total_packets_sent}</NewTotalPacketsSent>\
        </u:{action}Response>"
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes())
}

fn GetTotalPacketsReceived(h: &mut upnphttp, action: &str, ns: &str) {
	let mut data: ifdata = Default::default();
	let op = global_option.get().unwrap();
	let ext_if_name = &op.ext_ifname;
	let rt = h.rt_options.as_ref().unwrap();
	let r = rt.os.getifstats(ext_if_name, &mut data);
	let total_packets_received = fmt_upnp_ui4_strict(r, data.ibytes);
	let mut body = arrayvec::ArrayString::<252>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response  xmlns:u=\"{ns}\">\
            <NewTotalPacketsReceived>{total_packets_received}</NewTotalPacketsReceived>\
            </u:{action}Response>"
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes())
}

fn GetCommonLinkProperties(h: &mut upnphttp, action: &str, ns: &str) {
	/* WANAccessType : set depending on the hardware :
	 * DSL, POTS (plain old Telephone service), Cable, Ethernet */

	let mut data: ifdata = Default::default();
	let mut status = "Up"; /* Up, Down (Required), Initializing, Unavailable (Optional) */
	let wan_access_type = "Cable"; /* DSL, POTS, Cable, Ethernet */
	let op = global_option.get().unwrap();
	let ext_if_name = &op.ext_ifname;
	let mut downstream_bitrate = op.bitrate_down.unwrap_or(0);
	let mut upstream_bitrate = op.bitrate_up.unwrap_or(0);
	let rt = h.rt_options.as_ref().unwrap();
	if (downstream_bitrate == 0 || upstream_bitrate == 0) && rt.os.getifstats(ext_if_name, &mut data) >= 0 {
		if downstream_bitrate == 0 {
			downstream_bitrate = data.baudrate as usize;
		}
		if upstream_bitrate == 0 {
			upstream_bitrate = data.baudrate as usize;
		}
	}

	let mut _ip = Ipv4Addr::UNSPECIFIED;
	if getifaddr(ext_if_name, &mut _ip, None) < 0 {
		status = "Down";
	}
	let mut body = arrayvec::ArrayString::<508>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response xmlns:u=\"{ns}\">\
            <NewWANAccessType>{wan_access_type}</NewWANAccessType>\
            <NewLayer1UpstreamMaxBitRate>{upstream_bitrate}</NewLayer1UpstreamMaxBitRate>\
            <NewLayer1DownstreamMaxBitRate>{downstream_bitrate}</NewLayer1DownstreamMaxBitRate>\
            <NewPhysicalLinkStatus>{status}</NewPhysicalLinkStatus>\
            </u:{action}Response>"
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes())
}

fn GetStatusInfo(h: &mut upnphttp, action: &str, ns: &str) {
	let op = global_option.get().unwrap();
	let ext_if_name = &op.ext_ifname;
	let status = get_wan_connection_status_str(ext_if_name);
	let uptime = upnp_get_uptime().as_secs();
	let mut body = arrayvec::ArrayString::<508>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response xmlns:u=\"{ns}\">\
            <NewConnectionStatus>{status}</NewConnectionStatus>\
            <NewLastConnectionError>ERROR_NONE</NewLastConnectionError>\
            <NewUptime>{uptime}</NewUptime>\
            </u:{action}Response>",
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes())
}

fn GetNATRSIPStatus(h: &mut upnphttp, action: &str, ns: &str) {
	// 2.2.9. RSIPAvailable
	// This variable indicates if Realm-specific IP (RSIP) is available
	// as a feature on the InternetGatewayDevice. RSIP is being defined
	// in the NAT working group in the IETF to allow host-NATing using
	// a standard set of message exchanges. It also allows end-to-end
	// applications that otherwise break if NAT is introduced
	// (e.g. IPsec-based VPNs).
	// A gateway that does not support RSIP should set this variable to 0.
	let mut body = arrayvec::ArrayString::<252>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response xmlns:u=\"{ns}\">\
        <NewRSIPAvailable>0</NewRSIPAvailable>\
        <NewNATEnabled>1</NewNATEnabled>\
        </u:{action}Response>",
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes())
}

fn GetExternalIPAddress(h: &mut upnphttp, action: &str, ns: &str) {
	let mut ext_ip_addr;
	let op = global_option.get().unwrap();

	#[cfg(not(feature = "multiple_ext_ip"))]
	{
		let rt = h.rt_options.as_ref().unwrap();
		ext_ip_addr = Ipv4Addr::UNSPECIFIED;
		if let Some(addr) = rt.use_ext_ip_addr.as_ref() {
			match addr {
				IpAddr::V4(v4addr) => {
					ext_ip_addr = *v4addr;
				}
				IpAddr::V6(_) => {}
			}
		} else {
			let mut if_addr = Ipv4Addr::UNSPECIFIED;
			if getifaddr(&op.ext_ifname, &mut if_addr, None) == 0 {
				if !GETFLAG!(op.runtime_flags, ALLOWPRIVATEIPV4MASK) && addr_is_reserved(&if_addr) {
					notice!(
						"private/reserved address {} is not suitable for external IP",
						ext_ip_addr
					);
				} else {
					ext_ip_addr = if_addr;
				}
			} else {
				error!("Failed to get ip address for interface {}", op.ext_ifname.as_str());
			}
		}
	}

	#[cfg(feature = "multiple_ext_ip")]
	{
		ext_ip_addr = Ipv4Addr::UNSPECIFIED;
		// let op = global_option.get().unwrap();
		for lan_addr in op.listening_ip.iter() {
			match h.clientaddr {
				IpAddr::V4(addr) => {
					if addr & lan_addr.mask == lan_addr.addr & lan_addr.mask {
						ext_ip_addr = addr;
						break;
					}
				}
				IpAddr::V6(_) => {}
			}
		}
	}
	let mut body = arrayvec::ArrayString::<252>::new();
	if ext_ip_addr.is_unspecified() {
		let _ = body.write_fmt(format_args!(
			"<u:{action}Response xmlns:u=\"{ns}\">\
            <NewExternalIPAddress>{ext_ip_addr}</NewExternalIPAddress>\
            </u:{action}Response>"
		));
	} else {
		let _ = body.write_fmt(format_args!(
			"<u:{action}Response xmlns:u=\"{ns}\">\
            <NewExternalIPAddress>{}</NewExternalIPAddress>\
            </u:{action}Response>",
			""
		));
	};

	BuildSendAndCloseSoapResp(h, body.as_bytes())
}

fn AddPortMapping(h: &mut upnphttp, action: &str, ns: &str) {
	let mut data = NameValueParserData::default();
	let mut leaseduration;

	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);
	if data.l_head.is_empty() {
		error!(
			"cannot parse content: off={} '{}'",
			h.req_contentoff.0,
			h.get_req_str_from(h.req_contentoff)
		);
	}
	let int_ip = GetValueFromNameValueList(&data, "NewInternalClient").unwrap_or_default();

	let iaddr = if int_ip.is_empty() {
		if cfg!(feature = "strict") {
			SoapError(h, 402, "Invalid Args");
			return;
		} else {
			match h.clientaddr {
				IpAddr::V4(addr) => addr,
				IpAddr::V6(_) => unreachable!("Invalid Args"),
			}
		}
	} else {
		match (int_ip, 0).to_socket_addrs() {
			Ok(mut addrs) => {
				if let Some(SocketAddr::V4(addr)) = addrs.find(|x| x.is_ipv4()) {
					*addr.ip()
				} else {
					error!("Failed to convert hostname '{}' to ip address", int_ip);
					SoapError(h, 402, "Invalid Args");
					return;
				}
			}
			Err(e) => {
				error!("Failed to convert hostname '{}' to ip address: {}", int_ip, e);
				SoapError(h, 402, "Invalid Args");
				return;
			}
		}
	};
	let op = global_option.get().unwrap();
	if GETFLAG!(op.runtime_flags, SECUREMODEMASK) && h.clientaddr != IpAddr::V4(iaddr) {
		info!(
			"{}: Client {} tried to redirect port to {}",
			action, h.clientaddr, int_ip
		);
		if cfg!(feature = "igd2") {
			SoapError(h, 606, "Action not authorized");
		} else {
			SoapError(h, 718, "ConflictInMappingEntry");
		}
	}

	let r_host = GetValueFromNameValueList(&data, "NewRemoteHost").unwrap_or_default();
	let int_port = GetValueFromNameValueList(&data, "NewInternalPort").unwrap_or_default();
	let ext_port = GetValueFromNameValueList(&data, "NewExternalPort").unwrap_or_default();
	let protocol = GetValueFromNameValueList(&data, "NewProtocol").unwrap_or_default();
	let desc = GetValueFromNameValueList(&data, "NewPortMappingDescription");
	let leaseduration_str = GetValueFromNameValueList(&data, "NewLeaseDuration").unwrap_or_default();

	// Handle invalid arguments
	if int_port.is_empty() || ext_port.is_empty() || protocol.is_empty() {
		SoapError(h, 402, "Invalid Args");
		return;
	}

	// Additional port checks
	let eport: u16 = ext_port.parse().unwrap_or_default();
	let iport: u16 = int_port.parse().unwrap_or_default();

	if ext_port == "*" || eport == 0 {
		SoapError(h, 716, "WildCardNotPermittedInExtPort");
		return;
	}
	let raddr = if !r_host.is_empty() {
		if cfg!(feature = "strict") && r_host != "*" {
			SoapError(h, 726, "RemoteHostOnlySupportsWildcard");
			return;
		}
		if let Ok(addr) = r_host.parse() {
			addr
		} else {
			SoapError(h, 402, "Invalid Args");
			return;
		}
	} else {
		Ipv4Addr::UNSPECIFIED
	};

	leaseduration = leaseduration_str.parse().unwrap_or(0);
	#[cfg(feature = "igd2")]
	{
		leaseduration = if leaseduration == 0 || leaseduration > 64800 {
			64800
		} else {
			leaseduration
		};
	}

	let rt = h.rt_options.as_mut().unwrap();
	let proto = proto_atoi(protocol);
	debug!(
		"{}: ext port {} to {}:{} protocol {} for: {} leaseduration={} rhost={}",
		action,
		eport,
		int_ip,
		iport,
		protocol,
		desc.unwrap_or_default(),
		leaseduration,
		raddr
	);
	let r = upnp_redirect(op, rt, raddr, iaddr, eport, iport, proto, desc, leaseduration);

	// possible error codes for AddPortMapping :
	// 402 - Invalid Args
	// 501 - Action Failed
	// 606 - Action not authorized (added in IGD v2)
	// 715 - WildCardNotPermittedInSrcIP
	// 716 - WildCardNotPermittedInExtPort
	// 718 - ConflictInMappingEntry
	// 724 - SamePortValuesRequired (deprecated in IGD v2)
	// 725 - OnlyPermanentLeasesSupported
	// 		 The NAT implementation only supports permanent lease times on
	// 		 port mappings (deprecated in IGD v2)
	// 726 - RemoteHostOnlySupportsWildcard
	// 		 RemoteHost must be a wildcard and cannot be a specific IP
	// 		 address or DNS name (deprecated in IGD v2)
	// 727 - ExternalPortOnlySupportsWildcard
	// 		 ExternalPort must be a wildcard and cannot be a specific port
	// 		 value (deprecated in IGD v2)
	// 728 - NoPortMapsAvailable
	// 		 There are not enough free ports available to complete the mapping
	// 		 (added in IGD v2)
	// 729 - ConflictWithOtherMechanisms (added in IGD v2)
	// 732 - WildCardNotPermittedInIntPort (added in IGD v2)
	match r {
		0 => {
			let mut body = arrayvec::ArrayString::<124>::new();
			let _ = body.write_fmt(format_args!("<u:{action}Response xmlns:u=\"{ns}\"/>"));
			BuildSendAndCloseSoapResp(h, body.as_bytes());
		}
		#[cfg(feature = "igd2")]
		-4 => {
			SoapError(h, 729, "ConflictWithOtherMechanisms");
		}
		#[cfg(feature = "igd2")]
		-3 => {
			SoapError(h, 606, "Action not authorized");
		}
		#[cfg(feature = "igd2")]
		-2 => {
			SoapError(h, 718, "ConflictInMappingEntry");
		}
		#[cfg(not(feature = "igd2"))]
		-2 | -3 | -4 => {
			SoapError(h, 718, "ConflictInMappingEntry");
		}
		_ => {
			SoapError(h, 501, "Action Failed");
		}
	}
}

fn AddAnyPortMapping(h: &mut upnphttp, action: &str, ns: &str) {
	let mut data = NameValueParserData::default();

	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);
	let r_host = GetValueFromNameValueList(&data, "NewRemoteHost").unwrap_or_default();
	let ext_port = GetValueFromNameValueList(&data, "NewExternalPort").unwrap_or_default();
	let protocol = GetValueFromNameValueList(&data, "NewProtocol").unwrap_or_default();
	let int_port = GetValueFromNameValueList(&data, "NewInternalPort").unwrap_or_default();
	let int_ip = GetValueFromNameValueList(&data, "NewInternalClient").unwrap_or_default();
	let desc = GetValueFromNameValueList(&data, "NewPortMappingDescription").unwrap_or_default();
	let leaseduration_str = GetValueFromNameValueList(&data, "NewLeaseDuration").unwrap_or_default();

	let leaseduration = leaseduration_str.parse().unwrap_or(604800);

	if int_ip.is_empty() || ext_port.is_empty() || int_port.is_empty() || protocol.is_empty() {
		SoapError(h, 402, "Invalid Args");
		return;
	}
	let iaddr = match (int_ip, 0).to_socket_addrs() {
		Ok(mut addrs) => {
			if let Some(SocketAddr::V4(addr)) = addrs.find(|x| x.is_ipv4()) {
				*addr.ip()
			} else {
				error!("Failed to convert hostname '{}' to ip address", int_ip);
				SoapError(h, 402, "Invalid Args");
				return;
			}
		}
		Err(e) => {
			error!("Failed to convert hostname '{}' to ip address: {}", int_ip, e);
			SoapError(h, 402, "Invalid Args");
			return;
		}
	};

	let mut eport: u16 = if ext_port == "*" {
		0
	} else {
		ext_port.parse().unwrap_or(0)
	};
	if eport == 0 {
		eport = 1024 + ((random::<u32>() & 0x7ffffff) % (65536u32 - 1024)) as u16;
	}

	let iport: u16 = int_port.parse().unwrap_or(0);
	if iport == 0 || ((!ext_port.chars().all(char::is_numeric)) && ext_port != "*") {
		SoapError(h, 402, "Invalid Args");
		return;
	}

	if r_host.is_empty() || r_host != "*" {
		SoapError(h, 726, "RemoteHostOnlySupportsWildcard");
		return;
	}
	let raddr = if !r_host.is_empty() {
		if cfg!(feature = "strict") && r_host != "*" {
			SoapError(h, 726, "RemoteHostOnlySupportsWildcard");
			return;
		}
		if let Ok(addr) = r_host.parse() {
			addr
		} else {
			SoapError(h, 402, "Invalid Args");
			return;
		}
	} else {
		Ipv4Addr::UNSPECIFIED
	};

	let op = global_option.get().unwrap();

	if GETFLAG!(op.runtime_flags, SECUREMODEMASK) && h.clientaddr != IpAddr::V4(iaddr) {
		info!(
			"{}: Client {} tried to redirect port to {}",
			action, h.clientaddr, int_ip
		);
		SoapError(h, 606, "Action not authorized");
		return;
	}
	let rt = h.rt_options.as_mut().unwrap();
	let proto = proto_atoi(protocol);

	let mut r = upnp_redirect(op, rt, raddr, iaddr, eport, iport, proto, Some(desc), leaseduration);
	if r != 0 && r != -1 {
		let mut eport_below = eport;
		let mut eport_above = eport;
		let mut allowed_eports = AllowBitMap::default();
		let op = global_option.get().unwrap();
		get_permitted_ext_ports(&mut allowed_eports, &op.upnpperms, iaddr, iport);

		loop {
			if eport_below <= 1 && eport_above == 65535 {
				r = 1;
				break;
			}
			if eport_above == 65535 || (eport > eport_below && eport_below > 1) {
				eport = eport_below;
				eport_below -= 1;
			} else {
				eport = {
					eport_above += 1;
					eport_above
				};
			}
			if !allowed_eports.get(eport) {
				continue;
			}
			r = upnp_redirect(op, rt, raddr, iaddr, eport, iport, proto, Some(desc), leaseduration);
			if r == 0 || r == -1 {
				/* OK or failure : Stop */
				break;
			}
			/* r : -2 / -4 already redirected or -3 permission check failed :
			 * continue */
		}
	}

	match r {
		1 => SoapError(h, 728, "NoPortMapsAvailable"),
		0 => {
			let mut body = arrayvec::ArrayString::<252>::new();
			let _ = body.write_fmt(format_args!(
				"<u:{action}Response xmlns:u=\"{ns}\"><NewReservedPort>{eport}</NewReservedPort></u:{action}Response>"
			));
			BuildSendAndCloseSoapResp(h, body.as_bytes());
		}
		-2 => SoapError(h, 718, "ConflictInMappingEntry"),
		-3 => SoapError(h, 606, "Action not authorized"),
		_ => SoapError(h, 501, "Action Failed"),
	}
}

fn GetSpecificPortMappingEntry(h: &mut upnphttp, action: &str, ns: &str) {
	let mut data = NameValueParserData::default();

	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);
	let r_host = GetValueFromNameValueList(&data, "NewRemoteHost").unwrap_or_default();
	let ext_port = GetValueFromNameValueList(&data, "NewExternalPort").unwrap_or_default();
	let protocol = GetValueFromNameValueList(&data, "NewProtocol").unwrap_or_default();

	if ext_port.is_empty() || protocol.is_empty() || (cfg!(feature = "strict") && r_host.is_empty()) {
		SoapError(h, 402, "Invalid Args");
		return;
	}

	if cfg!(feature = "strict") && !r_host.is_empty() && r_host != "*" {
		SoapError(h, 726, "RemoteHostOnlySupportsWildcard");
		return;
	}

	let eport = ext_port.parse().unwrap_or(0);
	if eport == 0 {
		SoapError(h, 402, "Invalid Args");
		return;
	}
	let rt = h.rt_options.as_ref().unwrap();
	let proto = proto_atoi(protocol);
	if let Some(r) = rt.nat_impl.get_redirect_rule(|x| x.eport == eport && x.proto == proto) {
		info!(
			"{}: rhost='{}' {} {} found => {}:{} desc='{}' duration={}",
			action,
			r_host,
			ext_port,
			protocol,
			r.iaddr,
			r.iport,
			r.desc.as_ref().map(|x| x.as_str()).unwrap_or_default(),
			r.timestamp
		);
		let desc_rc = r.desc.unwrap_or_default();
		let mut desc = desc_rc.as_str();

		#[cfg(feature = "pcp")]
		let mut desc_s: arrayvec::ArrayString<124>;

		#[cfg(feature = "pcp")]
		if !desc.is_empty() {
			desc_s = arrayvec::ArrayString::from(desc).unwrap_or_default();

			hide_pcp_nonce(unsafe { desc_s.as_bytes_mut() });
			desc = desc_s.as_str();
		}
		let mut body = arrayvec::ArrayString::<1020>::new();

		let _ = body.write_fmt(format_args!(
			"<u:{action}Response xmlns:u=\"{ns}\">\
			<NewInternalPort>{}</NewInternalPort>\
			<NewInternalClient>{}</NewInternalClient>\
			<NewEnabled>1</NewEnabled>\
			<NewPortMappingDescription>{}</NewPortMappingDescription>\
			<NewLeaseDuration>{}</NewLeaseDuration>\
			</u:{action}Response>",
			r.iport, r.iaddr, desc, r.timestamp
		));
		BuildSendAndCloseSoapResp(h, body.as_bytes());
	} else {
		SoapError(h, 714, "NoSuchEntryInArray");
	}
}

fn DeletePortMapping(h: &mut upnphttp, action: &str, ns: &str) {
	let mut data: NameValueParserData = Default::default();
	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	let ext_port = GetValueFromNameValueList(&data, "NewExternalPort");
	let protocol = GetValueFromNameValueList(&data, "NewProtocol").unwrap_or_default();
	let r_host = GetValueFromNameValueList(&data, "NewRemoteHost").unwrap_or_default();

	if ext_port.is_none() || protocol.is_empty() || (cfg!(feature = "strict") && r_host.is_empty()) {
		SoapError(h, 402, "Invalid Args");
		return;
	}
	if cfg!(feature = "strict") && !r_host.is_empty() && r_host != "*" {
		SoapError(h, 726, "RemoteHostOnlySupportsWildcard");
		return;
	}

	let eport = ext_port.unwrap().parse().unwrap_or(0);
	if eport == 0 {
		SoapError(h, 402, "Invalid Args");
		return;
	}

	debug!("{}: external port: {}, protocol: {}", action, eport, protocol);
	let op = global_option.get().unwrap();
	let rt = h.rt_options.as_mut().unwrap();
	let proto = proto_atoi(protocol);
	if GETFLAG!(op.runtime_flags, SECUREMODEMASK)
		&& let Some(e) = upnp_get_redirection_infos(&rt.nat_impl, eport, proto)
			&& h.clientaddr != IpAddr::V4(e.iaddr) {
				if cfg!(feature = "igd2") {
					SoapError(h, 606, "Action not authorized");
				} else {
					SoapError(h, 714, "Action not authorized");
				}
				return;
			}

	let r = upnp_delete_redirection(rt, eport, proto);

	if r < 0 {
		SoapError(h, 714, "NoSuchEntryInArray");
	} else {
		let mut body = arrayvec::ArrayString::<124>::new();
		let _ = body.write_fmt(format_args!(
			"<u:{action}Response xmlns:u=\"{ns}\"> </u:{action}Response>"
		));
		BuildSendAndCloseSoapResp(h, body.as_bytes());
	}
}

fn DeletePortMappingRange(h: &mut upnphttp, action: &str, ns: &str) {
	let mut data: NameValueParserData = Default::default();
	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	let startport_s = GetValueFromNameValueList(&data, "NewStartPort").unwrap_or_default();
	let endport_s = GetValueFromNameValueList(&data, "NewEndPort").unwrap_or_default();
	let protocol = GetValueFromNameValueList(&data, "NewProtocol").unwrap_or_default();

	if startport_s.is_empty()
		|| endport_s.is_empty()
		|| protocol.is_empty()
		|| !startport_s.chars().all(char::is_numeric)
		|| !endport_s.chars().all(char::is_numeric)
	{
		SoapError(h, 402, "Invalid Args");
		return;
	}

	let startport = startport_s.parse().unwrap_or(0);
	let endport = endport_s.parse().unwrap_or(0);

	if startport > endport {
		SoapError(h, 733, "InconsistentParameter");
		return;
	}

	info!(
		"{}: deleting external ports: {}-{}, protocol: {}",
		action, startport, endport, protocol
	);
	let rt = h.rt_options.as_mut().unwrap();
	let proto = proto_atoi(protocol);
	if let Some(port_list) = upnp_get_portmappings_in_range(&rt.nat_impl, startport, endport, proto) {
		for port in port_list {
			let r = upnp_delete_redirection(rt, port, proto);
			debug!(
				"{}: deleting external port: {}, protocol: {}: {}",
				action,
				port,
				proto,
				if r < 0 { "failed" } else { "ok" }
			);
			// TODO: return a SOAP error code when there is at least 1 failure
		}
	} else {
		SoapError(h, 730, "PortMappingNotFound");
		return;
	}
	let mut body = arrayvec::ArrayString::<124>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response xmlns:u=\"{ns}\"></u:{action}Response>"
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes());
}

fn GetGenericPortMappingEntry(h: &mut upnphttp, action: &str, ns: &str) {
	let mut data: NameValueParserData = Default::default();
	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	let m_index = GetValueFromNameValueList(&data, "NewPortMappingIndex");

	if m_index.is_none() {
		SoapError(h, 402, "Invalid Args");
		return;
	}

	let m_index = m_index.unwrap();

	let index = m_index.parse().unwrap_or(-1);

	if index < 0 {
		warn!("GetGenericPortMappingEntry: parse index({}) failed", m_index);
		SoapError(h, 402, "Invalid Args");
		return;
	}

	info!("{}: index={}", action, index);

	let rt = h.rt_options.as_ref().unwrap();
	if let Some(r) = upnp_get_redirection_infos_by_index(&rt.nat_impl, index as usize) {
		let desc_rc = r.desc.unwrap_or_default();
		let mut desc = desc_rc.as_str();

		#[cfg(feature = "pcp")]
		let mut desc_s: arrayvec::ArrayString<124>;

		#[cfg(feature = "pcp")]
		if !desc.is_empty() {
			desc_s = arrayvec::ArrayString::from(desc).unwrap_or_default();

			hide_pcp_nonce(unsafe { desc_s.as_bytes_mut() });
			desc = desc_s.as_str();
		}

		let body = format!(
			"<u:{action}Response xmlns:u=\"{ns}\">\
            <NewRemoteHost>{}</NewRemoteHost>\
            <NewExternalPort>{}</NewExternalPort>\
            <NewProtocol>{}</NewProtocol>\
            <NewInternalPort>{}</NewInternalPort>\
            <NewInternalClient>{}</NewInternalClient>\
            <NewEnabled>1</NewEnabled>\
            <NewPortMappingDescription>{}</NewPortMappingDescription>\
            <NewLeaseDuration>{}</NewLeaseDuration>\
            </u:{action}Response>",
			r.raddr, r.eport, r.proto, r.iport, r.iaddr, desc, r.timestamp
		);
		BuildSendAndCloseSoapResp(h, body.as_bytes());
	} else {
		SoapError(h, 713, "SpecifiedArrayIndexInvalid");
	}
}

fn GetListOfPortMappings(h: &mut upnphttp, action: &str, ns: &str) {
	const list_start: &str = "<p:PortMappingList \
		xmlns:p=\"urn:schemas-upnp-org:gw:WANIPConnection\" \
		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
		xsi:schemaLocation=\"urn:schemas-upnp-org:gw:WANIPConnection http://www.upnp.org/schemas/gw/WANIPConnection-v2.xsd\">";
	const list_end: &str = "</p:PortMappingList>";
	// const entry: &str = "<p:PortMappingEntry><p:NewRemoteHost>{}</p:NewRemoteHost><p:NewExternalPort>{}</p:NewExternalPort><p:NewProtocol>{}</p:NewProtocol><p:NewInternalPort>{}</p:NewInternalPort><p:NewInternalClient>{}</p:NewInternalClient><p:NewEnabled>1</p:NewEnabled><p:NewDescription>{}</p:NewDescription><p:NewLeaseTime>{}</p:NewLeaseTime></p:PortMappingEntry>";

	let mut data: NameValueParserData = Default::default();
	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	let startport_s = GetValueFromNameValueList(&data, "NewStartPort");
	let endport_s = GetValueFromNameValueList(&data, "NewEndPort");
	let protocol = GetValueFromNameValueList(&data, "NewProtocol");
	let number_s = GetValueFromNameValueList(&data, "NewNumberOfPorts");

	if startport_s.is_none()
		|| endport_s.is_none()
		|| protocol.is_none()
		|| number_s.is_none()
		|| !number_s.unwrap().chars().all(|x| x.is_numeric())
		|| !startport_s.unwrap().chars().all(|x| x.is_numeric())
		|| !endport_s.unwrap().chars().all(|x| x.is_numeric())
	{
		SoapError(h, 402, "Invalid Args");

		return;
	}

	let startport = startport_s.unwrap().parse::<u16>().unwrap();
	let endport = endport_s.unwrap().parse::<u16>().unwrap();
	// let number = number_s.unwrap().parse::<i32>().unwrap_or(1000);

	if startport > endport {
		SoapError(h, 733, "InconsistentParameter");

		return;
	}
	let rt = h.rt_options.as_ref().unwrap();

	let mut body = String::with_capacity(4096);
	body.write_fmt(format_args!(
		"<u:{action}Response xmlns:u=\"{ns}\"><NewPortListing><![CDATA[",
	))
	.unwrap();

	body.push_str(list_start);
	let proto = proto_atoi(protocol.unwrap());

	if let Some(port_list) = upnp_get_portmappings_in_range(&rt.nat_impl, startport, endport, proto) {
		for port in port_list {
			if let Some(e) = upnp_get_redirection_infos(&rt.nat_impl, port, proto) {
				let desc_rc = e.desc.unwrap_or_default();
				let mut desc = desc_rc.as_str();

				#[cfg(feature = "pcp")]
				let mut desc_s: arrayvec::ArrayString<124>;

				#[cfg(feature = "pcp")]
				if !desc.is_empty() {
					desc_s = arrayvec::ArrayString::from(desc).unwrap_or_default();

					hide_pcp_nonce(unsafe { desc_s.as_bytes_mut() });
					desc = desc_s.as_str();
				}

				let _ = body.write_fmt(format_args!(
					"<p:PortMappingEntry>\
						<p:NewRemoteHost>{}</p:NewRemoteHost>\
						<p:NewExternalPort>{}</p:NewExternalPort>\
						<p:NewProtocol>{}</p:NewProtocol>\
						<p:NewInternalPort>{}</p:NewInternalPort>\
						<p:NewInternalClient>{}</p:NewInternalClient>\
						<p:NewEnabled>1</p:NewEnabled>\
						<p:NewDescription>{}</p:NewDescription>\
						<p:NewLeaseTime>{}</p:NewLeaseTime>\
						</p:PortMappingEntry>",
					e.raddr,
					e.eport,
					protocol.unwrap_or_default(),
					e.iport,
					e.iaddr,
					desc,
					e.timestamp
				));
			}
		}
	}
	body.push_str(list_end);
	let _ = body.write_fmt(format_args!("]]></NewPortListing></u:{action}Response>"));

	BuildSendAndCloseSoapResp(h, body.as_bytes());
}

fn SetDefaultConnectionService(h: &mut upnphttp, action: &str, ns: &str) {
	let mut data: NameValueParserData = Default::default();
	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	if let Some(p) = GetValueFromNameValueList(&data, "NewDefaultConnectionService") {
		if cfg!(feature = "strict") {
			let service = p.find(',');
			let uuid = uuidvalue_wcd.get().unwrap().fmt_as_array();
			if !(p.starts_with("uuid:") && p.as_bytes()[5..].starts_with(&uuid)) {
				SoapError(h, 720, "InvalidDeviceUUID");
			} else if service.is_none() || !p[service.unwrap() + 1..].starts_with(SERVICE_ID_WANIPC) {
				SoapError(h, 721, "InvalidServiceID");
			} else {
				info!("{}({}) : Ignored", action, p);
				let mut body = arrayvec::ArrayString::<252>::new();
				let _ = body.write_fmt(format_args!(
					"<u:{action}Response xmlns:u=\"{ns}\"></u:{action}Response>"
				));
				BuildSendAndCloseSoapResp(h, body.as_bytes());
			}
		} else {
			info!("{}({}) : Ignored", action, p);
			let mut body = arrayvec::ArrayString::<252>::new();
			let _ = body.write_fmt(format_args!(
				"<u:{action}Response xmlns:u=\"{ns}\"></u:{action}Response>"
			));
			BuildSendAndCloseSoapResp(h, body.as_bytes());
		}
	} else {
		SoapError(h, 402, "Invalid Args");
	}
}

fn GetDefaultConnectionService(h: &mut upnphttp, action: &str, ns: &str) {
	// Example: uuid:44f5824f-c57d-418c-a131-f22b34e14111:WANConnectionDevice:1,
	// urn:upnp-org:serviceId:WANPPPConn1
	let mut body = arrayvec::ArrayString::<508>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response xmlns:u=\"{ns}\">\
		<NewDefaultConnectionService>{}:WANConnectionDevice:{},{SERVICE_ID_WANIPC}</NewDefaultConnectionService>\
		</u:{action}Response>",
		uuidvalue_wcd.get().unwrap(),
		if cfg!(feature = "igd2") { 2 } else { 1 }
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes());
}

fn SetConnectionType(h: &mut upnphttp, _action: &str, _ns: &str) {
	let mut data: NameValueParserData = Default::default();

	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	#[cfg(feature = "strict")]
	{
		let connection_type = GetValueFromNameValueList(&data, "NewConnectionType");
		if connection_type.is_none() {
			SoapError(h, 402, "Invalid Args");
			return;
		}
	}

	SoapError(h, 731, "ReadOnly");
}
fn RequestConnection(h: &mut upnphttp, _action: &str, _ns: &str) {
	SoapError(h, 606, "Action not authorized");
}
fn ForceTermination(h: &mut upnphttp, _action: &str, _ns: &str) {
	SoapError(h, 606, "Action not authorized");
}

fn QueryStateVariable(h: &mut upnphttp, action: &str, ns: &str) {
	let mut data: NameValueParserData = Default::default();

	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	let var_name = GetValueFromNameValueList(&data, "varName").unwrap_or_default();
	if var_name.is_empty() {
		SoapError(h, 402, "Invalid Args");
		return;
	}

	match var_name {
		"ConnectionStatus" => {
			let op = global_option.get().unwrap();
			let status = get_wan_connection_status_str(&op.ext_ifname);
			let mut body = arrayvec::ArrayString::<252>::new();
			let _ = body.write_fmt(format_args!(
				"<u:{action}Response xmlns:u=\"{ns}\">\
                        <return>{status}</return>\
                        </u:{action}Response>",
			));
			BuildSendAndCloseSoapResp(h, body.as_bytes())
		}
		"PortMappingNumberOfEntries" => {
			let rt = h.rt_options.as_ref().unwrap();
			let num = upnp_get_portmapping_number_of_entries(&rt.nat_impl);
			let mut body = arrayvec::ArrayString::<252>::new();
			let _ = body.write_fmt(format_args!(
				"<u:{action}Response xmlns:u=\"{ns}\">\
                <return>{num}</return>\
                </u:{action}Response>"
			));
			BuildSendAndCloseSoapResp(h, body.as_bytes())
		}
		_ => {
			notice!("{}: Unknown: {}", action, var_name);
			SoapError(h, 404, "Invalid Var");
		}
	}
}
#[cfg(feature = "ipv6")]
fn GetFirewallStatus(h: &mut upnphttp, action: &str, ns: &str) {
	let op = global_option.get().unwrap();
	let firewall_enabled: u8 = if GETFLAG!(op.runtime_flags, IPV6FCFWDISABLEDMASK) {
		0
	} else {
		1
	};
	let inbound_pinhole_allowed: u8 = if GETFLAG!(op.runtime_flags, IPV6FCINBOUNDDISALLOWEDMASK) {
		0
	} else {
		1
	};
	let mut body = arrayvec::ArrayString::<508>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response xmlns:u=\"{ns}\">\
            <FirewallEnabled>{firewall_enabled}</FirewallEnabled>\
            <InboundPinholeAllowed>{inbound_pinhole_allowed}</InboundPinholeAllowed>\
            </u:{action}Response>"
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes())
}
#[cfg(feature = "ipv6")]
fn CheckStatus(h: &mut upnphttp) -> bool {
	let runtime_flag = global_option.get().unwrap().runtime_flags;
	if GETFLAG!(runtime_flag, IPV6FCFWDISABLEDMASK) {
		SoapError(h, 702, "FirewallDisabled");
		false
	} else if GETFLAG!(runtime_flag, IPV6FCINBOUNDDISALLOWEDMASK) {
		SoapError(h, 703, "InboundPinholeNotAllowed");
		return false;
	} else {
		return true;
	}
}
#[cfg(feature = "ipv6")]
fn PinholeVerification(h: &mut upnphttp, int_ip: &str, int_port: u16, iaddr: &mut Ipv6Addr) -> i32 {
	let result_ip;
	if let Ok(addr) = int_ip.parse::<Ipv6Addr>() {
		result_ip = addr;
	} else {
		info!(
			"PinholeVerification: InternalClient {} is not an IPv6, assume hostname and convert",
			int_ip
		);

		if let Ok(mut addrs) = (int_ip, int_port).to_socket_addrs() {
			if let Some(SocketAddr::V6(addr)) = addrs.find(|x| x.is_ipv6()) {
				info!("PinholeVerification: InternalClient resolved as {}", addr.ip());
				result_ip = *addr.ip();
			} else {
				notice!("PinholeVerification: No IPv6 address for hostname '{}'", int_ip);
				SoapError(h, 402, "Invalid Args");
				return -1;
			}
		} else {
			warn!(
				"PinholeVerification: Failed to convert hostname '{}' to IP address : ",
				int_ip
			);
			SoapError(h, 402, "Invalid Args");
			return -1;
		}
	}
	if h.clientaddr != IpAddr::V6(result_ip) {
		info!(
			"PinholeVerification: Client {} tried to access pinhole for internal {} and is not authorized",
			h.clientaddr, int_ip
		);
		SoapError(h, 606, "Action not authorized");
		return 0;
	} else {
		trace!(
			"PinholeVerification: sender {} == InternalClient {}",
			h.clientaddr, int_ip
		);
	}

	if int_port < 1024 {
		info!(
			"Client {} tried to access pinhole with port < 1024 and is not authorized to do it",
			h.clientaddr
		);
		SoapError(h, 606, "Action not authorized");
		return 0;
	}
	*iaddr = result_ip;
	1
}
#[cfg(feature = "ipv6")]
fn AddPinhole(h: &mut upnphttp, action: &str, ns: &str) {
	if !CheckStatus(h) {
		return;
	}

	let mut data: NameValueParserData = Default::default();
	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	let rem_host = GetValueFromNameValueList(&data, "RemoteHost");
	let rem_port = GetValueFromNameValueList(&data, "RemotePort");
	let int_ip = GetValueFromNameValueList(&data, "InternalClient").unwrap_or_default();
	let int_port = GetValueFromNameValueList(&data, "InternalPort");
	let protocol = GetValueFromNameValueList(&data, "Protocol").unwrap_or_default();
	let lease_time = GetValueFromNameValueList(&data, "LeaseTime");

	#[cfg(feature = "strict")]
	{
		if rem_port.is_none() || rem_port.unwrap().is_empty() || int_port.is_none() || int_port.unwrap().is_empty() {
			SoapError(h, 402, "Invalid Args");
			return;
		}
	}

	let rport = rem_port.map(|p| p.parse::<u16>().unwrap_or(0)).unwrap_or(0);
	let iport = int_port.map(|p| p.parse::<u16>().unwrap_or(0)).unwrap_or(0);
	let ltime = lease_time.map(|t| t.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
	let proto = protocol.parse::<i32>().unwrap_or(-1);

	if !(0..=65535).contains(&proto) {
		SoapError(h, 402, "Invalid Args");
		return;
	}

	if iport == 0 {
		SoapError(h, 706, "InternalPortWildcardingNotAllowed");
		return;
	}

	if int_ip.is_empty() || int_ip == "*" {
		SoapError(h, 708, "WildCardNotPermittedInSrcIP");
		return;
	}

	let rem_host = rem_host.map(|h| h.trim()).unwrap_or("");

	let rem_ip = if !rem_host.is_empty() && rem_host != "*" {
		match std::net::ToSocketAddrs::to_socket_addrs(&(rem_host, rport)) {
			Ok(mut addrs) => {
				if let Some(SocketAddr::V6(addr)) = addrs.find(|a| a.is_ipv6()) {
					Some(*addr.ip())
				} else {
					None
				}
			}
			Err(e) => {
				warn!("AddPinhole: getaddrinfo({}) failed: {}", rem_host, e);
				None
			}
		}
	} else {
		None
	};

	if proto == 65535 {
		SoapError(h, 707, "ProtocolWildcardingNotAllowed");
		return;
	}

	if proto != UDP as i32 && proto != TCP as i32 {
		SoapError(h, 705, "ProtocolNotSupported");
		return;
	}

	if !(1..=86400).contains(&ltime) {
		warn!("{}: LeaseTime={} not supported, (ip={})", action, ltime, int_ip);
		SoapError(h, 402, "Invalid Args");
		return;
	}
	let mut iaddr = Ipv6Addr::UNSPECIFIED;
	if PinholeVerification(h, int_ip, iport, &mut iaddr) <= 0 {
		return;
	}

	info!(
		"{}: (inbound) from [{}]:{} to [{}]:{} with proto {} during {} sec",
		action,
		rem_ip.unwrap_or(Ipv6Addr::UNSPECIFIED),
		rport,
		int_ip,
		iport,
		proto,
		ltime
	);
	let rt = h.rt_options.as_mut().unwrap();
	let op = global_option.get().unwrap();
	let mut new_uid = 0u16;
	let pinhole = PinholeEntry {
		raddr: rem_ip.unwrap_or(Ipv6Addr::UNSPECIFIED),
		rport,
		iport,
		proto: proto as u8,
		iaddr,
		desc: Some("IGD2 pinhole".into()),
		timestamp: upnp_time().as_secs() + ltime as u64,
		..Default::default()
	};
	match upnp_add_inboundpinhole(op, &mut rt.nat_impl, &pinhole, &mut new_uid) {
		1 => {
			let mut body = arrayvec::ArrayString::<252>::new();
			let _ = body.write_fmt(format_args!(
				"<u:{action}Response xmlns:u=\"{ns}\"><UniqueID>{new_uid}</UniqueID></u:{action}Response>"
			));
			BuildSendAndCloseSoapResp(h, body.as_bytes());
		}
		-1 => {
			SoapError(h, 701, "PinholeSpaceExhausted");
		}
		_ => {
			SoapError(h, 501, "Action Failed");
		}
	};
	// 606 Action not authorized
	// 701 PinholeSpaceExhausted
	// 702 FirewallDisabled
	// 703 InboundPinholeNotAllowed
	// 705 ProtocolNotSupported
	// 706 InternalPortWildcardingNotAllowed
	// 707 ProtocolWildcardingNotAllowed
	// 708 WildCardNotPermittedInSrcIP
}
#[cfg(feature = "ipv6")]
fn UpdatePinhole(h: &mut upnphttp, action: &str, ns: &str) {
	if !CheckStatus(h) {
		return;
	}

	let mut data: NameValueParserData = Default::default();
	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	let uid_str = GetValueFromNameValueList(&data, "UniqueID");
	let lease_time = GetValueFromNameValueList(&data, "NewLeaseTime");
	let uid = uid_str.map(|s| s.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
	let ltime = lease_time.map(|t| t.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);

	if !(0..=65535).contains(&uid) || ltime <= 0 || ltime > 86400 {
		SoapError(h, 402, "Invalid Args");
		return;
	}

	let rt = h.rt_options.as_mut().unwrap();
	if let Some(n) = upnp_get_pinhole_info(&mut rt.nat_impl, uid as u16) {
		if IpAddr::V6(n.iaddr) != h.clientaddr || n.iport < 1024 {
			SoapError(h, 606, "Action not authorized");
			return;
		}
	} else {
		SoapError(h, 704, "NoSuchEntry");
		return;
	}

	info!(
		"{}: (inbound) updating lease duration to {} for pinhole with ID: {}",
		action, ltime, uid
	);

	let n = upnp_update_inboundpinhole(&mut rt.nat_impl, uid as u16, ltime as u32);
	match n {
		-1 => SoapError(h, 704, "NoSuchEntry"),
		_ if n < 0 => SoapError(h, 501, "Action Failed"),
		_ => {
			let mut body = arrayvec::ArrayString::<124>::new();
			let _ = body.write_fmt(format_args!(
				"<u:{action}Response xmlns:u=\"{ns}\"> </u:{action}Response>",
			));
			BuildSendAndCloseSoapResp(h, body.as_bytes());
		}
	}
}
#[cfg(feature = "ipv6")]
fn GetOutboundPinholeTimeout(h: &mut upnphttp, action: &str, ns: &str) {
	let op = global_option.get().unwrap();
	if GETFLAG!(op.runtime_flags, IPV6FCFWDISABLEDMASK) {
		SoapError(h, 702, "FirewallDisabled");
		return;
	}

	let mut data: NameValueParserData = Default::default();
	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	let int_ip = GetValueFromNameValueList(&data, "InternalClient");
	let int_port = GetValueFromNameValueList(&data, "InternalPort");
	let rem_host = GetValueFromNameValueList(&data, "RemoteHost");
	let rem_port = GetValueFromNameValueList(&data, "RemotePort");
	let protocol = GetValueFromNameValueList(&data, "Protocol");

	if int_port.is_none() || rem_port.is_none() || protocol.is_none() {
		SoapError(h, 402, "Invalid Args");
		return;
	}

	let rport = rem_port.unwrap().parse::<u16>().unwrap_or(0);
	let iport = int_port.unwrap().parse::<u16>().unwrap_or(0);

	info!(
		"{}: retrieving timeout for outbound pinhole from [{}]:{} to [{}]:{} protocol {}",
		action,
		int_ip.unwrap_or_default(),
		iport,
		rem_host.unwrap_or_default(),
		rport,
		protocol.unwrap_or_default()
	);

	// TODO: Implement outbound pinhole timeout retrieval logic
	let r = -1; // Placeholder for upnp_check_outbound_pinhole(proto, &opt);

	match r {
		1 => {
			let opt = 0; // Placeholder for the actual timeout value
			let mut body = arrayvec::ArrayString::<252>::new();
			let _ = body.write_fmt(format_args!(
				"<u:{action}Response xmlns:u=\"{ns}\">\
                <OutboundPinholeTimeout>{opt}</OutboundPinholeTimeout>\
                </u:{action}Response>"
			));
			BuildSendAndCloseSoapResp(h, body.as_bytes());
		}
		-5 => SoapError(h, 705, "ProtocolNotSupported"),
		_ => SoapError(h, 501, "Action Failed"),
	}
}
#[cfg(feature = "ipv6")]
fn DeletePinhole(h: &mut upnphttp, action: &str, ns: &str) {
	if !CheckStatus(h) {
		return;
	}

	let mut data: NameValueParserData = Default::default();
	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	let uid_str = GetValueFromNameValueList(&data, "UniqueID");
	let uid = uid_str.map(|s| s.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);

	if !(0..=65535).contains(&uid) {
		SoapError(h, 402, "Invalid Args");
		return;
	}

	let rt = h.rt_options.as_mut().unwrap();
	if let Some(n) = upnp_get_pinhole_info(&mut rt.nat_impl, uid as u16) {
		if IpAddr::V6(n.iaddr) != h.clientaddr || n.iport < 1024 {
			SoapError(h, 606, "Action not authorized");
			return;
		}
	} else {
		SoapError(h, 704, "NoSuchEntry");
		return;
	}

	let n = upnp_delete_inboundpinhole(&mut rt.nat_impl, uid as u16);
	if n < 0 {
		info!("{}: (inbound) failed to remove pinhole with ID: {}", action, uid);
		SoapError(h, 501, "Action Failed");
		return;
	}

	info!("{}: (inbound) pinhole with ID {} successfully removed", action, uid);
	let mut body = arrayvec::ArrayString::<124>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response xmlns:u=\"{ns}\"></u:{action}Response>"
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes());
}
#[cfg(feature = "ipv6")]
fn CheckPinholeWorking(h: &mut upnphttp, action: &str, ns: &str) {
	if !CheckStatus(h) {
		return;
	}

	let mut data: NameValueParserData = Default::default();
	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	let uid_str = GetValueFromNameValueList(&data, "UniqueID");
	let uid = uid_str.map(|s| s.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);

	if !(0..=65535).contains(&uid) {
		SoapError(h, 402, "Invalid Args");
		return;
	}

	let rt = h.rt_options.as_mut().unwrap();
	if let Some(n) = upnp_get_pinhole_info(&mut rt.nat_impl, uid as u16) {
		if IpAddr::V6(n.iaddr) != h.clientaddr || n.iport < 1024 {
			SoapError(h, 606, "Action not authorized");
			return;
		}
		if n.packets == 0 {
			SoapError(h, 709, "NoTrafficReceived");
			return;
		}
		let mut body = arrayvec::ArrayString::<252>::new();

		let _ = body.write_fmt(format_args!(
			"<u:{action}Response xmlns:u=\"{ns}\"><IsWorking>1</IsWorking></u:{action}Response>"
		));
		BuildSendAndCloseSoapResp(h, body.as_bytes());
	} else {
		SoapError(h, 704, "NoSuchEntry");
	}
}
#[cfg(feature = "ipv6")]
fn GetPinholePackets(h: &mut upnphttp, action: &str, ns: &str) {
	if !CheckStatus(h) {
		return;
	}

	let mut data: NameValueParserData = Default::default();
	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	let uid_str = GetValueFromNameValueList(&data, "UniqueID");
	let uid = uid_str.map(|s| s.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);

	if !(0..=65535).contains(&uid) {
		SoapError(h, 402, "Invalid Args");
		return;
	}

	let rt = h.rt_options.as_mut().unwrap();
	if let Some(n) = upnp_get_pinhole_info(&mut rt.nat_impl, uid as u16) {
		if IpAddr::V6(n.iaddr) != h.clientaddr || n.iport < 1024 {
			SoapError(h, 606, "Action not authorized");
			return;
		}
		let mut body = arrayvec::ArrayString::<252>::new();
		let _ = body.write_fmt(format_args!(
			"<u:{action}Response xmlns:u=\"{ns}\">\
            <PinholePackets>{}</PinholePackets>\
            </u:{action}Response>",
			n.packets
		));
		BuildSendAndCloseSoapResp(h, body.as_bytes());
	} else {
		SoapError(h, 704, "NoSuchEntry");
	}
}
#[cfg(feature = "dp_service")]
fn SendSetupMessage(h: &mut upnphttp, action: &str, ns: &str) {
	let mut data: NameValueParserData = Default::default();
	ParseNameValue(h.get_req_str_from(h.req_contentoff), &mut data);

	let protocol_type = GetValueFromNameValueList(&data, "ProtocolType");
	let in_message = GetValueFromNameValueList(&data, "InMessage");

	if protocol_type.is_none() || in_message.is_none() {
		SoapError(h, 402, "Invalid Args");
		return;
	}

	if protocol_type.unwrap() != "WPS" {
		SoapError(h, 600, "Argument Value Invalid");
		return;
	}

	const out_message: &str = ""; // Placeholder for WPS output message
	let mut body = arrayvec::ArrayString::<252>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response  xmlns:u=\"{ns}\">\
        <OutMessage>{out_message}</OutMessage>\
        </u:{action}Response>"
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes());
}
#[cfg(feature = "dp_service")]
fn GetSupportedProtocols(h: &mut upnphttp, action: &str, ns: &str) {
	const PROTOCOL_LIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<SupportedProtocols xmlns="urn:schemas-upnp-org:gw:DeviceProtection"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="urn:schemas-upnp-org:gw:DeviceProtection
 http://www.upnp.org/schemas/gw/DeviceProtection-v1.xsd">
<Introduction><Name>WPS</Name></Introduction>
<Login><Name>PKCS5</Name></Login>
</SupportedProtocols>"#;

	let body = format!(
		"<u:{action}Response  xmlns:u=\"{ns}\">\
        <ProtocolList><![CDATA[{PROTOCOL_LIST}]]></ProtocolList>\
        </u:{action}Response>",
	);
	BuildSendAndCloseSoapResp(h, body.as_bytes());
}
#[cfg(feature = "dp_service")]
fn GetAssignedRoles(h: &mut upnphttp, action: &str, ns: &str) {
	let mut role_list = "Public"; // Default role list

	#[cfg(feature = "https")]
	{
		#[cfg(not(openssl3))]
		use openssl_sys::SSL_get_peer_certificate as peer_fn;
		#[cfg(openssl3)]
		use openssl_sys::SSL_get0_peer_certificate as peer_fn;

		use openssl_sys::X509_free;
		if !h.ssl.is_none() {
			let peer_cert = unsafe { peer_fn(h.ssl.as_ptr()) };
			if !peer_cert.is_null() {
				role_list = "Admin Basic"; // Update role list based on client certificate
				unsafe { X509_free(peer_cert) };
			}
		}
	}
	let mut body = arrayvec::ArrayString::<252>::new();
	let _ = body.write_fmt(format_args!(
		"<u:{action}Response xmlns:u=\"{ns}\">\
        <RoleList>{role_list}</RoleList>\
        </u:{action}Response>"
	));
	BuildSendAndCloseSoapResp(h, body.as_bytes());
}

const soapMethods: &[soapMethod] = &[
	/* WANCommonInterfaceConfig */
	soapMethod { methodName: "QueryStateVariable", methodImpl: QueryStateVariable },
	soapMethod { methodName: "GetTotalBytesSent", methodImpl: GetTotalBytesSent },
	soapMethod { methodName: "GetTotalBytesReceived", methodImpl: GetTotalBytesReceived },
	soapMethod { methodName: "GetTotalPacketsSent", methodImpl: GetTotalPacketsSent },
	soapMethod { methodName: "GetTotalPacketsReceived", methodImpl: GetTotalPacketsReceived },
	soapMethod { methodName: "GetCommonLinkProperties", methodImpl: GetCommonLinkProperties },
	soapMethod { methodName: "GetStatusInfo", methodImpl: GetStatusInfo },
	/* WANIPConnection */
	soapMethod { methodName: "GetConnectionTypeInfo", methodImpl: GetConnectionTypeInfo },
	soapMethod { methodName: "GetNATRSIPStatus", methodImpl: GetNATRSIPStatus },
	soapMethod { methodName: "GetExternalIPAddress", methodImpl: GetExternalIPAddress },
	soapMethod { methodName: "AddPortMapping", methodImpl: AddPortMapping },
	soapMethod { methodName: "DeletePortMapping", methodImpl: DeletePortMapping },
	soapMethod { methodName: "GetGenericPortMappingEntry", methodImpl: GetGenericPortMappingEntry },
	soapMethod { methodName: "GetSpecificPortMappingEntry", methodImpl: GetSpecificPortMappingEntry },
	/* Required in WANIPConnection:2 */
	soapMethod { methodName: "SetConnectionType", methodImpl: SetConnectionType },
	soapMethod { methodName: "RequestConnection", methodImpl: RequestConnection },
	soapMethod { methodName: "ForceTermination", methodImpl: ForceTermination },
	soapMethod { methodName: "AddAnyPortMapping", methodImpl: AddAnyPortMapping },
	soapMethod { methodName: "DeletePortMappingRange", methodImpl: DeletePortMappingRange },
	soapMethod { methodName: "GetListOfPortMappings", methodImpl: GetListOfPortMappings },
	/* Layer3Forwarding */
	soapMethod { methodName: "SetDefaultConnectionService", methodImpl: SetDefaultConnectionService },
	soapMethod { methodName: "GetDefaultConnectionService", methodImpl: GetDefaultConnectionService },
	/* WANIPv6FirewallControl */
	#[cfg(feature = "ipv6")]
	soapMethod { methodName: "GetFirewallStatus", methodImpl: GetFirewallStatus }, /* Required */
	#[cfg(feature = "ipv6")]
	soapMethod { methodName: "AddPinhole", methodImpl: AddPinhole }, /* Required */
	#[cfg(feature = "ipv6")]
	soapMethod { methodName: "UpdatePinhole", methodImpl: UpdatePinhole }, /* Required */
	#[cfg(feature = "ipv6")]
	soapMethod { methodName: "GetOutboundPinholeTimeout", methodImpl: GetOutboundPinholeTimeout }, /* Optional */
	#[cfg(feature = "ipv6")]
	soapMethod { methodName: "DeletePinhole", methodImpl: DeletePinhole }, /* Required */
	#[cfg(feature = "ipv6")]
	soapMethod { methodName: "CheckPinholeWorking", methodImpl: CheckPinholeWorking }, /* Optional */
	#[cfg(feature = "ipv6")]
	soapMethod { methodName: "GetPinholePackets", methodImpl: GetPinholePackets }, /* Required */
	/* DeviceProtection */
	#[cfg(feature = "dp_service")]
	soapMethod { methodName: "SendSetupMessage", methodImpl: SendSetupMessage }, /* Required */
	#[cfg(feature = "dp_service")]
	soapMethod { methodName: "GetSupportedProtocols", methodImpl: GetSupportedProtocols }, /* Required */
	#[cfg(feature = "dp_service")]
	soapMethod { methodName: "GetAssignedRoles", methodImpl: GetAssignedRoles }, /* Required */
];

pub fn ExecuteSoapAction(h: &mut upnphttp) {
	/* SoapAction example :
	 * urn:schemas-upnp-org:service:WANIPConnection:1#GetStatusInfo */

	let mut action = arrayvec::ArrayString::<124>::new();
	let _ = action.try_push_str(h.get_req_str_from(h.req_soapActionOff));

	let splited = action.split_once('#');
	if splited.is_none() {
		notice!("cannot parse SoapAction");
		SoapError(h, 401, "Invalid Action");
		return;
	}
	let (mut ns, mut p) = splited.unwrap();
	ns = ns.trim_start_matches('"');
	p = p.trim_end_matches('"');

	for i in soapMethods {
		if i.methodName == p {
			trace!("Remote Call of SoapMethod '{}' {}", i.methodName, ns);
			(i.methodImpl)(h, i.methodName, ns);
			return;
		}
	}

	notice!("SoapMethod: Unknown: {} {}", p, ns);
	SoapError(h, 401, "Invalid Action");
}

pub fn SoapError(h: &mut upnphttp, errCode: i32, errDesc: &str) {
	let mut body = arrayvec::ArrayString::<1020>::new();
	let _ = body.write_fmt(format_args!(
		"<s:Envelope \
        xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
        s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
        <s:Body>\
        <s:Fault>\
        <faultcode>s:Client</faultcode>\
        <faultstring>UPnPError</faultstring>\
        <detail>\
        <UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\
        <errorCode>{errCode}</errorCode>\
        <errorDescription>{errDesc}</errorDescription>\
        </UPnPError>\
        </detail>\
        </s:Fault>\
        </s:Body>\
        </s:Envelope>"
	));
	info!("Returning UPnPError {}: {}", errCode, errDesc);

	BuildResp2_upnphttp(h, 500, "Internal Server Error", Some(body.as_bytes()));
	SendRespAndClose_upnphttp(h);
}
