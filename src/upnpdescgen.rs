#![allow(dead_code)]

/* Event magical values codes */
use crate::getconnstatus::get_wan_connection_status_str;
use crate::getifaddr::{addr_is_reserved, getifaddr};
use std::fmt::Write;

use crate::miniupnpdpath::*;
use crate::options::RtOptions;
use crate::upnpdescstrings::*;

use crate::upnpglobalvars::OnceCell;
use crate::upnpglobalvars::*;
#[cfg(feature = "ipv6")]
use crate::upnpglobalvars::{IPV6FCFWDISABLEDMASK, IPV6FCINBOUNDDISALLOWEDMASK};
use crate::upnpredirect::upnp_get_portmapping_number_of_entries;
use crate::upnpurns::*;
use crate::uuid::UUID;
use std::net::Ipv4Addr;

type MAGICALVALUE = u8;

const SETUPREADY_MAGICALVALUE: MAGICALVALUE = 248;
const CONNECTIONSTATUS_MAGICALVALUE: MAGICALVALUE = 249;
const FIREWALLENABLED_MAGICALVALUE: MAGICALVALUE = 250;
const INBOUNDPINHOLEALLOWED_MAGICALVALUE: MAGICALVALUE = 251;
const SYSTEMUPDATEID_MAGICALVALUE: MAGICALVALUE = 252;
const PORTMAPPINGNUMBEROFENTRIES_MAGICALVALUE: MAGICALVALUE = 253;
const EXTERNALIPADDRESS_MAGICALVALUE: MAGICALVALUE = 254;
const DEFAULTCONNECTIONSERVICE_MAGICALVALUE: MAGICALVALUE = 255;

struct XMLElt {
	pub eltname: &'static str,
	pub data: XMLEltData,
}
#[derive(PartialEq)]
enum XMLEltData {
	/// offset, num "[XMLElt]" for [rootDesc]
	value(u16, u16),
	/// value type for leaf node
	str(&'static str),
	uuid(&'static OnceCell<UUID>),
	dyn_str(&'static OnceCell<Box<str>>),
}

struct serviceDesc {
	pub actionList: &'static [action],
	pub serviceStateTable: &'static [stateVar],
}
const sendEvent: u8 = 0x80;

struct stateVar {
	pub name: &'static str,
	/// MSB: sendEvent flag,
	/// 7 LSB: index in [`upnptypes`]
	pub itype: u8,
	/// default value [`upnpdefaultvalues`]
	pub idefault: u8,
	/// index in allowed values list or in allowed range list
	/// [`upnpallowedvalues`]
	pub iallowedlist: u8,
	/// fixed value returned or magical values [`MAGICALVALUE`]
	pub ieventvalue: u8,
}
impl stateVar {
	const fn default() -> Self {
		Self { name: "", itype: 0, idefault: 0, iallowedlist: 0, ieventvalue: 0 }
	}
}

struct action {
	pub name: &'static str,
	pub args: Option<&'static [argument]>,
}

const NO_NEW: u8 = 0x80;
const NAME_INDEX_MASK: u8 = 0x7c;
const IN: u8 = 1;
const OUT: u8 = 2;
const INOUT_MASK: u8 = 0x3;
macro_rules! index {
	($value:expr) => {
		$value << 2
	};
}
// #[derive(Copy, Clone)]
// #[repr(C)]
struct argument {
	/// the name of the arg is obtained from the variable
	/// MSB : don't append "New" Flag, [`NO_NEW`]
	/// 5 Medium bits : magic argument name index
	/// 2 LSB : 1 = [`IN`], 2 = [`OUT`]
	pub dir: u8,
	/// index of the related variable [`stateVar`]
	pub relatedVar: u8,
}

const upnptypes: [&str; 5] = ["string", "boolean", "ui2", "ui4", "bin.base64"];
const upnpdefaultvalues: [&str; 7] = ["", "IP_Routed", "3600", "Unconfigured", "0", "1", "ERROR_NONE"];
const upnpallowedvalues: [&str; 29] = [
	"",    // 0
	"DSL", // 1
	"POTS",
	"Cable",
	"Ethernet",
	"",
	"Up", // 6
	"Down",
	"Initializing",
	"Unavailable",
	"",
	"TCP", // 11
	"UDP",
	"",
	"Unconfigured", // 14
	"IP_Routed",
	"IP_Bridged",
	"",
	"Unconfigured", // 18
	"Connecting",
	"Connected",
	"PendingDisconnect",
	"Disconnecting",
	"Disconnected",
	"",
	"ERROR_NONE", // 25
	"",
	"", // 27
	"",
];
const upnpallowedranges: [i32; 9] = [
	0, 0, // 1 PortMappingLeaseDuration
	604800, 1, // 3 InternalPort
	65535, 1, // 5 LeaseTime
	86400, 100, // 7 OutboundPinholeTimeout
	200,
];
const magicargname: &[&str] = &[
	"",
	"StartPort",
	"EndPort",
	"RemoteHost",
	"RemotePort",
	"InternalClient",
	"InternalPort",
	"IsWorking",
	#[cfg(feature = "dp_service")]
	"ProtocolType", // 8
	#[cfg(feature = "dp_service")]
	"InMessage",
	#[cfg(feature = "dp_service")]
	"OutMessage",
	#[cfg(feature = "dp_service")]
	"ProtocolList",
	#[cfg(feature = "dp_service")]
	"RoleList",
];
const xmlver: &str = "<?xml version=\"1.0\"?>\r\n";
const root_service: &str = "scpd xmlns=\"urn:schemas-upnp-org:service-1-0\"";
const root_device: &str = "root xmlns=\"urn:schemas-upnp-org:device-1-0\"";

#[cfg(feature = "ipv6")]
const SERVICES_OFFSET: u16 = 63;
#[cfg(not(feature = "ipv6"))]
const SERVICES_OFFSET: u16 = 58;

/// root Description of the UPnP Device
/// fixed to match UPnP_IGD_InternetGatewayDevice 1.0.pdf
/// Needs to be checked with UPnP-gw-InternetGatewayDevice-v2-Device.pdf
/// presentationURL is only "recommended" but the router doesn't appears
/// in "Network connections" in Windows XP if it is not present.
static rootDesc: &[XMLElt] = &[
	// 0
	XMLElt { eltname: root_device, data: XMLEltData::value(1, 2) },
	XMLElt { eltname: "specVersion", data: XMLEltData::value(3, 2) },
	#[cfg(feature = "dp_service")]
	XMLElt { eltname: "device", data: XMLEltData::value(5, 13) },
	#[cfg(not(any(feature = "dp_service")))]
	XMLElt { eltname: "device", data: XMLEltData::value(5, 12) },
	XMLElt { eltname: "/major", data: XMLEltData::str(UPNP_VERSION_MAJOR_STR) },
	XMLElt { eltname: "/minor", data: XMLEltData::str(UPNP_VERSION_MINOR_STR) },
	// 5
	XMLElt { eltname: "/deviceType", data: XMLEltData::str(DEVICE_TYPE_IGD) },
	XMLElt { eltname: "/friendlyName", data: XMLEltData::str(ROOTDEV_FRIENDLYNAME) },
	XMLElt { eltname: "/manufacturer", data: XMLEltData::str(ROOTDEV_MANUFACTURER) },
	// 8
	XMLElt { eltname: "/manufacturerURL", data: XMLEltData::str(WANCDEV_MANUFACTURERURL) },
	XMLElt { eltname: "/modelDescription", data: XMLEltData::str(WANCDEV_MODELDESCRIPTION) },
	XMLElt { eltname: "/modelName", data: XMLEltData::str(ROOTDEV_MODELNAME) },
	XMLElt { eltname: "/modelNumber", data: XMLEltData::dyn_str(&modelnumber) },
	XMLElt { eltname: "/modelURL", data: XMLEltData::str(ROOTDEV_MODELURL) },
	XMLElt { eltname: "/serialNumber", data: XMLEltData::dyn_str(&serialnumber) },
	XMLElt { eltname: "/UDN", data: XMLEltData::uuid(&uuidvalue_igd) },
	XMLElt { eltname: "serviceList", data: XMLEltData::value(SERVICES_OFFSET, 1) },
	XMLElt { eltname: "deviceList", data: XMLEltData::value(18, 1) },
	XMLElt { eltname: "/presentationURL", data: XMLEltData::dyn_str(&presentationurl) },
	// 18
	XMLElt { eltname: "device", data: XMLEltData::value(19, 13) },
	XMLElt { eltname: "/deviceType", data: XMLEltData::str("urn:schemas-upnp-org:device:WANDevice:2") },
	XMLElt { eltname: "/friendlyName", data: XMLEltData::str("WANDevice") },
	XMLElt { eltname: "/manufacturer", data: XMLEltData::str("MiniUPnP") },
	XMLElt { eltname: "/manufacturerURL", data: XMLEltData::str(WANCDEV_MANUFACTURERURL) },
	XMLElt { eltname: "/modelDescription", data: XMLEltData::str(WANCDEV_MODELDESCRIPTION) },
	XMLElt { eltname: "/modelName", data: XMLEltData::str(WANCDEV_MODELNAME) },
	XMLElt { eltname: "/modelNumber", data: XMLEltData::str(WANCDEV_MODELNUMBER) },
	XMLElt { eltname: "/modelURL", data: XMLEltData::str(WANCDEV_MODELURL) },
	XMLElt { eltname: "/serialNumber", data: XMLEltData::dyn_str(&serialnumber) },
	XMLElt { eltname: "/UDN", data: XMLEltData::uuid(&uuidvalue_wan) },
	XMLElt { eltname: "/UPC", data: XMLEltData::str(WANCDEV_UPC) },
	// 30
	XMLElt { eltname: "serviceList", data: XMLEltData::value(32, 1) },
	XMLElt { eltname: "deviceList", data: XMLEltData::value(38, 1) },
	// 32
	XMLElt { eltname: "service", data: XMLEltData::value(33, 5) },
	// 33
	XMLElt {
		eltname: "/serviceType",
		data: XMLEltData::str("urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"),
	},
	XMLElt { eltname: "/serviceId", data: XMLEltData::str("urn:upnp-org:serviceId:WANCommonIFC1") },
	XMLElt { eltname: "/SCPDURL", data: XMLEltData::str(WANCFG_PATH) },
	XMLElt { eltname: "/controlURL", data: XMLEltData::str(WANCFG_CONTROLURL) },
	XMLElt { eltname: "/eventSubURL", data: XMLEltData::str(WANCFG_EVENTURL) },
	// 38
	XMLElt { eltname: "device", data: XMLEltData::value(39, 12) },
	// 39
	XMLElt { eltname: "/deviceType", data: XMLEltData::str(DEVICE_TYPE_WANC) },
	XMLElt { eltname: "/friendlyName", data: XMLEltData::str(WANCDEV_FRIENDLYNAME) },
	XMLElt { eltname: "/manufacturer", data: XMLEltData::str(WANCDEV_MANUFACTURER) },
	XMLElt { eltname: "/manufacturerURL", data: XMLEltData::str(WANCDEV_MANUFACTURERURL) },
	XMLElt { eltname: "/modelDescription", data: XMLEltData::str(WANCDEV_MODELDESCRIPTION) },
	XMLElt { eltname: "/modelName", data: XMLEltData::str("MiniUPnPd") },
	XMLElt { eltname: "/modelNumber", data: XMLEltData::str("20250113") },
	XMLElt { eltname: "/modelURL", data: XMLEltData::str("https://miniupnp.tuxfamily.org/") },
	XMLElt { eltname: "/serialNumber", data: XMLEltData::dyn_str(&serialnumber) },
	XMLElt { eltname: "/UDN", data: XMLEltData::uuid(&uuidvalue_wcd) },
	XMLElt { eltname: "/UPC", data: XMLEltData::str(WANDEV_UPC) },
	XMLElt { eltname: "serviceList", data: XMLEltData::value(51, 2) },
	// 51
	XMLElt { eltname: "service", data: XMLEltData::value(53, 5) },
	XMLElt { eltname: "service", data: XMLEltData::value(58, 5) },
	// 53
	XMLElt { eltname: "/serviceType", data: XMLEltData::str("urn:schemas-upnp-org:service:WANIPConnection:2") },
	XMLElt { eltname: "/serviceId", data: XMLEltData::str("urn:upnp-org:serviceId:WANIPConn1") },
	XMLElt { eltname: "/SCPDURL", data: XMLEltData::str("/WANIPCn.xml") },
	XMLElt { eltname: "/controlURL", data: XMLEltData::str("/ctl/IPConn") },
	XMLElt { eltname: "/eventSubURL", data: XMLEltData::str("/evt/IPConn") },
	// 58
	#[cfg(feature = "ipv6")]
	XMLElt {
		eltname: "/serviceType",
		data: XMLEltData::str("urn:schemas-upnp-org:service:WANIPv6FirewallControl:1"),
	},
	#[cfg(feature = "ipv6")]
	XMLElt { eltname: "/serviceId", data: XMLEltData::str("urn:upnp-org:serviceId:WANIPv6Firewall1") },
	#[cfg(feature = "ipv6")]
	XMLElt { eltname: "/SCPDURL", data: XMLEltData::str(WANIP6FC_PATH) },
	#[cfg(feature = "ipv6")]
	XMLElt { eltname: "/controlURL", data: XMLEltData::str(WANIP6FC_CONTROLURL) },
	#[cfg(feature = "ipv6")]
	XMLElt { eltname: "/eventSubURL", data: XMLEltData::str(WANIP6FC_EVENTURL) },
	// 58/63 SERVICES_OFFSET
	XMLElt { eltname: "service", data: XMLEltData::value(SERVICES_OFFSET + 2, 5) },
	XMLElt { eltname: "service", data: XMLEltData::value(SERVICES_OFFSET + 7, 5) },
	// 60/65 SERVICES_OFFSET +2
	XMLElt { eltname: "/serviceType", data: XMLEltData::str("urn:schemas-upnp-org:service:Layer3Forwarding:1") },
	XMLElt { eltname: "/serviceId", data: XMLEltData::str("urn:upnp-org:serviceId:L3Forwarding1") },
	XMLElt { eltname: "/SCPDURL", data: XMLEltData::str(L3F_PATH) },
	XMLElt { eltname: "/controlURL", data: XMLEltData::str(L3F_CONTROLURL) },
	XMLElt { eltname: "/eventSubURL", data: XMLEltData::str(L3F_EVENTURL) },
	// 65 / 70 SERVICES_OFFSET +7
	#[cfg(feature = "dp_service")]
	XMLElt { eltname: "/serviceType", data: XMLEltData::str("urn:schemas-upnp-org:service:DeviceProtection:1") },
	#[cfg(feature = "dp_service")]
	XMLElt { eltname: "/serviceId", data: XMLEltData::str("urn:upnp-org:serviceId:DeviceProtection1") },
	#[cfg(feature = "dp_service")]
	XMLElt { eltname: "/SCPDURL", data: XMLEltData::str(DP_PATH) },
	#[cfg(feature = "dp_service")]
	XMLElt { eltname: "/controlURL", data: XMLEltData::str(DP_CONTROLURL) },
	#[cfg(feature = "dp_service")]
	XMLElt { eltname: "/eventSubURL", data: XMLEltData::str(DP_EVENTURL) },
];
const AddPortMappingArgs: [argument; 8] = [
	argument { dir: IN, relatedVar: 11 }, // RemoteHost
	argument { dir: IN, relatedVar: 12 }, // ExternalPort
	argument { dir: IN, relatedVar: 14 }, // PortMappingProtocol
	argument { dir: IN, relatedVar: 13 }, // InternalPort
	argument { dir: IN, relatedVar: 15 }, // InternalClient
	argument { dir: IN, relatedVar: 9 },  // PortMappingEnabled
	argument { dir: IN, relatedVar: 16 }, // PortMappingDescription
	argument { dir: IN, relatedVar: 10 }, // PortMappingLeaseDuration
];
const AddAnyPortMappingArgs: [argument; 9] = [
	argument { dir: IN, relatedVar: 11 },  // RemoteHost
	argument { dir: IN, relatedVar: 12 },  // ExternalPort
	argument { dir: IN, relatedVar: 14 },  // PortMappingProtocol
	argument { dir: IN, relatedVar: 13 },  // InternalPort
	argument { dir: IN, relatedVar: 15 },  // InternalClient
	argument { dir: IN, relatedVar: 9 },   // PortMappingEnabled
	argument { dir: IN, relatedVar: 16 },  // PortMappingDescription
	argument { dir: IN, relatedVar: 10 },  // PortMappingLeaseDuration
	argument { dir: OUT, relatedVar: 12 }, // NewReservedPort / ExternalPort
];
const DeletePortMappingRangeArgs: [argument; 4] = [
	argument { dir: IN | index!(1), relatedVar: 12 }, // NewStartPort / ExternalPort
	argument { dir: IN | index!(2), relatedVar: 12 }, // NewEndPort / ExternalPort
	argument { dir: IN, relatedVar: 14 },             // NewProtocol / PortMappingProtocol
	argument { dir: IN, relatedVar: 18 },             // NewManage / A_ARG_TYPE_Manage
];
const GetListOfPortMappingsArgs: [argument; 6] = [
	argument { dir: IN | index!(1), relatedVar: 12 }, // NewStartPort / ExternalPort
	argument { dir: IN | index!(2), relatedVar: 12 }, // NewEndPort / ExternalPort
	argument { dir: IN, relatedVar: 14 },             // NewProtocol / PortMappingProtocol
	argument { dir: IN, relatedVar: 18 },             // NewManage / A_ARG_TYPE_Manage
	argument { dir: IN, relatedVar: 8 },              // NewNumberOfPorts / PortMappingNumberOfEntries
	argument { dir: OUT, relatedVar: 19 },            // NewPortListing / A_ARG_TYPE_PortListing
];
const GetExternalIPAddressArgs: [argument; 1] = [argument { dir: OUT, relatedVar: 7 }];
const DeletePortMappingArgs: [argument; 3] = [
	argument { dir: IN, relatedVar: 11 }, // RemoteHost
	argument { dir: IN, relatedVar: 12 }, // ExternalPort
	argument { dir: IN, relatedVar: 14 }, // PortMappingProtocol
];
const SetConnectionTypeArgs: [argument; 1] = [argument { dir: IN, relatedVar: 0 }];
const GetConnectionTypeInfoArgs: [argument; 2] = [
	argument { dir: OUT, relatedVar: 0 },
	argument { dir: OUT, relatedVar: 1 },
];
const GetStatusInfoArgs: [argument; 3] = [
	argument { dir: OUT, relatedVar: 2 },
	argument { dir: OUT, relatedVar: 4 },
	argument { dir: OUT, relatedVar: 3 },
];
const GetNATRSIPStatusArgs: [argument; 2] = [
	argument { dir: OUT, relatedVar: 5 },
	argument { dir: OUT, relatedVar: 6 },
];
const GetGenericPortMappingEntryArgs: [argument; 9] = [
	argument { dir: IN, relatedVar: 8 },
	argument { dir: OUT, relatedVar: 11 },
	argument { dir: OUT, relatedVar: 12 },
	argument { dir: OUT, relatedVar: 14 },
	argument { dir: OUT, relatedVar: 13 },
	argument { dir: OUT, relatedVar: 15 },
	argument { dir: OUT, relatedVar: 9 },
	argument { dir: OUT, relatedVar: 16 },
	argument { dir: OUT, relatedVar: 10 },
];
const GetSpecificPortMappingEntryArgs: [argument; 8] = [
	argument { dir: IN, relatedVar: 11 },
	argument { dir: IN, relatedVar: 12 },
	argument { dir: IN, relatedVar: 14 },
	argument { dir: OUT, relatedVar: 13 },
	argument { dir: OUT, relatedVar: 15 },
	argument { dir: OUT, relatedVar: 9 },
	argument { dir: OUT, relatedVar: 16 },
	argument { dir: OUT, relatedVar: 10 },
];
const WANIPCnActions: [action; 14] = [
	action { name: "SetConnectionType", args: Some(&SetConnectionTypeArgs) },
	action { name: "GetConnectionTypeInfo", args: Some(&GetConnectionTypeInfoArgs) },
	action { name: "RequestConnection", args: None },
	action { name: "ForceTermination", args: None },
	action { name: "GetStatusInfo", args: Some(&GetStatusInfoArgs) },
	action { name: "GetNATRSIPStatus", args: Some(&GetNATRSIPStatusArgs) },
	action { name: "GetGenericPortMappingEntry", args: Some(&GetGenericPortMappingEntryArgs) },
	action { name: "GetSpecificPortMappingEntry", args: Some(&GetSpecificPortMappingEntryArgs) },
	action { name: "AddPortMapping", args: Some(&AddPortMappingArgs) },
	action { name: "DeletePortMapping", args: Some(&DeletePortMappingArgs) },
	action { name: "GetExternalIPAddress", args: Some(&GetExternalIPAddressArgs) },
	#[cfg(feature = "igd2")]
	action { name: "DeletePortMappingRange", args: Some(&DeletePortMappingRangeArgs) },
	#[cfg(feature = "igd2")]
	action { name: "GetListOfPortMappings", args: Some(&GetListOfPortMappingsArgs) },
	#[cfg(feature = "igd2")]
	action { name: "AddAnyPortMapping", args: Some(&AddAnyPortMappingArgs) },
];
const WANIPCnVars: [stateVar; 20] = [
	stateVar { name: "ConnectionType", itype: 0, idefault: 1, iallowedlist: 0, ieventvalue: 15 },
	stateVar { name: "PossibleConnectionTypes", itype: sendEvent, idefault: 0, iallowedlist: 14, ieventvalue: 15 },
	stateVar {
		name: "ConnectionStatus",
		itype: sendEvent,
		idefault: 3,
		iallowedlist: 18,
		ieventvalue: CONNECTIONSTATUS_MAGICALVALUE,
	},
	stateVar { name: "Uptime", itype: 3, ..stateVar::default() },
	stateVar { name: "LastConnectionError", itype: 0, idefault: 6, iallowedlist: 25, ieventvalue: 0 },
	stateVar { name: "RSIPAvailable", itype: 1, idefault: 4, ..stateVar::default() },
	stateVar { name: "NATEnabled", itype: 1, idefault: 5, ..stateVar::default() },
	stateVar {
		name: "ExternalIPAddress",
		itype: sendEvent,
		ieventvalue: EXTERNALIPADDRESS_MAGICALVALUE,
		..stateVar::default()
	},
	stateVar {
		name: "PortMappingNumberOfEntries",
		itype: 2 | sendEvent,
		ieventvalue: PORTMAPPINGNUMBEROFENTRIES_MAGICALVALUE,
		..stateVar::default()
	},
	stateVar { name: "PortMappingEnabled", itype: 1, ..stateVar::default() },
	stateVar { name: "PortMappingLeaseDuration", itype: 3, idefault: 2, iallowedlist: 1, ieventvalue: 0 },
	stateVar { name: "RemoteHost", ..stateVar::default() },
	stateVar { name: "ExternalPort", itype: 2, ..stateVar::default() },
	stateVar { name: "InternalPort", itype: 2, idefault: 0, iallowedlist: 3, ieventvalue: 0 },
	stateVar { name: "PortMappingProtocol", itype: 0, idefault: 0, iallowedlist: 11, ieventvalue: 0 },
	stateVar { name: "InternalClient", ..stateVar::default() },
	stateVar { name: "PortMappingDescription", ..stateVar::default() },
	stateVar {
		name: "SystemUpdateID",
		itype: 3 | sendEvent,
		ieventvalue: SYSTEMUPDATEID_MAGICALVALUE,
		..stateVar::default()
	},
	stateVar { name: "A_ARG_TYPE_Manage", itype: 1, ..stateVar::default() },
	stateVar { name: "A_ARG_TYPE_PortListing", ..stateVar::default() },
];
const scpdWANIPCn: serviceDesc = serviceDesc { actionList: &WANIPCnActions, serviceStateTable: &WANIPCnVars };

const GetCommonLinkPropertiesArgs: [argument; 4] = [
	argument { dir: OUT, relatedVar: 0 },
	argument { dir: OUT, relatedVar: 1 },
	argument { dir: OUT, relatedVar: 2 },
	argument { dir: OUT, relatedVar: 3 },
];
const GetTotalBytesSentArgs: [argument; 1] = [argument { dir: OUT, relatedVar: 4 }];
const GetTotalBytesReceivedArgs: [argument; 1] = [argument { dir: OUT, relatedVar: 5 }];
const GetTotalPacketsSentArgs: [argument; 1] = [argument { dir: OUT, relatedVar: 6 }];
const GetTotalPacketsReceivedArgs: [argument; 1] = [argument { dir: OUT, relatedVar: 7 }];
const WANCfgActions: [action; 5] = [
	action { name: "GetCommonLinkProperties", args: Some(&GetCommonLinkPropertiesArgs) }, /* Required */
	action { name: "GetTotalBytesSent", args: Some(&GetTotalBytesSentArgs) },             /* optional */
	action { name: "GetTotalBytesReceived", args: Some(&GetTotalBytesReceivedArgs) },     /* optional */
	action { name: "GetTotalPacketsSent", args: Some(&GetTotalPacketsSentArgs) },         /* optional */
	action { name: "GetTotalPacketsReceived", args: Some(&GetTotalPacketsReceivedArgs) }, /* optional */
];
const WANCfgVars: [stateVar; 8] = [
	stateVar { name: "WANAccessType", iallowedlist: 1, ..stateVar::default() },
	stateVar { name: "Layer1UpstreamMaxBitRate", itype: 3, ..stateVar::default() },
	stateVar { name: "Layer1DownstreamMaxBitRate", itype: 3, ..stateVar::default() },
	stateVar { name: "PhysicalLinkStatus", itype: sendEvent, idefault: 0, iallowedlist: 6, ieventvalue: 6 },
	stateVar { name: "TotalBytesSent", itype: 3, ..stateVar::default() },
	stateVar { name: "TotalBytesReceived", itype: 3, ..stateVar::default() },
	stateVar { name: "TotalPacketsSent", itype: 3, ..stateVar::default() },
	stateVar { name: "TotalPacketsReceived", itype: 3, ..stateVar::default() },
];
const scpdWANCfg: serviceDesc = serviceDesc { actionList: &WANCfgActions, serviceStateTable: &WANCfgVars };
const SetDefaultConnectionServiceArgs: [argument; 1] = [argument { dir: IN, relatedVar: 0 }];
const GetDefaultConnectionServiceArgs: [argument; 1] = [argument { dir: OUT, relatedVar: 0 }];
const L3FActions: [action; 2] = [
	action { name: "SetDefaultConnectionService", args: Some(&SetDefaultConnectionServiceArgs) },
	action { name: "GetDefaultConnectionService", args: Some(&GetDefaultConnectionServiceArgs) },
];
const L3FVars: [stateVar; 1] = [stateVar {
	name: "DefaultConnectionService",
	itype: sendEvent,
	ieventvalue: DEFAULTCONNECTIONSERVICE_MAGICALVALUE,
	..stateVar::default()
}];
const scpdL3F: serviceDesc = serviceDesc { actionList: &L3FActions, serviceStateTable: &L3FVars };
const GetFirewallStatusArgs: [argument; 2] = [
	argument { dir: OUT | NO_NEW, relatedVar: 0 },
	argument { dir: OUT | NO_NEW, relatedVar: 6 },
];
const GetOutboundPinholeTimeoutArgs: [argument; 6] = [
	argument { dir: IN | NO_NEW | index!(3), relatedVar: 1 },
	argument { dir: IN | NO_NEW | index!(4), relatedVar: 2 },
	argument { dir: IN | NO_NEW | index!(5), relatedVar: 1 },
	argument { dir: IN | NO_NEW | index!(6), relatedVar: 2 },
	argument { dir: IN | NO_NEW, relatedVar: 3 },
	argument { dir: OUT | NO_NEW, relatedVar: 7 },
];
const AddPinholeArgs: [argument; 7] = [
	argument { dir: IN | NO_NEW | index!(3), relatedVar: 1 },
	argument { dir: IN | NO_NEW | index!(4), relatedVar: 2 },
	argument { dir: IN | NO_NEW | index!(5), relatedVar: 1 },
	argument { dir: IN | NO_NEW | index!(6), relatedVar: 2 },
	argument { dir: IN | NO_NEW, relatedVar: 3 },
	argument { dir: IN | NO_NEW, relatedVar: 5 },
	argument { dir: OUT | NO_NEW, relatedVar: 4 },
];
const UpdatePinholeArgs: [argument; 2] = [
	argument { dir: IN | NO_NEW, relatedVar: 4 },
	argument { dir: IN, relatedVar: 5 },
];
const DeletePinholeArgs: [argument; 1] = [argument { dir: IN | NO_NEW, relatedVar: 4 }];
const GetPinholePacketsArgs: [argument; 2] = [
	argument { dir: IN | NO_NEW, relatedVar: 4 },
	argument { dir: OUT | NO_NEW, relatedVar: 9 },
];
const CheckPinholeWorkingArgs: [argument; 2] = [
	argument { dir: IN | NO_NEW, relatedVar: 4 },
	argument { dir: OUT | NO_NEW | index!(7), relatedVar: 8 },
];
const IPv6FCActions: [action; 7] = [
	action { name: "GetFirewallStatus", args: Some(&GetFirewallStatusArgs) },
	action { name: "GetOutboundPinholeTimeout", args: Some(&GetOutboundPinholeTimeoutArgs) },
	action { name: "AddPinhole", args: Some(&AddPinholeArgs) },
	action { name: "UpdatePinhole", args: Some(&UpdatePinholeArgs) },
	action { name: "DeletePinhole", args: Some(&DeletePinholeArgs) },
	action { name: "GetPinholePackets", args: Some(&GetPinholePacketsArgs) },
	action { name: "CheckPinholeWorking", args: Some(&CheckPinholeWorkingArgs) },
];
const IPv6FCVars: [stateVar; 10] = [
	stateVar {
		name: "FirewallEnabled",
		itype: 1 | sendEvent,
		ieventvalue: FIREWALLENABLED_MAGICALVALUE,
		..stateVar::default()
	},
	stateVar { name: "A_ARG_TYPE_IPv6Address", ..stateVar::default() },
	stateVar { name: "A_ARG_TYPE_Port", itype: 2, ..stateVar::default() },
	stateVar { name: "A_ARG_TYPE_Protocol", itype: 2, ..stateVar::default() },
	stateVar { name: "A_ARG_TYPE_UniqueID", itype: 2, ..stateVar::default() },
	stateVar { name: "A_ARG_TYPE_LeaseTime", itype: 3, iallowedlist: 5, ..stateVar::default() },
	stateVar {
		name: "InboundPinholeAllowed",
		itype: 1 | sendEvent,
		ieventvalue: INBOUNDPINHOLEALLOWED_MAGICALVALUE,
		..stateVar::default()
	},
	stateVar { name: "A_ARG_TYPE_OutboundPinholeTimeout", itype: 3, idefault: 0, iallowedlist: 7, ieventvalue: 0 },
	stateVar { name: "A_ARG_TYPE_Boolean", itype: 1, ..stateVar::default() },
	stateVar { name: "A_ARG_TYPE_PinholePackets", itype: 3, ..stateVar::default() },
];
const scpd6FC: serviceDesc = serviceDesc { actionList: &IPv6FCActions, serviceStateTable: &IPv6FCVars };

#[cfg(feature = "dp_service")]
const SendSetupMessageArgs: [argument; 3] = [
	argument { dir: IN | NO_NEW | (index!(8)), relatedVar: 6 }, /* ProtocolType : in ProtocolType / A_ARG_TYPE_String */
	argument { dir: IN | NO_NEW | (index!(9)), relatedVar: 5 }, /* InMessage : in InMessage / A_ARG_TYPE_Base64 */
	argument { dir: OUT | NO_NEW | (index!(10)), relatedVar: 5 }, /* OutMessage : out OutMessage / A_ARG_TYPE_Base64 */
];
#[cfg(feature = "dp_service")]
const GetSupportedProtocolsArgs: [argument; 1] = [argument { dir: OUT | NO_NEW | (index!(11)), relatedVar: 1 }];
#[cfg(feature = "dp_service")]
const GetAssignedRolesArgs: [argument; 1] = [argument { dir: OUT | NO_NEW | (index!(12)), relatedVar: 6 }];
#[cfg(feature = "dp_service")]
const DPActions: [action; 3] = [
	action { name: "SendSetupMessage", args: Some(&SendSetupMessageArgs) },
	action { name: "GetSupportedProtocols", args: Some(&GetSupportedProtocolsArgs) },
	action { name: "GetAssignedRoles", args: Some(&GetAssignedRolesArgs) },
];
#[cfg(feature = "dp_service")]
const DPVars: [stateVar; 7] = [
	stateVar {
		name: "SetupReady",
		itype: 1 | sendEvent,
		idefault: 0,
		iallowedlist: 0,
		ieventvalue: SETUPREADY_MAGICALVALUE,
	},
	stateVar { name: "SupportedProtocols", itype: 0, ..stateVar::default() },
	stateVar { name: "A_ARG_TYPE_ACL", itype: 0, ..stateVar::default() },
	stateVar { name: "A_ARG_TYPE_IdentityList", itype: 0, ..stateVar::default() },
	stateVar { name: "A_ARG_TYPE_Identity", itype: 0, ..stateVar::default() },
	stateVar { name: "A_ARG_TYPE_Base64", itype: 4, ..stateVar::default() },
	stateVar { name: "A_ARG_TYPE_String", itype: 0, ..stateVar::default() },
];
#[cfg(feature = "dp_service")]
const scpdDP: serviceDesc = serviceDesc { actionList: &DPActions, serviceStateTable: &DPVars };

fn genXML(p: &[XMLElt], force_igd1: bool) -> String {
	const GENXML_STACK_SIZE: usize = 16;
	let mut result = String::with_capacity(2048);

	#[derive(Clone, Copy, Default)]
	struct StackItem {
		i: u16,
		j: u16,
		eltname: &'static str,
	}

	let mut stack = [StackItem::default(); GENXML_STACK_SIZE];
	let mut top: i32 = -1;
	let mut i: u16 = 0; // current node
	let mut j: u16; // i + number of nodes

	'unstack: loop {
		let eltname = p[i as usize].eltname;
		if eltname.is_empty() {
			return result;
		}

		if eltname.starts_with('/') {
			// 叶子节点

			let mut push_str = |data: &str| {
				if !data.is_empty() {
					result.push('<');
					result.push_str(&eltname[1..]);
					result.push('>');

					#[cfg(feature = "randomurl")]
					if data.starts_with('/') {
						result.push('/');
						result.push_str(&random_url.get().unwrap());
					}

					result.push_str(data);

					#[cfg(feature = "igd2")]
					if force_igd1
						&& data.starts_with('u')
						&& (data == DEVICE_TYPE_IGD
							|| data == DEVICE_TYPE_WAN
							|| data == DEVICE_TYPE_WANC
							|| data == SERVICE_TYPE_WANIPC)
					{
						let len = result.len();
						result.replace_range(len - 1..len, "1");
					}

					result.push('<');
					result.push_str(eltname);
					result.push('>');
				}
			};

			match p[i as usize].data {
				XMLEltData::str(data) => {
					push_str(data);
				}
				XMLEltData::dyn_str(data) => push_str(data.get().unwrap().as_str()),
				XMLEltData::uuid(data) => {
					let uuid_str = format!("uuid:{}", data.get().unwrap());
					push_str(&uuid_str);
				}
				_ => {}
			}

			loop {
				if top < 0 {
					return result;
				}

				let stack_top = &mut stack[top as usize];
				stack_top.i += 1;
				i = stack_top.i;
				j = stack_top.j;

				if i == j {
					result.push('<');
					result.push('/');
					result.push_str(stack_top.eltname.split_whitespace().next().unwrap_or(""));
					result.push('>');
					top -= 1;
				} else {
					break;
				}
			}
		} else {
			// 有子节点的节点
			if let XMLEltData::value(off, num) = p[i as usize].data {
				#[cfg(feature = "igd2")]
				if force_igd1
					&& p[off as usize].eltname.starts_with('/')
					&& (p[off as usize].data == XMLEltData::str("urn:schemas-upnp-org:service:DeviceProtection:1")
						|| p[off as usize].data
							== XMLEltData::str("urn:schemas-upnp-org:service:WANIPv6FirewallControl:1"))
				{
					continue 'unstack;
				}

				result.push('<');
				result.push_str(eltname);

				if eltname.starts_with("root ") {
					result.push_str(" configId=\"");
					result.write_fmt(const_format_args!("{}", upnp_configid)).unwrap();
					result.push('"');
				}

				result.push('>');

				i = off;
				j = i + (num);

				if top < (GENXML_STACK_SIZE - 1) as i32 {
					top += 1;
					stack[top as usize] = StackItem { i, j, eltname };
				} else {
					#[cfg(debug_assertions)]
					eprintln!("*** GenXML(): stack OVERFLOW ***");
				}
			}
		}
	}
}

pub fn genRootDesc(force_igd1: bool) -> String {
	genXML(rootDesc, force_igd1)
}

fn genServiceDesc(s: &serviceDesc, force_igd1: bool) -> String {
	let mut result = String::with_capacity(2048);
	result.push_str(xmlver);

	let acts = s.actionList;
	let vars = s.serviceStateTable;

	// 添加开始标签
	result.push('<');
	result.push_str(root_service);
	result.push('>');

	// 添加版本信息
	result.push_str("<specVersion><major>");
	result.push_str(UPNP_VERSION_MAJOR_STR);
	result.push_str("</major><minor>");
	result.push_str(UPNP_VERSION_MINOR_STR);
	result.push_str("</minor></specVersion>");

	// 处理 actionList
	result.push_str("<actionList>");
	let mut i = 0;
	while let Some(act) = acts.get(i) {
		#[cfg(feature = "igd2")]
		if force_igd1 && act.name == "DeletePortMappingRange" {
			break;
		}

		result.push_str("<action><name>");
		result.push_str(act.name);
		result.push_str("</name>");

		// 处理参数列表
		if let Some(args) = act.args {
			result.push_str("<argumentList>");
			for arg in args.iter() {
				if arg.dir == 0 {
					break;
				}

				result.push_str("<argument><name>");
				if (arg.dir & NO_NEW) == 0 {
					result.push_str("New");
				}

				let var_name = vars[arg.relatedVar as usize].name;

				if (arg.dir & NAME_INDEX_MASK) != 0 {
					result.push_str(magicargname[((arg.dir & NAME_INDEX_MASK) >> 2) as usize]);
				} else if var_name.starts_with("PortMapping")
					&& !(var_name.len() >= 22 && var_name[11..22] == *"Description")
				{
					if var_name.len() >= 26 && var_name[11..26] == *"NumberOfEntries" {
						#[cfg(feature = "igd2")]
						if act.name == "GetListOfPortMappings" {
							result.push_str("NumberOfPorts");
						} else {
							result.push_str("PortMappingIndex");
						}
						#[cfg(not(feature = "igd2"))]
						result.push_str("PortMappingIndex");
					} else {
						result.push_str(&var_name[11..]);
					}
				} else if cfg!(feature = "igd2") && var_name.starts_with("A_ARG_TYPE_") {
					result.push_str(&var_name[11..]);
				} else if var_name == "ExternalPort" && arg.dir == 2 && act.name == "AddAnyPortMapping" {
					result.push_str("ReservedPort");
				} else {
					result.push_str(var_name);
				}

				result.push_str("</name><direction>");
				result.push_str(if (arg.dir & INOUT_MASK) == 1 { "in" } else { "out" });
				result.push_str("</direction><relatedStateVariable>");
				result.push_str(var_name);
				result.push_str("</relatedStateVariable></argument>");
			}
			result.push_str("</argumentList>");
		}
		result.push_str("</action>");
		i += 1;
	}

	// 处理 serviceStateTable
	result.push_str("</actionList><serviceStateTable>");
	i = 0;
	while let Some(var) = vars.get(i) {
		if var.name.is_empty() {
			break;
		}

		result.push_str("<stateVariable sendEvents=\"");
		#[cfg(feature = "events")]
		result.push_str(if (var.itype & sendEvent) != 0 { "yes" } else { "no" });
		#[cfg(not(feature = "events"))]
		result.push_str("no");

		result.push_str("\"><name>");
		result.push_str(var.name);
		result.push_str("</name><dataType>");
		result.push_str(upnptypes[var.itype as usize & 0x0f]);
		result.push_str("</dataType>");

		if var.idefault != 0 {
			result.push_str("<defaultValue>");
			result.push_str(upnpdefaultvalues[var.idefault as usize]);
			result.push_str("</defaultValue>");
		}

		if var.iallowedlist != 0 {
			if (var.itype & 0x0f) == 0 {
				// 字符串类型
				result.push_str("<allowedValueList>");
				let mut j = var.iallowedlist as usize;
				while !upnpallowedvalues[j].is_empty() {
					result.push_str("<allowedValue>");
					result.push_str(upnpallowedvalues[j]);
					result.push_str("</allowedValue>");
					j += 1;
				}
				result.push_str("</allowedValueList>");
			} else {
				// ui2 和 ui4 类型
				result.push_str("<allowedValueRange><minimum>");
				result.write_fmt(const_format_args!("{}", upnpallowedranges[var.iallowedlist as usize])).unwrap();
				result.push_str("</minimum><maximum>");
				result
					.write_fmt(const_format_args!(
						"{}",
						upnpallowedranges[var.iallowedlist as usize + 1]
					))
					.unwrap();
				result.push_str("</maximum></allowedValueRange>");
			}
		}
		result.push_str("</stateVariable>");
		i += 1;
	}

	result.push_str("</serviceStateTable></scpd>");
	// *len = result.len() as i32;
	result
}

pub fn genWANIPCn(force_igd1: bool) -> String {
	genServiceDesc(&scpdWANIPCn, force_igd1)
}

pub fn genWANCfg(force_igd1: bool) -> String {
	genServiceDesc(&scpdWANCfg, force_igd1)
}

pub fn genL3F(force_igd1: bool) -> String {
	genServiceDesc(&scpdL3F, force_igd1)
}

pub fn gen6FC(force_igd1: bool) -> String {
	genServiceDesc(&scpd6FC, force_igd1)
}

fn genEventVars(rt: &mut RtOptions, s: &serviceDesc) -> Option<String> {
	let mut result = String::with_capacity(512);
	result.push_str("<e:propertyset xmlns:e=\"urn:schemas-upnp-org:event-1-0\">");

	for var in s.serviceStateTable.iter() {
		if var.name.is_empty() {
			break;
		}

		if var.itype & sendEvent != 0 {
			result.push_str("<e:property><");
			result.push_str(var.name);
			result.push('>');

			match var.ieventvalue {
				0 => {}

				#[cfg(feature = "dp_service")]
				SETUPREADY_MAGICALVALUE => {
					result.push_str("1"); // always ready for setup
				}

				CONNECTIONSTATUS_MAGICALVALUE => {
					result.push_str(get_wan_connection_status_str(&global_option.get().unwrap().ext_ifname));
				}

				#[cfg(feature = "ipv6")]
				FIREWALLENABLED_MAGICALVALUE => {
					let runtime_flag = global_option.get().unwrap().runtime_flags;
					result.push_str(if GETFLAG!(runtime_flag, IPV6FCFWDISABLEDMASK) {
						"0"
					} else {
						"1"
					});
				}

				#[cfg(feature = "ipv6")]
				INBOUNDPINHOLEALLOWED_MAGICALVALUE => {
					let runtime_flag = global_option.get().unwrap().runtime_flags;
					result.push_str(if GETFLAG!(runtime_flag, IPV6FCINBOUNDDISALLOWEDMASK) {
						"0"
					} else {
						"1"
					});
				}

				#[cfg(feature = "igd2")]
				SYSTEMUPDATEID_MAGICALVALUE => {
					result.push('1'); // system update id
				}

				PORTMAPPINGNUMBEROFENTRIES_MAGICALVALUE => {
					result.write_fmt(format_args!("{}", upnp_get_portmapping_number_of_entries(&rt.nat_impl))).unwrap();
				}

				EXTERNALIPADDRESS_MAGICALVALUE => {
					if let Some(ext_ip) = &rt.use_ext_ip_addr {
						result.write_fmt(format_args!("{ext_ip}")).unwrap();
					} else {
						let op = global_option.get().unwrap();
						let ext_if_name = &op.ext_ifname;
						let mut addr = Ipv4Addr::UNSPECIFIED;
						if getifaddr(ext_if_name, &mut addr, None) == 0 {
							if !GETFLAG!(op.runtime_flags, ALLOWPRIVATEIPV4MASK) && addr_is_reserved(&addr) {
								result.push_str("0.0.0.0");
							} else {
								result.write_fmt(format_args!("{addr}")).unwrap();
							}
						} else {
							result.push_str("0.0.0.0");
						}
					}
				}

				DEFAULTCONNECTIONSERVICE_MAGICALVALUE => {
					result.write_fmt(format_args!("{}", uuidvalue_wcd.get().unwrap())).unwrap();
					#[cfg(feature = "igd2")]
					result.push_str(":WANConnectionDevice:2,urn:upnp-org:serviceId:WANIPConn1");
					#[cfg(not(feature = "igd2"))]
					result.push_str(":WANConnectionDevice:1,urn:upnp-org:serviceId:WANIPConn1");
				}

				_ => {
					result.push_str(upnpallowedvalues[var.ieventvalue as usize]);
				}
			}

			result.push_str("</");
			result.push_str(var.name);
			result.push_str("></e:property>");
		}
	}

	result.push_str("</e:propertyset>");
	Some(result)
}

pub fn getVarsWANIPCn(rt: &mut RtOptions) -> Option<String> {
	genEventVars(rt, &scpdWANIPCn)
}

pub fn getVarsWANCfg(rt: &mut RtOptions) -> Option<String> {
	genEventVars(rt, &scpdWANCfg)
}

pub fn getVarsL3F(rt: &mut RtOptions) -> Option<String> {
	genEventVars(rt, &scpdL3F)
}

pub fn getVars6FC(rt: &mut RtOptions) -> Option<String> {
	genEventVars(rt, &scpd6FC)
}
#[cfg(feature = "dp_service")]
pub fn genDP(force_igd1: bool) -> String {
	genServiceDesc(&scpdDP, force_igd1)
}

#[cfg(feature = "dp_service")]
pub fn getVarsDP(rt: &mut RtOptions) -> Option<String> {
	genEventVars(rt, &scpdDP)
}
