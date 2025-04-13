/* IGD v2 */
#[cfg(feature = "igd2")]
pub const DEVICE_TYPE_IGD: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:2";
#[cfg(feature = "igd2")]
pub const DEVICE_TYPE_WAN: &str = "urn:schemas-upnp-org:device:WANDevice:2";
#[cfg(feature = "igd2")]
pub const DEVICE_TYPE_WANC: &str = "urn:schemas-upnp-org:device:WANConnectionDevice:2";
#[cfg(feature = "igd2")]
pub const SERVICE_TYPE_WANIPC: &str = "urn:schemas-upnp-org:service:WANIPConnection:2";
#[cfg(feature = "igd2")]
pub const SERVICE_ID_WANIPC: &str = "urn:upnp-org:serviceId:WANIPConn1";

#[cfg(not(feature = "igd2"))]
pub const DEVICE_TYPE_IGD: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
#[cfg(not(feature = "igd2"))]
pub const DEVICE_TYPE_WAN: &str = "urn:schemas-upnp-org:device:WANDevice:1";
#[cfg(not(feature = "igd2"))]
pub const DEVICE_TYPE_WANC: &str = "urn:schemas-upnp-org:device:WANConnectionDevice:1";
#[cfg(not(feature = "igd2"))]
pub const SERVICE_TYPE_WANIPC: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";
#[cfg(not(feature = "igd2"))]
pub const SERVICE_ID_WANIPC: &str = "urn:upnp-org:serviceId:WANIPConn1";
