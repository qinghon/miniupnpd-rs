pub const ROOTDESC_PATH: &str = "/rootDesc.xml";

pub const DUMMY_PATH: &str = "/dummy.xml";

pub const WANCFG_PATH: &str = "/WANCfg.xml";
pub const WANCFG_CONTROLURL: &str = "/ctl/CmnIfCfg";
pub const WANCFG_EVENTURL: &str = "/evt/CmnIfCfg";

pub const WANIPC_PATH: &str = "/WANIPCn.xml";
pub const WANIPC_CONTROLURL: &str = "/ctl/IPConn";
pub const WANIPC_EVENTURL: &str = "/evt/IPConn";

pub const L3F_PATH: &str = "/L3F.xml";
pub const L3F_CONTROLURL: &str = "/ctl/L3F";
pub const L3F_EVENTURL: &str = "/evt/L3F";

#[cfg(feature = "ipv6")]
pub const WANIP6FC_PATH: &str = "/WANIP6FC.xml";
#[cfg(feature = "ipv6")]
pub const WANIP6FC_CONTROLURL: &str = "/ctl/IP6FCtl";
#[cfg(feature = "ipv6")]
pub const WANIP6FC_EVENTURL: &str = "/evt/IP6FCtl";

/* For DeviceProtection introduced in IGD v2 */
pub const DP_PATH: &str = "/DP.xml";
pub const DP_CONTROLURL: &str = "/ctl/DP";
pub const DP_EVENTURL: &str = "/evt/DP";
