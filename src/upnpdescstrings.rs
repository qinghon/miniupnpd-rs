pub const OS_NAME: &str = env!("OS_NAME");
pub const OS_URL: &str = env!("OS_URL");
pub const MINIUPNPD_DATE: &str = env!("MINIUPNPD_DATE");

pub const MINIUPNPD_VERSION: &str = env!("CARGO_PKG_VERSION");
/* strings used in the root device xml description */
pub const ROOTDEV_FRIENDLYNAME: &str = concat!(env!("OS_NAME"), " router");
pub const ROOTDEV_MANUFACTURER: &str = env!("OS_NAME");
pub const ROOTDEV_MANUFACTURERURL: &str = env!("OS_URL");
pub const ROOTDEV_MODELNAME: &str = concat!(env!("OS_NAME"), " router");
pub const ROOTDEV_MODELDESCRIPTION: &str = concat!(
	env!("OS_NAME"),
	" with MiniUPnPd version ",
	env!("CARGO_PKG_VERSION"),
	" router"
);
pub const ROOTDEV_MODELURL: &str = env!("OS_URL");

pub const WANDEV_FRIENDLYNAME: &str = "WANDevice";
pub const WANDEV_MANUFACTURER: &str = "MiniUPnP";
pub const WANDEV_MANUFACTURERURL: &str = env!("CARGO_PKG_HOMEPAGE");
pub const WANDEV_MODELNAME: &str = "MiniUPnPd";
pub const WANDEV_MODELDESCRIPTION: &str = concat!("MiniUPnP daemon version ", env!("CARGO_PKG_VERSION"));
pub const WANDEV_MODELNUMBER: &str = MINIUPNPD_DATE;
pub const WANDEV_MODELURL: &str = env!("CARGO_PKG_HOMEPAGE");
pub const WANDEV_UPC: &str = "000000000000";
/* UPC is 12 digit (barcode) */

pub const WANCDEV_FRIENDLYNAME: &str = "WANConnectionDevice";
pub const WANCDEV_MANUFACTURER: &str = WANDEV_MANUFACTURER;
pub const WANCDEV_MANUFACTURERURL: &str = WANDEV_MANUFACTURERURL;
pub const WANCDEV_MODELNAME: &str = WANDEV_MODELNAME;
pub const WANCDEV_MODELDESCRIPTION: &str = WANDEV_MODELDESCRIPTION;
pub const WANCDEV_MODELNUMBER: &str = WANDEV_MODELNUMBER;
pub const WANCDEV_MODELURL: &str = WANDEV_MODELURL;
pub const WANCDEV_UPC: &str = WANDEV_UPC;
/* UPC is 12 digit (barcode) */

pub const UPNP_VERSION_MAJOR_STR: &str = "1";
pub const UPNP_VERSION_MINOR_STR: &str = "1";