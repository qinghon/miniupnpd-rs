#![allow(unused_assignments)]

use bindgen::RustTarget;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::process::Command;

#[cfg(target_os = "linux")]
fn build_if_addr() {
	let if_addr = bindgen::Builder::default()
		.header_contents("wrapper.h", "#include <linux/if_addr.h>")
		.parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
		.use_core()
		.ctypes_prefix("libc")
		.allowlist_file("/usr/include/linux/if_addr.h")
		.generate()
		.expect("Unable to generate bindings");

	let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
	if_addr.write_to_file(out_path.join("if_addr.rs")).expect("Couldn't write bindings!");

	const RT_PREFIX: &str =
		"^(RT|RTNL|RTM|RTNH|RTAX|RTMGRP|RTNLGRP|rt|rta|PREFIX|prefix|TCA|RTEXT|tcm|TCM|NDUSEROPT)_.+$";
	let rtnetlink = bindgen::Builder::default()
		.header_contents("wrapper.h", "#include <linux/rtnetlink.h>")
		.allowlist_file(RT_PREFIX)
		.allowlist_type(RT_PREFIX)
		.allowlist_var(RT_PREFIX)
		.allowlist_item(RT_PREFIX)
		.allowlist_type("rtattr")
		.allowlist_type("rtmsg")
		.allowlist_type("rtattr_type_t")
		.allowlist_type("rtnexthop")
		.allowlist_type("rtvia")
		.allowlist_type("rtgenmsg")
		.allowlist_type("ifinfomsg")
		.allowlist_type("prefixmsg")
		.allowlist_type("tcmsg")
		.allowlist_type("tcamsg")
		.allowlist_type("nduseroptmsg")
		.use_core()
		.derive_default(true)
		.ctypes_prefix("libc")
		.rust_target(bindgen::RustTarget::nightly())
		.rust_edition(bindgen::RustEdition::Edition2024)
		.generate()
		.expect("Unable to generate bindings");
	rtnetlink.write_to_file(out_path.join("rtnetlink.rs")).expect("Couldn't write rtnetlink bindings!");
}
fn probe_iptables() {
	let libiptc = pkg_config::probe_library("libiptc").unwrap();
	const IPTC_PREFIX: &str = "^(iptc|ip6tc|xtc|xt|IPTC|IP6TC|XTC|XT)_.+$";
	let bindings = bindgen::Builder::default()
		.header_contents(
			"wrapper.h",
			"
		#include <libiptc/libiptc.h>
		#include <libiptc/libip6tc.h>
		",
		)
		.allowlist_type(IPTC_PREFIX)
		.allowlist_var(IPTC_PREFIX)
		.allowlist_function(IPTC_PREFIX)
		.allowlist_type("_xt_align")
		.blocklist_type("in_addr|in6_addr")
		.use_core()
		.ctypes_prefix("libc")
		.rust_target(bindgen::RustTarget::nightly())
		.rust_edition(bindgen::RustEdition::Edition2024)
		.clang_args(libiptc.include_paths.iter().map(|x| format!("-I{}", x.to_str().unwrap())))
		.raw_line("use libc::{self, in_addr, in6_addr};")
		.generate()
		.expect("Unable to generate bindings");
	let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
	bindings.write_to_file(out_path.join("iptc.rs")).expect("Couldn't write iptc bindings!");
}

fn probe_nftables() {
	let libnftnl = pkg_config::probe_library("libnftnl").unwrap();

	// code from libnftnl-sys
	// const NFTNL_PKG_CONFIG: &'static str = "libnftnl";
	const NFTNL_REGEX: &'static str = "^nftnl_.+$";
	const NFTNL_FLAGS_REGEX: &'static str = "^nftnl_.+_flags$";
	const NFTNL_NOT_FLAGS_REGEX: &'static str = "^nftnl_.+[^_][^f][^l][^a][^g][^s]$";

	let bindings = bindgen::Builder::default()
		.header_contents(
			"wrapper.h",
			"
		#include <libnftnl/batch.h>
		#include <libnftnl/chain.h>
		#include <libnftnl/common.h>
		#include <libnftnl/expr.h>
		#include <libnftnl/gen.h>
		#include <libnftnl/object.h>
		#include <libnftnl/rule.h>
		#include <libnftnl/ruleset.h>
		#include <libnftnl/set.h>
		#include <libnftnl/table.h>
		#include <libnftnl/trace.h>
		#include <libnftnl/udata.h>
		",
		)
		.opaque_type(NFTNL_REGEX)
		.opaque_type("_IO_FILE")
		.blocklist_type("iovec")
		.blocklist_type("nlmsghdr")
		.blocklist_type("FILE")
		.allowlist_type(NFTNL_REGEX)
		.allowlist_type("^_bindgen.*")
		.allowlist_var(NFTNL_REGEX)
		.allowlist_function(NFTNL_REGEX)
		.bitfield_enum(NFTNL_FLAGS_REGEX)
		.constified_enum_module(NFTNL_NOT_FLAGS_REGEX)
		// .rustified_enum("^_bindgen.*")
		.prepend_enum_name(true)
		.rust_edition(bindgen::RustEdition::Edition2024)
		.clang_args(libnftnl.include_paths.iter().map(|x| format!("-I{}", x.to_str().unwrap())))
		.raw_line("use libc::{self, nlmsghdr, FILE};")
		.rust_target(RustTarget::nightly());
	// .rustfmt_bindings(false)
	// .generate()
	// .unwrap();

	// eprintln!("{}", bindings.command_line_flags().iter().map(|x|format!("\"{x}\" ")).collect::<String>());
	let bindings = bindings.generate().expect("Couldn't generate bindings");

	let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
	bindings.write_to_file(out_path.join("nftnl.rs")).unwrap();

	// from mnl-sys
	let libmnl = pkg_config::probe_library("libmnl").unwrap();
	let bindings = bindgen::Builder::default()
		.header_contents("wrapper.h", "#include <libmnl/libmnl.h>")
		.clang_args(libmnl.include_paths.iter().map(|x| format!("-I{}", x.to_str().unwrap())))
		.use_core()
		.prepend_enum_name(false)
		.allowlist_function("^mnl.+$")
		.allowlist_var("^MNL.+$")
		.allowlist_type("^mnl_.+$")
		.blocklist_type("^_.+$")
		.blocklist_type("FILE")
		.blocklist_type("_IO_FILE")
		.blocklist_type("(__)?(pid|socklen)_t")
		.blocklist_type("iovec")
		.blocklist_type("nlmsghdr")
		.blocklist_type("nlattr")
		.raw_line("use libc::{self, nlmsghdr, nlattr, pid_t, socklen_t, FILE};")
		.ctypes_prefix("libc")
		.rust_target(RustTarget::nightly())
		.generate()
		.expect("Couldn't generate bindings");

	bindings.write_to_file(out_path.join("mnl.rs")).expect("Couldn't write libmnl bindings!");
}
#[cfg(target_os = "linux")]
fn probe_libmnl() -> Result<(), pkg_config::Error> {
	// from mnl-sys
	let libmnl = pkg_config::probe_library("libmnl")?;
	let bindings = bindgen::Builder::default()
		.header_contents("wrapper.h", "#include <libmnl/libmnl.h>")
		.clang_args(libmnl.include_paths.iter().map(|x| format!("-I{}", x.to_str().unwrap())))
		.use_core()
		.prepend_enum_name(false)
		.allowlist_function("^mnl.+$")
		.allowlist_var("^MNL.+$")
		.allowlist_type("^mnl_.+$")
		.blocklist_type("^_.+$")
		.blocklist_type("FILE")
		.blocklist_type("_IO_FILE")
		.blocklist_type("(__)?(pid|socklen)_t")
		.blocklist_type("iovec")
		.blocklist_type("nlmsghdr")
		.blocklist_type("nlattr")
		.raw_line("use libc::{self, nlmsghdr, nlattr, pid_t, socklen_t, FILE};")
		.ctypes_prefix("libc")
		.rust_target(RustTarget::nightly())
		.generate()
		.expect("Couldn't generate bindings");

	let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
	bindings.write_to_file(out_path.join("mnl.rs")).expect("Couldn't write libmnl bindings!");
	Ok(())
}
#[cfg(target_os = "linux")]
fn probe_libnetfilter_conntrack(lib_map: &mut HashMap<&'static str, bool>) {
	let _libnetfilter_conntrack = pkg_config::probe_library("libnetfilter_conntrack");
	if _libnetfilter_conntrack.is_err() {
		println!("cargo:rustc-cfg=conntrack=\"proc\"");
		return;
	}
	if probe_libmnl().is_err() {
		println!("cargo:rustc-cfg=conntrack=\"proc\"");
		return;
	}
	if probe_libnfnetlink(lib_map).is_err() {
		println!("cargo:rustc-cfg=conntrack=\"proc\"");
		return;
	}
	// let libnetfilter_conntrack = libnetfilter_conntrack.unwrap();

	let headers = [
		"libnetfilter_conntrack/libnetfilter_conntrack.h",
		"libnetfilter_conntrack/libnetfilter_conntrack_dccp.h",
		"libnetfilter_conntrack/libnetfilter_conntrack_icmp.h",
		"libnetfilter_conntrack/libnetfilter_conntrack_ipv4.h",
		"libnetfilter_conntrack/libnetfilter_conntrack_ipv6.h",
		"libnetfilter_conntrack/libnetfilter_conntrack_sctp.h",
		"libnetfilter_conntrack/libnetfilter_conntrack_tcp.h",
		"libnetfilter_conntrack/libnetfilter_conntrack_udp.h",
		"libnetfilter_conntrack/linux_nf_conntrack_common.h",
		"libnetfilter_conntrack/linux_nfnetlink_conntrack.h",
	];
	let ret = probe_lib_generic(
		"libnetfilter_conntrack",
		&headers,
		"netfilter_conntrack",
		"libnetfilter_conntrack",
		Some(&["nlmsghdr"]),
	);
	if ret.is_err() {
		println!("cargo:rustc-cfg=conntrack=\"proc\"");
		lib_map.insert("netfilter_conntrack", false);
		return;
	}
	lib_map.insert("netfilter_conntrack", true);
	println!("cargo:rustc-cfg=conntrack=\"nfct\"");
}
#[cfg(target_os = "linux")]
fn probe_libnfnetlink(lib_map: &mut HashMap<&'static str, bool>) -> Result<(), Box<dyn Error>> {
	// let libnfnetlink = pkg_config::probe_library("libnfnetlink")?;
	if lib_map.contains_key("libnfnetlink") {
		return Ok(());
	}
	let headers = [
		"libnfnetlink/libnfnetlink.h",
		"libnfnetlink/linux_nfnetlink.h",
		"libnfnetlink/linux_nfnetlink_compat.h",
	];

	let ret = probe_lib_generic(
		"libnfnetlink",
		&headers,
		"nfnetlink",
		"libnfnetlink",
		Some(&["nlmsghdr", "iovec"]),
	);
	if ret.is_err() {
		lib_map.insert("libnfnetlink", false);
		return ret;
	}
	lib_map.insert("libnfnetlink", true);
	Ok(())
}

fn probe_linux_capability(_lib_map: &mut HashMap<&'static str, bool>) -> Result<(), Box<dyn Error>> {
	probe_lib_generic("libcap-ng", &["linux/capability.h"], "", "linux_capability", None)
}

fn probe_cap_ng(lib_map: &mut HashMap<&'static str, bool>) {
	if probe_lib_generic("libcap-ng", &["cap-ng.h"], "cap-ng", "cap-ng", None).is_err() {
		lib_map.insert("libcap-ng", false);
		return;
	}

	if probe_linux_capability(lib_map).is_err() {
		lib_map.insert("libcap-ng", false);
		return;
	}

	lib_map.insert("libcap-ng", true);
	println!("cargo:rustc-cfg=cap_lib=\"cap_ng\"");
}
fn probe_libcap(lib_map: &mut HashMap<&'static str, bool>) {
	if probe_lib_generic("libcap", &["sys/capability.h"], "cap", "capability", None).is_err() {
		lib_map.insert("libcap", false);
		return;
	}
	lib_map.insert("libcap", true);
	println!("cargo:rustc-cfg=cap_lib=\"cap\"");
}
/// native uuid impl is safe, but extern lib small, so~, sometimes we need
fn probe_libuuid() {
	if env::var("LIB_UUID") == Ok("1".to_string()) {
		println!("cargo:rustc-link-lib=uuid");
		println!("cargo:rustc-cfg=uuid=\"libuuid\"");
	} else {
		println!("cargo:rustc-cfg=uuid=\"native\"");
	}
}
#[cfg(target_os = "linux")]
fn probe_systemd(lib_map: &mut HashMap<&str, bool>) {
	if env::var("USE_SYSTEMD") != Ok("1".to_string()) {
		return;
	}
	if probe_lib_generic("libsystemd", &["systemd/sd-daemon.h"], "systemd", "libsystemd", None).is_err() {
		lib_map.insert("libsystemd", false);
		return;
	}
	lib_map.insert("libsystemd", true);
	println!("cargo:rustc-cfg=use_systemd");
}

fn probe_lib_generic(
	name: &str,
	headers: &[&'static str],
	link_name: &str,
	dst_file: &str,
	ignore_struct: Option<&[&str]>,
) -> Result<(), Box<dyn Error>> {
	let lib = pkg_config::probe_library(name)?;

	for p in lib.link_paths {
		println!("cargo:rustc-link-search=native={}", p.display());
	}
	if !link_name.is_empty() {
		println!("cargo::rustc-link-lib={link_name}");
	}
	let allow_files = lib
		.include_paths
		.iter()
		.flat_map(|x| headers.iter().map(|header| x.clone().join(header)))
		.map(|x| x.to_string_lossy().into_owned())
		.collect::<Vec<String>>();

	let header_content = headers.iter().map(|x| format!("#include <{}>", x)).collect::<Vec<String>>().join("\n");

	let mut bindings = bindgen::Builder::default()
		.header_contents("wrapper.h", &header_content)
		.clang_args(lib.include_paths.iter().map(|x| format!("-I{}", x.to_str().unwrap())))
		.use_core()
		.prepend_enum_name(false)
		.ctypes_prefix("libc")
		.rust_edition(bindgen::RustEdition::Edition2024)
		.rust_target(RustTarget::nightly());
	if let Some(ignore_struct) = ignore_struct {
		for block_type in ignore_struct {
			bindings = bindings.blocklist_type(block_type);
		}
	}

	for allow_file in allow_files {
		bindings = bindings.allowlist_file(allow_file);
	}
	let bindings = bindings.generate()?;
	let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
	bindings.write_to_file(out_path.join(format!("{dst_file}.rs")))?;
	Ok(())
}

fn load_env() {
	let script_path = "./configure";
	let ext_args = env::var("EXT_ARGS").unwrap_or("".to_string());

	let output = Command::new("sh")
		.arg("-c")
		.arg(format!(". {} {} && env", script_path, ext_args))
		.output()
		.expect("Failed to execute script");
	if output.status.success() {
		let stdout = String::from_utf8_lossy(&output.stdout);

		// 解析环境变量
		let env_vars: HashMap<String, String> = stdout
			.lines()
			.filter_map(|line| {
				if line.contains('=') {
					let mut parts = line.splitn(2, '=');
					Some((parts.next()?.to_string(), parts.next()?.to_string()))
				} else {
					None
				}
			})
			.collect();

		for (key, value) in env_vars {
			unsafe { env::set_var(&key, &value) };
		}
	} else {
		eprintln!("Failed to source script.");
	}
}

#[cfg(feature = "https")]
fn fix_openssl() {
	use openssl_sys;
	if openssl_sys::OPENSSL_VERSION_TEXT.starts_with(b"OpenSSL 3") {
		println!("cargo:rustc-cfg=openssl3");
	}
}

fn main() {
	load_env();
	// for e in env::vars() {
	// 	eprintln!("environment variable: {}={}", e.0, e.1);
	// }
	println!("cargo:rerun-if-changed=build.rs");

	let fw = env::var("FW").expect("FW environment variable not set");
	// let fw = "nftables".to_string();
	let os_version = env::var("OS_VERSION").expect("OS_VERSION environment variable not set");
	if os_version.contains("%s") {
		panic!("OS_VERSION contain '%s'\n");
	}

	let os_name = env::var("OS_NAME").unwrap_or("Ubuntu".to_string());
	let os_url = env::var("OS_URL").unwrap_or("https://www.ubuntu.com/".to_string());
	let date = env::var("MINIUPNPD_DATE").unwrap_or("".to_string());
	println!("cargo:rustc-cfg=fw=\"{fw}\"");
	println!("cargo:rustc-env=FW={fw}");
	// println!("cargo:rustc-check-cfg=cfg(fw, values(\"{fw}\"))");
	// println!("cargo:rustc-cfg=fw=\"iptables\"");
	println!("cargo:rustc-env=OS_NAME={os_name}");
	println!("cargo:rustc-env=OS_URL={os_url}");
	println!("cargo:rustc-env=OS_VERSION={os_version}");
	println!("cargo:rustc-env=MINIUPNPD_DATE={date}");
	println!("cargo:rerun-if-changed=configure");
	println!("cargo:rerun-if-env-changed=EXT_ARGS");
	println!("cargo:rerun-if-env-changed=HAS_LIBCAP_NG");
	println!("cargo:rerun-if-env-changed=HAS_LIBCAP");
	println!("cargo:rerun-if-env-changed=USE_GETIFADDRS");
	println!("cargo:rerun-if-env-changed=USE_SYSTEMD");

	let mut lib_map: HashMap<&str, bool> = HashMap::new();

	if env::var("HAS_LIBCAP_NG") == Ok("1".into()) {
		probe_cap_ng(&mut lib_map);
	} else if env::var("HAS_LIBCAP") == Ok("1".into()) {
		probe_libcap(&mut lib_map);
	} else {
		println!("cargo:rustc-cfg=cap_lib=\"none\"");
	}
	let use_getifaaddrs = env::var("USE_GETIFADDRS").unwrap_or("0".to_string());
	if use_getifaaddrs == "1" {
		println!("cargo:rustc-cfg=use_getifaddrs");
	}

	match fw.as_str() {
		#[cfg(target_os = "linux")]
		"iptables" => {
			println!("cargo::rustc-link-lib=ip4tc");
			println!("cargo::rustc-link-lib=ip6tc");
			probe_iptables();
			probe_libnetfilter_conntrack(&mut lib_map);
		}
		#[cfg(target_os = "linux")]
		"nftables" => {
			println!("cargo::rustc-link-lib=nftnl");
			println!("cargo::rustc-link-lib=mnl");
			probe_nftables();
			probe_libnetfilter_conntrack(&mut lib_map);
		}
		_ => {}
	}
	#[cfg(target_os = "linux")]
	build_if_addr();
	#[cfg(target_os = "linux")]
	probe_systemd(&mut lib_map);

	#[cfg(feature = "https")]
	fix_openssl();

	probe_libuuid();
	let features = env::var("CARGO_FEATURE_EVENTS").map(|_| "events").unwrap_or_default().to_string()
		+ env::var("CARGO_FEATURE_IGD2").map(|_| " igdv2").unwrap_or_default()
		+ env::var("CARGO_FEATURE_PCP_PEER").map(|_| " PCP-PEER").unwrap_or_default()
		+ env::var("CARGO_FEATURE_PCP_FLOWP").map(|_| " PCP-FLOWP").unwrap_or_default()
		+ env::var("CARGO_FEATURE_PCP_SADSCP").map(|_| " PCP-SADSCP").unwrap_or_default()
		+ env::var("CARGO_FEATURE_LEASEFILE").map(|_| " leasefile").unwrap_or_default()
		+ env::var("CARGO_FEATURE_CHECK_PORTINUSE").map(|_| " check_portinuse").unwrap_or_default()
		+ env::var("CARGO_FEATURE_STRICT").map(|_| " strict").unwrap_or_default()
		+ env::var("CARGO_FEATURE_IPV6").map(|_| " ipv6").unwrap_or_default()
		+ env::var("CARGO_FEATURE_MINIUPNPDCTL").map(|_| " miniupnpdctl").unwrap_or_default();
	println!("cargo:rustc-env=FEATURES={features}");
}
