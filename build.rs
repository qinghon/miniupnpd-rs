use bindgen::RustTarget;
use std::collections::HashMap;
use std::env;
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

fn probe_cap_ng() {
	let libcap_ng = pkg_config::probe_library("libcap-ng");
	if libcap_ng.is_err() {
		return;
	}
	let libcap_ng = libcap_ng.unwrap();
	for p in libcap_ng.link_paths {
		println!("cargo:rustc-link-search=native={}", p.display());
	}
	println!("cargo::rustc-link-lib=cap-ng");

	const CAPNG_FREFIX: &str = "^(capng|CAPNG|CAP)_.+";
	let bindings = bindgen::Builder::default()
		.header_contents("wrapper.h", "#include <cap-ng.h>")
		.clang_args(libcap_ng.include_paths.iter().map(|x| format!("-I{}", x.to_str().unwrap())))
		.use_core()
		.prepend_enum_name(false)
		.allowlist_function(CAPNG_FREFIX)
		.allowlist_var(CAPNG_FREFIX)
		.allowlist_type(CAPNG_FREFIX)
		.ctypes_prefix("libc")
		.rust_target(RustTarget::nightly())
		.generate()
		.expect("Couldn't generate bindings");

	let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
	bindings.write_to_file(out_path.join("cap-ng.rs")).unwrap();
	println!("cargo:rustc-cfg=cap_lib=\"cap_ng\"");
}
fn probe_libcap() {
	let libcap = pkg_config::probe_library("libcap");
	if libcap.is_err() {
		return;
	}
	let libcap = libcap.unwrap();
	for p in libcap.link_paths {
		println!("cargo:rustc-link-search=native={}", p.display());
	}
	println!("cargo::rustc-link-lib=cap");

	const CAPNG_FREFIX: &str = "^(cap|CAP)_.+";
	let bindings = bindgen::Builder::default()
		.header_contents("wrapper.h", "#include <sys/capability.h>")
		.clang_args(libcap.include_paths.iter().map(|x| format!("-I{}", x.to_str().unwrap())))
		.use_core()
		.prepend_enum_name(false)
		.allowlist_function(CAPNG_FREFIX)
		.allowlist_var(CAPNG_FREFIX)
		.allowlist_type(CAPNG_FREFIX)
		.ctypes_prefix("libc")
		.rust_target(RustTarget::nightly())
		.generate()
		.expect("Couldn't generate bindings");

	let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
	bindings.write_to_file(out_path.join("capability.rs")).unwrap();
	println!("cargo:rustc-cfg=cap_lib=\"cap\"");
}
/// native uuid impl is safe, but extern lib small, so~, sometimes we need
fn probe_libuuid() {
	if env::var("LIB_UUID") == Ok("1".to_string()) {
		println!("cargo:rustc-link-lib=uuid");
		println!("cargo:rustc-cfg=uuid=\"libuuid\"");
	}else {
		println!("cargo:rustc-cfg=uuid=\"native\"");
	}
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

fn main() {
	load_env();
	// for e in env::vars() {
	// 	eprintln!("environment variable: {}={}", e.0, e.1);
	// }
	println!("cargo:rerun-if-changed=build.rs");

	let fw = env::var("FW").expect("FW environment variable not set");
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

	if env::var("HAS_LIBCAP_NG") == Ok("1".into()) {
		probe_cap_ng();
	} else if env::var("HAS_LIBCAP") == Ok("1".into()) {
		probe_libcap();
	} else {
		println!("cargo:rustc-cfg=cap_lib=\"none\"");
	}
	let use_getifaaddrs = env::var("USE_GETIFADDRS").unwrap_or("0".to_string());
	if use_getifaaddrs == "1" {
		println!("cargo:rustc-cfg=use_getifaddrs=\"1\"");
	} else {
		println!("cargo:rustc-cfg=use_getifaddrs=\"0\"");
	}

	match fw.as_str() {
		"iptables" => {
			println!("cargo::rustc-link-lib=ip4tc");
			println!("cargo::rustc-link-lib=ip6tc");
			probe_iptables();
		}
		"nftables" => {
			println!("cargo::rustc-link-lib=nftnl");
			println!("cargo::rustc-link-lib=mnl");
			probe_nftables();
		}
		_ => {}
	}
	#[cfg(target_os = "linux")]
	build_if_addr();
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
