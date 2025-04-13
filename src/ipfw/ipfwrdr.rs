#![allow(
	dead_code,
	mutable_transmutes,
	non_camel_case_types,
	non_snake_case,
	non_upper_case_globals,
	unused_assignments,
	unused_mut
)]
#![feature(extern_types)]
extern "C" {
	fn ipfw_free_ruleset(rules: *mut *mut ip_fw);
	fn ipfw_fetch_ruleset(rules: *mut *mut ip_fw_0, total_fetched: *mut i32, count: i32) -> i32;
	fn ipfw_validate_protocol(value: i32) -> i32;
	fn ipfw_validate_ifname(value: *const libc::c_char) -> i32;
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mapping_desc_time {
	pub next: *mut mapping_desc_time,
	pub timestamp: u32,
	pub eport: u16,
	pub proto: libc::c_short,
	pub desc: [libc::c_char; 0],
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn init_redirect() -> i32 {
	panic!("Reached end of non-void function without returning");
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shutdown_redirect() {}
static mut mappings_list: *mut mapping_desc_time = 0 as *const mapping_desc_time as *mut mapping_desc_time;
unsafe extern "C" fn add_desc_time(mut eport: u16, mut proto: i32, mut desc: *const libc::c_char, mut timestamp: u32) {
	let mut tmp: *mut mapping_desc_time = 0 as *mut mapping_desc_time;
	let mut l: usize = 0;
	if desc.is_null() {
		desc = b"miniupnpd\0" as *const u8 as *const libc::c_char;
	}
	l = (strlen(desc)).wrapping_add(1 as i32 as libc::c_ulong);
	tmp = malloc((::core::mem::size_of::<mapping_desc_time>() as libc::c_ulong).wrapping_add(l))
		as *mut mapping_desc_time;
	if !tmp.is_null() {
		(*tmp).next = mappings_list;
		(*tmp).timestamp = timestamp;
		(*tmp).eport = eport;
		(*tmp).proto = proto as libc::c_short;
		memcpy(
			((*tmp).desc).as_mut_ptr() as *mut libc::c_void,
			desc as *const libc::c_void,
			l,
		);
		mappings_list = tmp;
	}
}
unsafe extern "C" fn del_desc_time(mut eport: u16, mut proto: i32) {
	let mut e: *mut mapping_desc_time = 0 as *mut mapping_desc_time;
	let mut p: *mut *mut mapping_desc_time = 0 as *mut *mut mapping_desc_time;
	p = &mut mappings_list;
	e = *p;
	while !e.is_null() {
		if (*e).eport as i32 == eport as i32 && (*e).proto as i32 == proto as libc::c_short as i32 {
			*p = (*e).next;
			free(e as *mut libc::c_void);
			return;
		} else {
			p = &mut (*e).next;
			e = *p;
		}
	}
}
unsafe extern "C" fn get_desc_time(
	mut eport: u16,
	mut proto: i32,
	mut desc: *mut libc::c_char,
	mut desclen: i32,
	mut timestamp: *mut u32,
) {
	let mut e: *mut mapping_desc_time = 0 as *mut mapping_desc_time;
	e = mappings_list;
	while !e.is_null() {
		if (*e).eport as i32 == eport as i32 && (*e).proto as i32 == proto as libc::c_short as i32 {
			if !desc.is_null() {
				strlcpy(desc, ((*e).desc).as_mut_ptr(), desclen);
			}
			if !timestamp.is_null() {
				*timestamp = (*e).timestamp;
			}
			return;
		}
		e = (*e).next;
	}
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn add_filter_rule2(
	mut ifname: *const libc::c_char,
	mut rhost: *const libc::c_char,
	mut iaddr: *const libc::c_char,
	mut eport: u16,
	mut iport: u16,
	mut proto: i32,
	mut desc: *const libc::c_char,
) -> i32 {
	return 0 as i32;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn delete_filter_rule(mut ifname: *const libc::c_char, mut eport: u16, mut proto: i32) -> i32 {
	return 0 as i32;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn update_portmapping_desc_timestamp(
	mut ifname: *const libc::c_char,
	mut eport: u16,
	mut proto: i32,
	mut desc: *const libc::c_char,
	mut timestamp: u32,
) -> i32 {
	del_desc_time(eport, proto);
	add_desc_time(eport, proto, desc, timestamp);
	return 0 as i32;
}
