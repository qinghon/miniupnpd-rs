use crate::Rc;
use crate::PinholeEntry;
use crate::netfilter_nft::nftnlrdr::nftable;
use crate::netfilter_nft::nftnlrdr_misc::rule_t;
use crate::netfilter_nft::nftnlrdr_misc::rule_type::RULE_FILTER;

pub(crate) struct Nftable6Iter<'a> {
	rule: Box<dyn Iterator<Item = &'a rule_t> + 'a>,
	entry: PinholeEntry,
}
impl<'a> Nftable6Iter<'a> {
	pub(super) fn new(n: &'a nftable) -> Nftable6Iter<'a> {
		let iter = Box::new(n.filter_rule.iter());
		Self { rule: iter, entry: Default::default() }
	}
}
impl<'a> Iterator for Nftable6Iter<'a> {
	type Item = &'a mut PinholeEntry;

	fn next(&mut self) -> Option<Self::Item> {
		let rule = loop {
			let rule = self.rule.next()?;
			if rule.type_0 != RULE_FILTER {
				continue;
			}
			if rule.desc.is_empty() || !rule.desc.starts_with("pinhole-") {
				continue;
			}
			break rule;
		};

		self.entry = PinholeEntry::default();
		self.entry.proto = rule.proto;
		self.entry.eport = rule.sport;
		self.entry.iport = rule.dport;

		self.entry.iaddr = rule.saddr6;
		self.entry.eaddr = rule.daddr6;

		let (uid, ts) = parse_pinhole_desc(&rule.desc)?;
		self.entry.index = uid as _;
		self.entry.timestamp = ts as _;
		self.entry.desc = Some(Rc::from(rule.desc.split_ascii_whitespace().nth(2)?.as_str()));

		Some(unsafe { &mut *((&mut self.entry) as *mut PinholeEntry) })
	}
}

pub(super) fn parse_pinhole_desc(s: &str) -> Option<(u16, u32)> {
	let mut u = -1i32;
	let mut t = 0;

	for token in s.split(&[' ', ':']) {
		if token.starts_with("pinhole-") {
			let (_, d) = token.split_once('-')?;
			u = d.parse::<u16>().ok()? as i32;
		} else if token.starts_with("ts-") {
			let (_, d) = token.split_once('-')?;
			t = d.parse::<u32>().ok()?;
		}
	}

	if u == -1 || t == 0 { None } else { Some((u as _, t)) }
}
#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn test_pinhole_desc() {
		assert_eq!(parse_pinhole_desc("pinhole-0 ts-464165: test desc"), Some((0, 464165)));
		assert_eq!(parse_pinhole_desc("pinhole-0 ts-0: test desc"), None);
		assert_eq!(parse_pinhole_desc("pinhole-0 ts-464165: "), Some((0, 464165)));
	}
}
