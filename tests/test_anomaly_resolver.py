import itertools
import os
import random
import tempfile
import unittest

from anomaly_resolver import AnomalyResolver, Rule, SimpleRuleParser


def first_match(rules, packet):
	for rule in rules:
		if packet.issubset(rule):
			return rule.actions
	return None


class RuleHelperTests(unittest.TestCase):

	def test_detail_repr_includes_direction_and_action(self):
		detail = Rule(direction='OUT', actions='ALLOW').__repr__('detail')
		self.assertIn('direction:OUT', detail)
		self.assertIn('actions:ALLOW', detail)

	def test_wildcard_port_contiguous_check_uses_port_parsing(self):
		self.assertFalse(Rule.contiguous('*', '1', attribute='tp_src'))

	def test_ip_ranges_merge_when_contiguous(self):
		left = '129.110.96.64-129.110.96.127'
		right = '129.110.96.128-129.110.96.164'
		self.assertTrue(Rule.contiguous(left, right, attribute='nw_dst'))
		self.assertEqual(
			Rule.combine_range(left, right, attribute='nw_dst'),
			'129.110.96.64-129.110.96.164'
		)


class ParserTests(unittest.TestCase):

	def test_parser_skips_comments_and_blank_lines(self):
		with tempfile.NamedTemporaryFile('w', delete=False) as handle:
			handle.write('# comment\n')
			handle.write('\n')
			handle.write('1. <IN, TCP, ANY, ANY, ANY, 80, REJECT>\n')
			path = handle.name
		self.addCleanup(lambda: os.remove(path))

		parsed = SimpleRuleParser(path)
		self.assertEqual(len(parsed.rules), 1)

	def parse(self, *lines):
		with tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8') as handle:
			handle.write(''.join(line + '\n' for line in lines))
			path = handle.name
		self.addCleanup(lambda: os.remove(path))
		return SimpleRuleParser(path).rules

	def test_invalid_value_names_the_line(self):
		with self.assertRaises(ValueError) as error:
			self.parse('1. <IN, TCP, ANY, ANY, ANY, 80, REJECT>',
				'2. <IN, TCP, 129.110.96.300, ANY, 129.110.96.80, 22, ACCEPT>')
		self.assertIn("Invalid IPv4 value '129.110.96.300' on line 2", str(error.exception))

	def test_tab_separated_fields_are_parsed(self):
		rules = self.parse('1.\t<IN,\tUDP,\t10.0.0.1,\tANY,\tANY,\t53,\tACCEPT>')
		self.assertEqual(str(rules[0]), '<IN, UDP, 10.0.0.1, *, *, 53, ALLOW>')


class InputValidationTests(unittest.TestCase):

	def test_values_that_do_not_parse_are_rejected(self):
		# Issue #3: these used to become ANY, TCP, IN or DENY without a warning.
		invalid = {
			'nw_src': ['129.110.96.300', '129.110.96.1l7', '2001:db8::1', '10.*.0.*',
				'', '10.0.0.1/33', '10.0.0.1/3200', '10.0.0.9-10.0.0.1', '10.0.0.9-1',
				'10.0.0.1-10.0.0.2-3', 'abc-5', '010.0.0.1'],
			'tp_dst': ['8O', '44E', '0x50', '', '-1', '1-', '70000', '1-70000', '80-20', '1-2-3'],
			'nw_proto': ['ANY', 'SCTP', ''],
			'direction': ['INBOUND', ''],
			'actions': ['DROP', ''],
			'priority': [-1, 65536, '5', True],
		}
		for field, values in invalid.items():
			for value in values:
				with self.subTest(field=field, value=value):
					with self.assertRaises(ValueError):
						Rule(**{field: value})

	def test_valid_values_are_normalized(self):
		valid = [
			('nw_src', 'ANY', '*'), ('nw_src', 'any', '*'), ('nw_src', '*', '*'),
			('nw_src', '10.0.0.1', '10.0.0.1'), ('nw_src', '10.0.0.1/32', '10.0.0.1'),
			('nw_src', '10.0.0.5/24', '10.0.0.5/24'),
			('nw_src', '10.0.0.0/255.255.255.0', '10.0.0.0/255.255.255.0'),
			('nw_src', '202.80.169.29-63', '202.80.169.29-202.80.169.63'),
			('nw_src', '129.110.96.*', '129.110.96.0/24'),
			('nw_src', '10.0.1-2.*', '10.0.1.0-10.0.2.255'),
			('tp_dst', 'ANY', '*'), ('tp_dst', '0-65535', '*'), ('tp_dst', '80', '80'),
			('tp_dst', '1000-2000', '1000-2000'), ('tp_dst', '65535', '65535'),
			('nw_proto', 'udp', 'UDP'), ('nw_proto', 'ICMPv6', 'ICMPv6'),
			('dl_type', 'ipv6', 'IPv6'), ('dl_type', 'IPv4', 'IPv4'),
			('direction', 'out', 'OUT'), ('actions', 'accept', 'ALLOW'),
			('actions', 'reject', 'DENY'), ('priority', 65535, 65535),
		]
		for field, value, expected in valid:
			with self.subTest(field=field, value=value):
				self.assertEqual(getattr(Rule(**{field: value}), field), expected)


class ResolverTests(unittest.TestCase):

	def test_resolver_instances_do_not_stack_handlers(self):
		first = AnomalyResolver(log_level='CRITICAL')
		second = AnomalyResolver(log_level='CRITICAL')
		self.assertEqual(len(first.resolver_logger.handlers), 1)
		self.assertEqual(len(second.resolver_logger.handlers), 1)


class DetectionTests(unittest.TestCase):

	def setUp(self):
		self.resolver = AnomalyResolver(log_level='CRITICAL')

	def tearDown(self):
		self.resolver.resolver_logger.handlers.clear()

	def redundancies(self, rules):
		with self.assertLogs(self.resolver.resolver_logger, 'INFO') as logs:
			self.resolver.detect_anomalies(rules)
		return [record.getMessage().split('\n\t')[1:] for record in logs.records
			if record.getMessage().startswith('Redundancy Anomaly')]

	def test_rule_needed_by_a_rule_in_between_is_not_redundant(self):
		# Issue #2: removing the host rule would let the subnet ALLOW decide.
		rules = [Rule(nw_src='10.0.0.1', tp_dst='80', actions='DENY'),
			Rule(nw_src='10.0.0.0/24', tp_dst='80', actions='ALLOW'),
			Rule(nw_src='*', tp_dst='80', actions='DENY')]
		self.assertEqual(self.redundancies(rules), [])

	def test_rule_covered_by_a_later_rule_with_the_same_action_is_redundant(self):
		host = Rule(nw_src='10.0.0.1', tp_dst='80', actions='DENY')
		subnet = Rule(nw_src='10.0.0.0/24', tp_dst='80', actions='DENY')
		self.assertEqual(self.redundancies([host, subnet]), [[str(host), str(subnet)]])

	def test_later_rule_inside_an_earlier_rule_with_the_same_action_is_redundant(self):
		# The host rule never matches, whatever lies in between.
		subnet = Rule(nw_src='10.0.0.0/24', tp_dst='80', actions='DENY')
		everyone = Rule(nw_src='*', tp_dst='80', actions='ALLOW')
		host = Rule(nw_src='10.0.0.1', tp_dst='80', actions='DENY')
		self.assertEqual(self.redundancies([subnet, everyone, host]),
			[[str(subnet), str(host)]])


class ResolveTests(unittest.TestCase):
	# insert() never builds a list with two rules covering the same packets, but
	# resolve() must not rely on that: Rule.__eq__ ignores the action.

	def setUp(self):
		self.resolver = AnomalyResolver(log_level='CRITICAL')

	def tearDown(self):
		self.resolver.resolver_logger.handlers.clear()

	def test_rule_is_reordered_right_before_the_rule_containing_it(self):
		twin = Rule(nw_src='10.0.0.0/24', tp_dst='80', actions='ALLOW')
		subnet = Rule(nw_src='10.0.0.0/24', tp_dst='80', actions='DENY')
		host = Rule(nw_src='10.0.0.1', tp_dst='80', actions='ALLOW')
		rules = [twin, subnet]
		self.assertTrue(self.resolver.resolve(host, subnet, rules))
		self.assertEqual(len(rules), 3)
		self.assertIs(rules[0], twin)
		self.assertIs(rules[1], host)
		self.assertIs(rules[2], subnet)

	def test_correlated_rule_replaces_the_rule_it_overlaps(self):
		twin = Rule(nw_src='10.0.0.0/24', tp_dst='80-90', actions='ALLOW')
		existing = Rule(nw_src='10.0.0.0/24', tp_dst='80-90', actions='DENY')
		overlapping = Rule(nw_src='10.0.0.0/24', tp_dst='85-100', actions='DENY')
		rules = [twin, existing]
		self.assertTrue(self.resolver.resolve(overlapping, existing, rules))
		self.assertEqual(sum(rule is twin for rule in rules), 1)
		self.assertEqual(sum(rule is existing for rule in rules), 1)


class RedundancyRemovalTests(unittest.TestCase):

	def setUp(self):
		self.resolver = AnomalyResolver(log_level='CRITICAL')

	def tearDown(self):
		# The logger outlives the resolver. Drop its handler so a later resolver
		# that reuses the same id does not end up with two.
		self.resolver.resolver_logger.handlers.clear()

	def test_deny_exception_before_broader_allow_is_kept(self):
		# Issue #2: the host rule is not redundant with the last rule, because
		# the subnet ALLOW in between would take over its packets.
		def policy():
			return [Rule(nw_src='10.0.0.1', tp_dst='80', actions='DENY'),
				Rule(nw_src='10.0.0.0/24', tp_dst='80', actions='ALLOW'),
				Rule(nw_src='*', tp_dst='80', actions='DENY')]
		packet = Rule(nw_src='10.0.0.1', tp_src='1234', nw_dst='8.8.8.8', tp_dst='80')
		resolved = self.resolver.resolve_anomalies(policy())
		self.assertEqual(len(resolved), 3)
		self.assertEqual(first_match(policy(), packet), 'DENY')
		self.assertEqual(first_match(resolved, packet), 'DENY')

	def test_allow_exception_between_deny_rules_is_kept(self):
		rules = [Rule(nw_src='10.0.0.1', tp_dst='80', actions='ALLOW'),
			Rule(nw_src='10.0.0.0/24', tp_dst='80', actions='DENY'),
			Rule(nw_src='*', tp_dst='80', actions='ALLOW')]
		kept = self.resolver.remove_redundant_rules(rules)
		self.assertEqual([rule.actions for rule in kept], ['ALLOW', 'DENY', 'ALLOW'])

	def test_rule_covered_by_first_broader_rule_with_same_action_is_removed(self):
		host = Rule(nw_src='10.0.0.1', tp_dst='80', actions='DENY')
		subnet = Rule(nw_src='10.0.0.0/24', tp_dst='80', actions='DENY')
		everyone = Rule(nw_src='*', tp_dst='80', actions='ALLOW')
		kept = self.resolver.remove_redundant_rules([host, subnet, everyone])
		self.assertEqual(len(kept), 2)
		self.assertIs(kept[0], subnet)
		self.assertIs(kept[1], everyone)

	def test_rule_with_an_empty_range_is_removed(self):
		# A reversed port range matches nothing, so removing the rule is safe.
		# Rule() rejects one, but assigning the field directly still works.
		empty = Rule(nw_src='10.0.0.1', tp_dst='20-80', actions='DENY')
		empty.tp_dst = '80-20'
		subnet = Rule(nw_src='10.0.0.0/24', tp_dst='1-100', actions='DENY')
		kept = self.resolver.remove_redundant_rules([empty, subnet])
		self.assertEqual(len(kept), 1)
		self.assertIs(kept[0], subnet)

	def test_disjoint_and_same_action_rules_before_the_container_are_skipped(self):
		host = Rule(nw_src='10.0.0.1', tp_dst='80-81', actions='DENY')
		other_host = Rule(nw_src='10.0.0.9', tp_dst='80', actions='ALLOW')
		overlapping = Rule(nw_src='10.0.0.1', tp_dst='81-200', actions='DENY')
		subnet = Rule(nw_src='10.0.0.0/24', tp_dst='1-100', actions='DENY')
		kept = self.resolver.remove_redundant_rules([host, other_host, overlapping, subnet])
		self.assertEqual(len(kept), 3)
		self.assertIs(kept[0], other_host)
		self.assertIs(kept[1], overlapping)
		self.assertIs(kept[2], subnet)

	def test_rules_are_removed_by_identity(self):
		# Rule.__eq__ ignores the action, so list.remove would drop host_allow.
		host_allow = Rule(nw_src='10.0.0.1', tp_dst='80', actions='ALLOW')
		host_deny = Rule(nw_src='10.0.0.1', tp_dst='80', actions='DENY')
		subnet = Rule(nw_src='10.0.0.0/24', tp_dst='80', actions='DENY')
		kept = self.resolver.remove_redundant_rules([host_allow, host_deny, subnet])
		self.assertEqual(len(kept), 2)
		self.assertIs(kept[0], host_allow)
		self.assertIs(kept[1], subnet)

	def test_redundant_rules_are_logged_in_list_order(self):
		host = Rule(nw_src='10.0.0.1', tp_dst='80', actions='DENY')
		subnet = Rule(nw_src='10.0.0.0/24', tp_dst='80', actions='DENY')
		everyone = Rule(nw_src='*', tp_dst='80', actions='DENY')
		with self.assertLogs(self.resolver.resolver_logger, 'INFO') as logs:
			self.resolver.remove_redundant_rules([host, subnet, everyone])
		self.assertEqual([record.getMessage() for record in logs.records],
			['Redundant rule %s' % host, 'Redundant rule %s' % subnet])

	def test_removal_never_changes_a_decision(self):
		# Random policies over a small space, checked against every packet in it
		# with plain integer ranges rather than Rule.issubset. Most ranges span
		# the whole space and most rules share a direction and protocol, so rules
		# often contain one another. Explicit in_port values keep the port checks
		# small.
		generator = random.Random(2)

		def bounds(low, high):
			if generator.random() < 0.6:
				return low, high
			first = generator.randrange(low, high + 1)
			return first, generator.randrange(first, high + 1)

		def address(prefix, low, high):
			if generator.random() < 0.2:
				return '*', (0, 255)
			first, last = bounds(low, high)
			if first == last:
				return '%s.%d' % (prefix, first), (first, last)
			return '%s.%d-%s.%d' % (prefix, first, prefix, last), (first, last)

		def port(low, high):
			first, last = bounds(low, high)
			return (str(first) if first == last else '%d-%d' % (first, last)), (first, last)

		def random_rule():
			nw_src, nw_src_bounds = address('10.0.0', 0, 4)
			nw_dst, nw_dst_bounds = address('10.0.1', 0, 2)
			tp_src, tp_src_bounds = port(1, 2)
			tp_dst, tp_dst_bounds = port(1, 3)
			fields = {'direction': generator.choice(['IN', 'IN', 'IN', 'OUT']),
				'nw_proto': generator.choice(['TCP', 'TCP', 'TCP', 'UDP']),
				'nw_src': nw_src_bounds, 'nw_dst': nw_dst_bounds,
				'tp_src': tp_src_bounds, 'tp_dst': tp_dst_bounds,
				'actions': generator.choice(['ALLOW', 'DENY'])}
			rule = Rule(in_port='1', direction=fields['direction'],
				nw_proto=fields['nw_proto'], nw_src=nw_src, nw_dst=nw_dst,
				tp_src=tp_src, tp_dst=tp_dst, actions=fields['actions'])
			return rule, fields

		def decision(rules_fields, packet):
			for fields in rules_fields:
				if fields['direction'] == packet['direction'] and \
					fields['nw_proto'] == packet['nw_proto'] and \
					all(fields[key][0] <= packet[key] <= fields[key][1]
						for key in ('nw_src', 'nw_dst', 'tp_src', 'tp_dst')):
					return fields['actions']
			return None

		keys = ('direction', 'nw_proto', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst')
		packets = [dict(zip(keys, values)) for values in itertools.product(
			['IN', 'OUT'], ['TCP', 'UDP'], range(6), range(4), range(4), range(5))]
		for _ in range(400):
			pairs = [random_rule() for _ in range(generator.randrange(2, 9))]
			rules = [rule for rule, _ in pairs]
			kept = self.resolver.remove_redundant_rules(rules)
			remaining = iter(rules)
			self.assertTrue(all(any(rule is other for other in remaining) for rule in kept),
				'kept rules must stay in their original order')
			if len(kept) == len(rules):
				continue
			fields_of = dict((id(rule), fields) for rule, fields in pairs)
			before = [fields for _, fields in pairs]
			after = [fields_of[id(rule)] for rule in kept]
			for packet in packets:
				self.assertEqual(decision(after, packet), decision(before, packet),
					'%s changed for %s -> %s' % (packet, rules, kept))
