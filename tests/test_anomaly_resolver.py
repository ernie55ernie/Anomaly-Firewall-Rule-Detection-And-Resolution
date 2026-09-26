import itertools
import os
import random
import tempfile
import unittest

import networkx as nx

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


class MergeTests(unittest.TestCase):
	# Trees are built with plot=False so the README images in img/ are not
	# overwritten.

	def setUp(self):
		self.resolver = AnomalyResolver(log_level='CRITICAL')

	def tearDown(self):
		self.resolver.resolver_logger.handlers.clear()

	def paths(self):
		# One list of edge ranges per root-to-leaf path, that is, per rule.
		tree = self.resolver.tree
		result = list()
		pending = [(self.resolver.get_rule_tree_root(), [])]
		while pending:
			node, ranges = pending.pop()
			edges = list(tree.edges([node]))
			if not edges:
				result.append(ranges)
			for edge in edges:
				pending.append((edge[1], ranges + [tree.edges[edge]['range']]))
		return sorted(result)

	def merge(self, rules):
		self.resolver.construct_rule_tree(rules, plot=False)
		self.resolver.merge(self.resolver.get_rule_tree_root())
		return self.paths()

	def test_rules_below_siblings_with_the_same_range_are_kept(self):
		# Issue #5: merging 1-5 and 6-10 left two 1-10 edges below each source,
		# the sources were then taken as equal, and the DENY rule was dropped.
		rules = [
			Rule(nw_src='10.0.0.1', tp_src='1-10', nw_dst='10.0.1.1', tp_dst='80', actions='ALLOW'),
			Rule(nw_src='10.0.0.1', tp_src='1-5', nw_dst='10.0.1.2', tp_dst='80', actions='ALLOW'),
			Rule(nw_src='10.0.0.1', tp_src='6-10', nw_dst='10.0.1.2', tp_dst='80', actions='ALLOW'),
			Rule(nw_src='10.0.0.2', tp_src='1-10', nw_dst='10.0.1.3', tp_dst='80', actions='DENY'),
			Rule(nw_src='10.0.0.2', tp_src='1-5', nw_dst='10.0.1.2', tp_dst='80', actions='ALLOW'),
			Rule(nw_src='10.0.0.2', tp_src='6-10', nw_dst='10.0.1.2', tp_dst='80', actions='ALLOW'),
		]
		self.assertEqual(self.merge(rules), [
			['IN', 'TCP', '10.0.0.1', '1-10', '10.0.1.1', '80', 'ALLOW'],
			['IN', 'TCP', '10.0.0.1', '1-10', '10.0.1.2', '80', 'ALLOW'],
			['IN', 'TCP', '10.0.0.2', '1-10', '10.0.1.2', '80', 'ALLOW'],
			['IN', 'TCP', '10.0.0.2', '1-10', '10.0.1.3', '80', 'DENY'],
		])

	def test_subtree_equal_counts_children_with_the_same_range(self):
		def subtree(node, actions):
			for index, action in enumerate(actions):
				child = '%s.%d' % (node, index)
				self.resolver.tree.add_edge(node, child, range='1-10')
				self.resolver.tree.add_edge(child, child + '.leaf', range=action)

		self.resolver.tree = nx.DiGraph()
		for node, actions in [('a', ['ALLOW', 'DENY']), ('b', ['DENY', 'DENY']), ('c', ['DENY', 'ALLOW'])]:
			self.resolver.tree.add_edge('root', node, range=node)
			subtree(node, actions)
		# The last 1-10 child of a and b match, but their first ones differ.
		self.assertFalse(self.resolver.subtree_equal(('root', 'a'), ('root', 'b')))
		# a and c hold the same children, added in a different order.
		self.assertTrue(self.resolver.subtree_equal(('root', 'a'), ('root', 'c')))

	def test_merging_keeps_every_rule_in_random_variants_of_issue_5(self):
		# Each source gets a full tp_src range plus two halves that merge into
		# it, with random destinations and actions.
		generator = random.Random(9)
		sources = ['10.0.0.1', '10.0.0.2']
		for _ in range(150):
			rules = list()
			for source in sources:
				rules.append(Rule(nw_src=source, tp_src='1-10', tp_dst='80',
					nw_dst='10.0.1.%d' % generator.randrange(1, 4),
					actions=generator.choice(['ALLOW', 'DENY'])))
				destination = '10.0.1.%d' % generator.randrange(1, 4)
				action = generator.choice(['ALLOW', 'DENY'])
				for ports in ['1-5', '6-10']:
					rules.append(Rule(nw_src=source, tp_src=ports, tp_dst='80',
						nw_dst=destination, actions=action))
			expected = set((rule.nw_src, rule.nw_dst, rule.actions) for rule in rules)
			merged = set()
			for path in self.merge(rules):
				addresses = Rule.ipstr2range(path[2])
				for source in sources:
					if Rule.ipstr2range(source)[0] in addresses:
						merged.add((source, path[4], path[6]))
			self.assertEqual(merged, expected, '%s -> %s' % (rules, self.paths()))

	def test_merging_keeps_the_actions_every_packet_can_reach(self):
		# Every root-to-leaf path is a rule, so a merge must not change which
		# actions each packet can reach. Values are drawn from aligned pieces
		# so that merges are common.
		generator = random.Random(5)
		choices = {'nw_src': ['10.0.0.0', '10.0.0.1', '10.0.0.0-10.0.0.1'],
			'tp_src': ['1-2', '3-4', '1-4'], 'nw_dst': ['10.0.1.0-10.0.1.1',
			'10.0.1.2-10.0.1.3', '10.0.1.0-10.0.1.3'], 'tp_dst': ['1', '2', '1-2']}
		order = ['nw_src', 'tp_src', 'nw_dst', 'tp_dst']

		def bounds(key, value):
			values = Rule.ipstr2range(value) if key.startswith('nw') else Rule.portstr2range(value)
			return int(values[0]), int(values[-1])

		packets = list(itertools.product(
			[bounds('nw_src', '10.0.0.%d' % host)[0] for host in range(3)], range(6),
			[bounds('nw_dst', '10.0.1.%d' % host)[0] for host in range(5)], range(4)))

		def reachable():
			# Each path's ranges as integer bounds, in the order of `order`.
			paths = [([bounds(key, value) for key, value in zip(order, path[2:6])], path[6])
				for path in self.paths()]
			return dict((packet, set(action for ranges, action in paths
				if all(low <= value <= high for value, (low, high) in zip(packet, ranges))))
				for packet in packets)

		merged_cases = 0
		for _ in range(60):
			rules = dict()
			for _ in range(generator.randrange(3, 10)):
				key = tuple(generator.choice(choices[field]) for field in order)
				rules.setdefault(key, generator.choice(['ALLOW', 'ALLOW', 'DENY']))
			self.resolver.construct_rule_tree([Rule(actions=action, **dict(zip(order, key)))
				for key, action in rules.items()], plot=False)
			before, paths_before = reachable(), len(self.paths())
			try:
				self.resolver.merge(self.resolver.get_rule_tree_root())
			except KeyError:
				# merge() still raises KeyError at some nodes with three or
				# more children (#7); those trees are skipped here.
				continue
			merged_cases += len(self.paths()) < paths_before
			self.assertEqual(reachable(), before)
		self.assertGreater(merged_cases, 5)


class ParserTests(unittest.TestCase):

	def test_parser_skips_comments_and_blank_lines(self):
		with tempfile.NamedTemporaryFile('w', delete=False) as handle:
			handle.write('# comment\n')
			handle.write('\n')
			handle.write('1. <IN, TCP, ANY, ANY, ANY, 80, REJECT>\n')
			path = handle.name
		self.addCleanup(os.remove, path)

		parsed = SimpleRuleParser(path)
		self.assertEqual(len(parsed.rules), 1)

	def parse(self, *lines):
		with tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8') as handle:
			handle.write(''.join(line + '\n' for line in lines))
			path = handle.name
		self.addCleanup(os.remove, path)
		return SimpleRuleParser(path).rules

	def test_invalid_value_names_the_line(self):
		with self.assertRaises(ValueError) as error:
			self.parse('1. <IN, TCP, ANY, ANY, ANY, 80, REJECT>',
				'2. <IN, TCP, 129.110.96.300, ANY, 129.110.96.80, 22, ACCEPT>')
		self.assertIn("Invalid IPv4 value '129.110.96.300' on line 2", str(error.exception))

	def test_tab_separated_fields_are_parsed(self):
		rules = self.parse('1.\t<IN,\tUDP,\t10.0.0.1,\tANY,\tANY,\t53,\tACCEPT>')
		self.assertEqual(str(rules[0]), '<IN, UDP, 10.0.0.1, *, *, 53, ALLOW>')

	def test_whitespace_inside_a_field_is_rejected(self):
		# It used to be deleted, so '22 23' became port 2223.
		for line, bad_value in [('1. <IN, TCP, 10.0.0.1, ANY, ANY, 22 23, ACCEPT>', "port value '22 23'"),
			('1. <IN, TCP, 129.110.96.1\t17, ANY, ANY, 22, ACCEPT>', "IPv4 value '129.110.96.1\\t17'"),
			('1. <IN, TCP, 10.0.0.1, ANY, ANY, 22, ACC EPT>', "action value 'ACC EPT'")]:
			with self.subTest(line=line):
				with self.assertRaises(ValueError) as error:
					self.parse(line)
				self.assertIn('Invalid %s on line 1' % bad_value, str(error.exception))

	def test_priority_must_be_ascii_digits(self):
		for priority in ['٥', '1_0', '+1', '-1']:
			with self.subTest(priority=priority):
				with self.assertRaises(ValueError) as error:
					self.parse('%s. <IN, TCP, ANY, ANY, ANY, 80, REJECT>' % priority)
				self.assertIn('Invalid priority on line 1', str(error.exception))


class InputValidationTests(unittest.TestCase):

	def test_values_that_do_not_parse_are_rejected(self):
		# Issue #3: these used to become ANY, TCP, IN or DENY without a warning.
		invalid = {
			'nw_src': ['129.110.96.300', '129.110.96.1l7', '2001:db8::1', '10.*.0.*',
				'', '10.0.0.1/33', '10.0.0.1/3200', '10.0.0.9-10.0.0.1', '10.0.0.9-1',
				'10.0.0.1-10.0.0.2-3', 'abc-5', '010.0.0.1',
				# Mask notation, signed or empty prefixes, and whitespace.
				'10.0.0.0/255.255.255.0', '10.0.0.1/0.0.0.0', '10.0.0.0/0.0.0.255',
				'10.0.0.1/-0', '10.0.0.1/+24', '10.0.0.0/', '10.0.0.0/24/8',
				'10.0.0.0/ 24', ' 10.0.0.1', '١٠.0.0.1'],
			'tp_dst': ['8O', '44E', '0x50', '', '-1', '1-', '70000', '1-70000', '80-20', '1-2-3',
				'22 23', ' 80', '٨٠', '８０'],
			'nw_proto': ['ANY', 'SCTP', '', 'ıcmp'],
			'direction': ['INBOUND', '', 'ın'],
			'actions': ['DROP', '', 'ACC EPT'],
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
			('nw_src', '10.0.0.0/24', '10.0.0.0/24'), ('nw_src', '10.0.0.0/024', '10.0.0.0/24'),
			('nw_src', '0.0.0.0/0', '0.0.0.0/0'),
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
				rule = Rule(**{field: value})
				self.assertEqual(getattr(rule, field), expected)
				# The stored value must also parse in the comparison code, which
				# used to crash on values like 10.0.0.1/-0 that passed validation.
				rule.disjoint(Rule())

	def test_cidr_must_use_the_network_address(self):
		# Host bits set outside the prefix usually mean a typo that widens the
		# rule, as ipaddress.ip_network(value, strict=True) also rejects.
		for value, expected in [('10.0.0.0/24', '10.0.0.0/24'), ('10.0.0.5/24', None),
			('129.110.96.117/2', None), ('10.0.0.1/32', '10.0.0.1'),
			('0.0.0.0/0', '0.0.0.0/0'), ('10.0.0.1/0', None)]:
			with self.subTest(value=value):
				if expected is None:
					with self.assertRaises(ValueError):
						Rule(nw_src=value)
				else:
					self.assertEqual(Rule(nw_src=value).nw_src, expected)

	def test_port_ranges_are_stored_in_canonical_form(self):
		# One spelling per range, since rules are also compared as text.
		for value, expected in [('5-5', '5'), ('65535-65535', '65535'), ('00-65535', '*'),
			('0-65535', '*'), ('0-65534', '0-65534'), ('080', '80'), ('0080-0090', '80-90')]:
			with self.subTest(value=value):
				self.assertEqual(Rule(tp_dst=value).tp_dst, expected)

	def test_keywords_are_stored_in_canonical_spelling(self):
		for field, value, expected in [('dl_type', 'arp', 'ARP'), ('dl_type', 'IPV6', 'IPv6'),
			('nw_proto', 'Tcp', 'TCP'), ('nw_proto', 'icmpv6', 'ICMPv6'),
			('direction', 'In', 'IN'), ('actions', 'Accept', 'ALLOW'), ('actions', 'Deny', 'DENY')]:
			with self.subTest(field=field, value=value):
				self.assertEqual(getattr(Rule(**{field: value}), field), expected)

	def test_unknown_field_is_rejected(self):
		with self.assertRaisesRegex(ValueError, "Unknown field 'ip'"):
			Rule._sanity_check('10.0.0.1', 'ip')


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


class ConflictResolutionTests(unittest.TestCase):
	# resolve_anomalies decides each packet from the original rules that match
	# it: a rule strictly inside another wins, and among rules that overlap
	# without nesting, DENY wins.

	def setUp(self):
		self.resolver = AnomalyResolver(log_level='CRITICAL')

	def tearDown(self):
		self.resolver.resolver_logger.handlers.clear()

	def decisions(self, rules, packets):
		resolved = self.resolver.resolve_anomalies(rules)
		return [first_match(resolved, Rule(nw_src=src, nw_dst=dst, tp_src='1', tp_dst=dport))
			for src, dst, dport in packets]

	def test_correlated_overlap_stays_denied(self):
		# Issue #4: a piece of the third rule was moved in front of the DENY
		# common part of the first two, so 10.0.1.100 became ALLOW.
		rules = [Rule(nw_src='10.0.0.0/24', nw_dst='10.0.1.0-10.0.1.127', tp_dst='*', actions='DENY'),
			Rule(nw_src='10.0.0.0/24', nw_dst='10.0.1.64-10.0.1.255', tp_dst='80', actions='ALLOW'),
			Rule(nw_src='10.0.0.5', nw_dst='10.0.1.0/24', tp_dst='80', actions='ALLOW')]
		self.assertEqual(self.decisions(rules, [('10.0.0.5', '10.0.1.10', '80'),
			('10.0.0.5', '10.0.1.100', '80')]), ['DENY', 'DENY'])

	def test_piece_inside_a_correlated_rule_is_denied(self):
		# The first rule's piece for 10.0.1.1 lies inside the third rule, but
		# the two original rules only overlap, so DENY wins there.
		rules = [Rule(nw_src='10.0.0.3-10.0.0.5', nw_dst='10.0.1.1-10.0.1.3', tp_dst='1-4', actions='ALLOW'),
			Rule(nw_src='10.0.0.0-10.0.0.7', nw_dst='10.0.1.2', tp_dst='1-4', actions='DENY'),
			Rule(nw_src='10.0.0.0-10.0.0.7', nw_dst='10.0.1.0-10.0.1.2', tp_dst='1-4', actions='DENY')]
		self.assertEqual(self.decisions(rules, [('10.0.0.3', '10.0.1.1', '1')]), ['DENY'])

	def test_piece_equal_to_a_more_specific_rule_keeps_its_action(self):
		# A piece of the first rule equals the third rule, but the third rule
		# lies strictly inside the first, so its ALLOW wins.
		rules = [Rule(nw_src='10.0.0.0-10.0.0.7', nw_dst='10.0.1.1', tp_dst='1-4', actions='DENY'),
			Rule(nw_src='10.0.0.4-10.0.0.6', nw_dst='10.0.1.0-10.0.1.3', tp_dst='1-2', actions='DENY'),
			Rule(nw_src='10.0.0.0-10.0.0.3', nw_dst='10.0.1.1', tp_dst='1-4', actions='ALLOW')]
		self.assertEqual(self.decisions(rules, [('10.0.0.0', '10.0.1.1', '1')]), ['ALLOW'])

	def test_unexpected_action_fails_closed(self):
		# Actions assigned directly skip validation. Only an explicit ALLOW
		# may allow; anything else must not open traffic.
		for actions in ['deny', 'allow', 'PERMIT']:
			with self.subTest(actions=actions):
				rule = Rule(nw_src='10.0.0.0-10.0.0.7', tp_dst='1-4', actions='ALLOW')
				rule.actions = actions
				resolved = self.resolver.resolve_anomalies([rule])
				self.assertEqual([piece.actions for piece in resolved], ['DENY'])
		deny = Rule(nw_src='10.0.0.0-10.0.0.7', tp_dst='1-4', actions='DENY')
		deny.actions = 'deny'
		allow = Rule(nw_src='10.0.0.0-10.0.0.7', tp_dst='1-4', actions='ALLOW')
		resolved = self.resolver.resolve_anomalies([deny, allow])
		self.assertEqual([piece.actions for piece in resolved], ['DENY'])

	def test_piece_outside_every_original_rule_raises(self):
		with self.assertRaisesRegex(RuntimeError, 'No original rule contains'):
			self.resolver.set_actions([Rule(nw_src='10.0.0.1')], [Rule(nw_src='10.0.0.2')])

	def test_input_rules_are_not_modified(self):
		policies = [
			[Rule(nw_src='10.0.0.0/24', nw_dst='10.0.1.0-10.0.1.127', tp_dst='*', actions='DENY'),
				Rule(nw_src='10.0.0.0/24', nw_dst='10.0.1.64-10.0.1.255', tp_dst='80', actions='ALLOW'),
				Rule(nw_src='10.0.0.5', nw_dst='10.0.1.0/24', tp_dst='80', actions='ALLOW')],
			[Rule(nw_src='10.0.0.0-10.0.0.7', nw_dst='10.0.1.1', tp_dst='1-4', actions='DENY'),
				Rule(nw_src='10.0.0.4-10.0.0.6', nw_dst='10.0.1.0-10.0.1.3', tp_dst='1-2', actions='DENY'),
				Rule(nw_src='10.0.0.0-10.0.0.3', nw_dst='10.0.1.1', tp_dst='1-4', actions='ALLOW')],
		]
		for rules in policies:
			before = [rule.__repr__('detail') for rule in rules]
			resolved = self.resolver.resolve_anomalies(rules)
			self.assertEqual([rule.__repr__('detail') for rule in rules], before)
			self.assertFalse(any(piece is rule for piece in resolved for rule in rules))

	def test_resolved_decisions_follow_the_policy_for_random_rules(self):
		# Every field that resolution can split on varies, including *
		# wildcards, and each resolved decision is checked against the policy
		# for every packet in a small space. The policy is computed from the
		# generated ranges with plain integers rather than Rule.issubset.
		generator = random.Random(4)
		ip_base = {'nw_src': int(Rule.ipstr2range('10.0.0.0')[0]),
			'nw_dst': int(Rule.ipstr2range('10.0.1.0')[0])}
		space = {'in_port': (1, 2), 'nw_src': (0, 4), 'nw_dst': (0, 2), 'tp_src': (1, 2), 'tp_dst': (1, 3)}
		keys = sorted(space)

		def random_field(key):
			low, high = space[key]
			if generator.random() < 0.1:
				if key in ip_base:
					return '*', (0, 2 ** 32 - 1)
				return '*', (0, 65535)
			if generator.random() < 0.5:
				first, last = low, high
			else:
				first = generator.randrange(low, high + 1)
				last = generator.randrange(first, high + 1)
			if key in ip_base:
				prefix = '10.0.0.' if key == 'nw_src' else '10.0.1.'
				return ('%s%d-%s%d' % (prefix, first, prefix, last),
					(ip_base[key] + first, ip_base[key] + last))
			return '%d-%d' % (first, last), (first, last)

		def random_rule():
			texts, fields = dict(), dict()
			for key in keys:
				texts[key], fields[key] = random_field(key)
			fields['direction'] = generator.choice(['IN', 'IN', 'IN', 'OUT'])
			fields['nw_proto'] = generator.choice(['TCP', 'TCP', 'UDP'])
			fields['actions'] = generator.choice(['ALLOW', 'DENY'])
			rule = Rule(direction=fields['direction'], nw_proto=fields['nw_proto'],
				actions=fields['actions'], **texts)
			return rule, fields

		def resolved_fields(rule):
			fields = {'direction': rule.direction, 'nw_proto': rule.nw_proto, 'actions': rule.actions}
			for key in keys:
				value = getattr(rule, key)
				if key in ip_base:
					addresses = Rule.ipstr2range(value)
					fields[key] = (int(addresses[0]), int(addresses[-1]))
				elif value == '*':
					fields[key] = (0, 65535)
				else:
					first, _, last = value.partition('-')
					fields[key] = (int(first), int(last or first))
			return fields

		def inside(inner, outer):
			return inner['direction'] == outer['direction'] and \
				inner['nw_proto'] == outer['nw_proto'] and all(
				outer[key][0] <= inner[key][0] and inner[key][1] <= outer[key][1] for key in keys)

		def expected(originals, matching):
			most_specific = [fields for fields in matching if not any(
				inside(other, fields) and not inside(fields, other) for other in matching)]
			if not most_specific:
				return None
			return 'DENY' if any(fields['actions'] == 'DENY' for fields in most_specific) else 'ALLOW'

		# One bit per rule: which rules match each value of each field.
		packet_values = {key: [ip_base.get(key, 0) + value for value in range(space[key][0] - 1, space[key][1] + 2)]
			for key in keys}
		packet_values['direction'] = ['IN', 'OUT']
		packet_values['nw_proto'] = ['TCP', 'UDP']

		def masks(rules):
			result = dict()
			for key, values in packet_values.items():
				result[key] = [sum(1 << index for index, fields in enumerate(rules)
					if (fields[key] == value if key in ('direction', 'nw_proto')
						else fields[key][0] <= value <= fields[key][1])) for value in values]
			return result

		for _ in range(60):
			pairs = [random_rule() for _ in range(generator.randrange(2, 7))]
			rules = [rule for rule, _ in pairs]
			originals = [fields for _, fields in pairs]
			before = [rule.__repr__('detail') for rule in rules]
			resolved = [resolved_fields(rule) for rule in self.resolver.resolve_anomalies(rules)]
			self.assertEqual([rule.__repr__('detail') for rule in rules], before)
			original_masks, resolved_masks, decisions = masks(originals), masks(resolved), dict()
			for indexes in itertools.product(*[range(len(packet_values[key])) for key in packet_values]):
				matching_originals, matching_resolved = -1, -1
				for key, index in zip(packet_values, indexes):
					matching_originals &= original_masks[key][index]
					matching_resolved &= resolved_masks[key][index]
				if matching_originals not in decisions:
					decisions[matching_originals] = expected(originals, [fields
						for bit, fields in enumerate(originals) if matching_originals >> bit & 1])
				first = (matching_resolved & -matching_resolved).bit_length() - 1
				got = resolved[first]['actions'] if matching_resolved else None
				if got != decisions[matching_originals]:
					self.fail('%s gives %s instead of %s for %s -> %s' % (
						dict((key, packet_values[key][index]) for key, index in zip(packet_values, indexes)),
						got, decisions[matching_originals], originals, resolved))


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
