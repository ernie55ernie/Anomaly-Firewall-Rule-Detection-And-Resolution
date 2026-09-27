import collections
import itertools
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import networkx as nx
from netaddr import IPRange, IPSet

import anomaly_resolver
from anomaly_resolver import AnomalyResolver, Rule, SimpleRuleParser


def first_match(rules, packet):
	for rule in rules:
		if packet.issubset(rule):
			return rule.actions
	return None


def address(number):
	return '.'.join(str(number >> shift & 255) for shift in (24, 16, 8, 0))


def random_bounds(generator, top):
	# The whole space, one value at either end, a range ending at the top or
	# starting at 0, a wide range, or a short one near either end.
	kind = generator.randrange(6)
	if kind == 0:
		return 0, top
	if kind == 1:
		return (generator.choice([0, top]),) * 2
	if kind == 2:
		return generator.randint(0, top), top
	if kind == 3:
		return 0, generator.randint(0, top)
	if kind == 4:
		return tuple(sorted(generator.randint(0, top) for _ in range(2)))
	low = generator.choice([0, top - 7])
	first = low + generator.randrange(8)
	return first, generator.randint(first, low + 7)


def related_bounds(generator, top, first, last):
	# A range touching the given one on either side, overlapping it, apart
	# from it on either side, or picked on its own.
	relation = generator.randrange(6)
	if relation == 0 and last < top:
		return last + 1, generator.choice([last + 1, top, generator.randint(last + 1, top)])
	if relation == 1 and first > 0:
		return generator.choice([0, first - 1, generator.randint(0, first - 1)]), first - 1
	if relation == 2:
		shared = generator.randint(first, last)
		return generator.randint(0, shared), generator.randint(shared, top)
	if relation == 3 and last + 2 <= top:
		start = generator.randint(last + 2, top)
		return start, generator.randint(start, top)
	if relation == 4 and first >= 2:
		end = generator.randint(0, first - 2)
		return generator.randint(0, end), end
	return random_bounds(generator, top)


def range_text(generator, bounds, top, spell, full):
	# '*' or the spelled-out full range for the whole space, one value, or a-b.
	first, last = bounds
	if bounds == (0, top):
		return generator.choice(['*', full])
	if first == last:
		return spell(first)
	return '%s-%s' % (spell(first), spell(last))


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

	def test_contiguous_handles_ranges_ending_at_the_last_address(self):
		# Issue #8: adding 1 to the IPAddress 255.255.255.255 raised IndexError,
		# so ANY and ranges ending there failed in one argument order or both.
		cases = [
			('*', '1.2.3.4', False),
			('*', '*', False),
			('255.255.255.255', '10.0.0.1', False),
			('129.110.97.0-255.255.255.255', '1.2.3.4', False),
			('0.0.0.0-127.255.255.255', '128.0.0.0-255.255.255.255', True),
			('10.0.0.0-10.0.0.255', '10.0.1.0-255.255.255.255', True),
			('255.255.255.254', '255.255.255.255', True),
			('0.0.0.0-255.255.255.254', '255.255.255.255', True),
			('0.0.0.0', '255.255.255.255', False),
		]
		for first, second, expected in cases:
			with self.subTest(first=first, second=second):
				self.assertIs(Rule.contiguous(first, second, attribute='nw_src'), expected)
				self.assertIs(Rule.contiguous(second, first, attribute='nw_src'), expected)
		self.assertEqual(Rule.combine_range('10.0.0.0-10.0.0.255', '10.0.1.0-255.255.255.255',
			attribute='nw_dst'), '10.0.0.0-255.255.255.255')

	def test_contiguous_handles_the_ends_of_the_port_space(self):
		# Issue #8's boundary for ports: '*', single values at 0 and 65535, and
		# ranges ending at 65535.
		cases = [
			('*', '0', False),
			('*', '65535', False),
			('*', '0-65535', False),
			('0', '65535', False),
			('0', '1', True),
			('65534', '65535', True),
			('0-65534', '65535', True),
			('1-65535', '0', True),
			('100-65535', '0-99', True),
			('100-65535', '0-100', False),
			('100-65535', '0-98', False),
		]
		for first, second, expected in cases:
			with self.subTest(first=first, second=second):
				self.assertIs(Rule.contiguous(first, second, attribute='tp_dst'), expected)
				self.assertIs(Rule.contiguous(second, first, attribute='tp_dst'), expected)

	def test_contiguous_rejects_malformed_port_ranges(self):
		# The values Rule() rejects since #3 raise ValueError here too, instead of
		# getting an answer. A reversed range such as '10-5' is not read as '5-10'.
		malformed = ['-80-', '10-5', '80-', '-80', '-', '', '80--90', '1-2-3', '65536',
			'70000', '1-70000', '65535-65536', '+80', ' 80', '80 ', '0x50', '1_000', '8O',
			'٨٠']
		generator = random.Random(8)
		for _ in range(50):
			high = generator.randrange(65535)
			malformed.append('%d-%d' % (generator.randint(high + 1, 65535), high))
			malformed.append(str(generator.randint(65536, 10 ** 6)))
		for value in malformed:
			with self.subTest(value=value):
				with self.assertRaises(ValueError):
					Rule(tp_dst=value)
				with self.assertRaises(ValueError):
					Rule.range_bounds('port', value)
				for other in ['*', '0', '65535', '81']:
					with self.assertRaises(ValueError):
						Rule.contiguous(value, other, attribute='tp_dst')
					with self.assertRaises(ValueError):
						Rule.contiguous(other, value, attribute='tp_dst')

	def test_contiguous_agrees_with_value_sets_in_both_orders(self):
		# The expected answer never compares bounds: two ranges are contiguous
		# when the sets of values they stand for are disjoint and their union has
		# no gap, that is, holds as many values as its span. Ports are expanded
		# into sets. Addresses go into netaddr IPSets, which store CIDR blocks, so
		# even the whole space stays small.
		generator = random.Random(8)

		def adjacent(values_1, values_2):
			union = values_1 | values_2
			if isinstance(union, IPSet):
				blocks = union.iter_cidrs()
				count, lowest, highest = union.size, int(blocks[0][0]), int(blocks[-1][-1])
			else:
				count, lowest, highest = len(union), min(union), max(union)
			return values_1.isdisjoint(values_2) and count == highest - lowest + 1

		spaces = [
			('nw_src', 2 ** 32 - 1, address, '0.0.0.0-255.255.255.255',
				lambda first, last: IPSet(IPRange(first, last))),
			('tp_dst', 65535, str, '0-65535', lambda first, last: set(range(first, last + 1))),
		]
		for attribute, top, spell, full, values in spaces:
			outcomes = collections.Counter()
			for _ in range(300):
				bounds_1 = random_bounds(generator, top)
				bounds_2 = related_bounds(generator, top, *bounds_1)
				expected = adjacent(values(*bounds_1), values(*bounds_2))
				outcomes[expected] += 1
				range_1, range_2 = [range_text(generator, bounds, top, spell, full)
					for bounds in [bounds_1, bounds_2]]
				with self.subTest(attribute=attribute, ranges=(range_1, range_2)):
					forward = Rule.contiguous(range_1, range_2, attribute=attribute)
					backward = Rule.contiguous(range_2, range_1, attribute=attribute)
					self.assertIs(forward, backward)
					self.assertIs(forward, expected)
			# Both answers come up often, so the test can't pass on only one.
			self.assertGreater(min(outcomes[True], outcomes[False]), 50, outcomes)

	def test_range_checks_agree_with_value_sets(self):
		# Issue #10: containment and disjointness compare bounds now, instead of
		# building a set of up to 65,536 ports for every check. The expected
		# answers still come from sets of values: Python sets of ports, and
		# netaddr IPSets of addresses. Some addresses are CIDR blocks, the form
		# Rule() stores networks in, so that blocks nest.
		generator = random.Random(10)

		def cidr_around(value):
			# The block holding value, with a random prefix length.
			prefix = generator.randint(0, 32)
			network = (value >> (32 - prefix)) << (32 - prefix)
			bounds = network, network + 2 ** (32 - prefix) - 1
			return bounds, '%s/%d' % (address(network), prefix)

		spaces = [
			('ip', Rule.ipinrange, Rule.ipdisjoint, 2 ** 32 - 1, address,
				'0.0.0.0-255.255.255.255', lambda first, last: IPSet(IPRange(first, last))),
			('port', Rule.portinrange, Rule.portdisjoint, 65535, str, '0-65535',
				lambda first, last: set(range(first, last + 1))),
		]
		for kind, inrange, disjoint, top, spell, full, values in spaces:
			outcomes = collections.Counter()
			for _ in range(300):
				if kind == 'ip' and generator.randrange(4) == 0:
					bounds_1, range_1 = cidr_around(generator.randint(0, top))
				else:
					bounds_1 = random_bounds(generator, top)
					range_1 = range_text(generator, bounds_1, top, spell, full)
				if kind == 'ip' and generator.randrange(3) == 0:
					bounds_2, range_2 = cidr_around(generator.randint(*bounds_1))
				else:
					bounds_2 = related_bounds(generator, top, *bounds_1)
					range_2 = range_text(generator, bounds_2, top, spell, full)
				values_1, values_2 = values(*bounds_1), values(*bounds_2)
				expected = {'first inside': values_1.issubset(values_2),
					'second inside': values_2.issubset(values_1),
					'disjoint': values_1.isdisjoint(values_2)}
				outcomes.update(key for key, value in expected.items() if value)
				with self.subTest(kind=kind, ranges=(range_1, range_2)):
					self.assertIs(inrange(range_1, range_2), expected['first inside'])
					self.assertIs(inrange(range_2, range_1), expected['second inside'])
					self.assertIs(disjoint(range_1, range_2), expected['disjoint'])
					self.assertIs(disjoint(range_2, range_1), expected['disjoint'])
			# Each answer comes up often both ways, so no check can pass on one.
			for key in ['first inside', 'second inside', 'disjoint']:
				self.assertTrue(30 < outcomes[key] < 270, (kind, outcomes))

	def test_address_checks_reject_ipv6(self):
		# Rule() accepts only IPv4 in nw_src and nw_dst, but a field assigned
		# directly still reaches these helpers. Bounds are bare integers, and
		# '::a00:1' is the number of 10.0.0.1, so comparing IPv6 as IPv4 gave
		# answers such as '::a00:1' being inside 10.0.0.0/24. They raise instead,
		# whichever operand is IPv6.
		ipv6 = ['::a00:1', '::5-::a', '::8-::f', '::ffff:10.0.0.1', '::/0']
		ipv4 = ['10.0.0.0/24', '10.0.0.1', '0.0.0.5-0.0.0.10', '*']
		for value in ipv6:
			with self.subTest(value=value):
				with self.assertRaises(ValueError):
					Rule(nw_src=value)
				with self.assertRaises(ValueError):
					Rule.range_bounds('ip', value)
				for other in ipv4 + ipv6:
					for check in [Rule.ipinrange, Rule.ipdisjoint]:
						with self.assertRaises(ValueError):
							check(value, other)
						with self.assertRaises(ValueError):
							check(other, value)


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

	def issue_5_rules(self, order):
		# For each source, a full tp_src range and two halves that merge into
		# it, listed in the given order.
		rules = list()
		for source, full_range in [('10.0.0.1', ('10.0.1.1', 'ALLOW')), ('10.0.0.2', ('10.0.1.3', 'DENY'))]:
			pieces = [('1-10',) + full_range, ('1-5', '10.0.1.2', 'ALLOW'), ('6-10', '10.0.1.2', 'ALLOW')]
			for ports, destination, action in [pieces[index] for index in order]:
				rules.append(Rule(nw_src=source, tp_src=ports, nw_dst=destination, tp_dst='80', actions=action))
		return rules

	ISSUE_5_MERGED = [
		['IN', 'TCP', '10.0.0.1', '1-10', '10.0.1.1', '80', 'ALLOW'],
		['IN', 'TCP', '10.0.0.1', '1-10', '10.0.1.2', '80', 'ALLOW'],
		['IN', 'TCP', '10.0.0.2', '1-10', '10.0.1.2', '80', 'ALLOW'],
		['IN', 'TCP', '10.0.0.2', '1-10', '10.0.1.3', '80', 'DENY'],
	]

	def test_rules_below_siblings_with_the_same_range_are_kept(self):
		# Issue #5: merging 1-5 and 6-10 left two 1-10 edges below each source,
		# the sources were then taken as equal, and the DENY rule was dropped.
		# With a half range listed first, merge() also used to raise KeyError
		# (#7), so every insertion order is checked.
		for order in itertools.permutations(range(3)):
			with self.subTest(order=order):
				self.assertEqual(self.merge(self.issue_5_rules(order)), self.ISSUE_5_MERGED)

	def port_rules(self, ports, actions=None):
		# Rules that differ only in their destination port and, if given, action.
		return [Rule(nw_src='1.1.1.1', tp_src='80', nw_dst='2.2.2.2', tp_dst=port, actions=action)
			for port, action in zip(ports, actions or ['ALLOW'] * len(ports))]

	def test_a_merge_at_a_node_with_three_children_does_not_raise(self):
		# Issue #7: the pairs at a node were listed once, so after 22 and 23
		# merged, the pair (23, 443) named a removed edge and raised KeyError.
		self.assertEqual([path[5] for path in self.merge(self.port_rules(['22', '23', '443']))],
			['22-23', '443'])

	def test_overlapping_ranges_merge_to_one_range_in_any_order(self):
		# Review of #25: joining only exactly contiguous pairs gave 1-10 and
		# 6-8, or 1-8 and 6-10, depending on the insertion order.
		for ports in itertools.permutations(['1-5', '6-10', '6-8']):
			with self.subTest(order=ports):
				self.assertEqual([path[5] for path in self.merge(self.port_rules(ports))], ['1-10'])

	def test_sibling_ranges_join_when_they_overlap_or_touch_and_lead_to_the_same_rules(self):
		cases = [
			('overlapping', ['1-6', '4-10'], None, ['1-10']),
			('touching', ['1-5', '6-10'], None, ['1-10']),
			('disjoint, a gap at 5', ['1-4', '6-10'], None, ['1-4', '6-10']),
			('overlapping, different rules', ['1-6', '4-10'], ['ALLOW', 'DENY'], ['1-6', '4-10']),
			('touching, different rules', ['1-5', '6-10'], ['ALLOW', 'DENY'], ['1-5', '6-10']),
		]
		for name, ports, actions, expected in cases:
			with self.subTest(name):
				self.assertEqual([path[5] for path in self.merge(self.port_rules(ports, actions))], expected)

	def test_duplicate_ranges_collapse_to_one_rule(self):
		# Two spellings of the same addresses, and a merged 1-10 next to an
		# existing 1-10, each leave exactly one rule.
		spellings = [Rule(nw_src=source, tp_dst='80', actions='ALLOW')
			for source in ['10.0.0.0/24', '10.0.0.0-10.0.0.255']]
		self.assertEqual(self.merge(spellings), [['IN', 'TCP', '10.0.0.0-10.0.0.255', '*', '*', '80', 'ALLOW']])
		self.assertEqual([path[5] for path in self.merge(self.port_rules(['1-10', '1-5', '6-10']))], ['1-10'])

	def test_sources_holding_the_same_rules_merge_whatever_their_order(self):
		# Each source's ranges now join into the same 1-10, so the sources
		# lead to the same rules and merge.
		rules = [Rule(nw_src='10.0.0.1', tp_src='80', nw_dst='2.2.2.2', tp_dst=port, actions='ALLOW')
			for port in ['1-5', '6-10', '6-8']]
		rules += [Rule(nw_src='10.0.0.2', tp_src='80', nw_dst='2.2.2.2', tp_dst=port, actions='ALLOW')
			for port in ['1-5', '6-8', '6-10']]
		self.assertEqual(self.merge(rules), [['IN', 'TCP', '10.0.0.1-10.0.0.2', '80', '2.2.2.2', '1-10', 'ALLOW']])

	def test_contiguous_ranges_merge_fully_in_any_order(self):
		# A widened range can become contiguous with a sibling that was already
		# compared, so merging repeats until nothing more merges.
		for ports in itertools.permutations(['100-110', '111-120', '121-130']):
			with self.subTest(order=ports):
				self.assertEqual([path[5] for path in self.merge(self.port_rules(ports))], ['100-130'])

	def hand_built_tree(self, subtrees):
		# A root edge for each node, and below it one (range, action) path per child.
		self.resolver.tree = nx.DiGraph()
		for node, children in subtrees.items():
			self.resolver.tree.add_edge('root', node, range=node)
			for index, (child_range, action) in enumerate(children):
				child = '%s.%d' % (node, index)
				self.resolver.tree.add_edge(node, child, range=child_range)
				self.resolver.tree.add_edge(child, child + '.leaf', range=action)

	def test_subtree_equal_rejects_the_issue_5_shape(self):
		# The last 1-10 child of a and b match, but their first ones differ.
		self.hand_built_tree({'a': [('1-10', 'ALLOW'), ('1-10', 'DENY')],
			'b': [('1-10', 'DENY'), ('1-10', 'DENY')]})
		self.assertFalse(self.resolver.subtree_equal(('root', 'a'), ('root', 'b')))

	def test_subtree_equal_ignores_the_order_children_were_added(self):
		self.hand_built_tree({'a': [('1-10', 'ALLOW'), ('1-10', 'DENY')],
			'c': [('1-10', 'DENY'), ('1-10', 'ALLOW')]})
		self.assertTrue(self.resolver.subtree_equal(('root', 'a'), ('root', 'c')))

	def test_subtree_equal_ignores_duplicate_copies_of_a_rule(self):
		# a and b hold the same two rules, a with two copies of the first and
		# b with two copies of the second.
		self.hand_built_tree({'a': [('1-5', 'ALLOW'), ('1-5', 'ALLOW'), ('6-10', 'DENY')],
			'b': [('1-5', 'ALLOW'), ('6-10', 'DENY'), ('6-10', 'DENY')]})
		self.assertTrue(self.resolver.subtree_equal(('root', 'a'), ('root', 'b')))

	def test_duplicate_copies_of_a_rule_do_not_block_a_merge(self):
		# Merging 1-5 and 6-10 below 10.0.0.1 leaves two copies of its 1-10
		# rule, while 10.0.0.2 holds that rule once. The sources still merge.
		rules = [Rule(nw_src='10.0.0.1', tp_src=ports, nw_dst='10.0.1.1', tp_dst='80', actions='ALLOW')
			for ports in ['1-10', '1-5', '6-10']]
		rules.append(Rule(nw_src='10.0.0.2', tp_src='1-10', nw_dst='10.0.1.1', tp_dst='80', actions='ALLOW'))
		self.assertEqual(self.merge(rules),
			[['IN', 'TCP', '10.0.0.1-10.0.0.2', '1-10', '10.0.1.1', '80', 'ALLOW']])

	# Contiguous sibling values and their merged range. The action edge is
	# four levels below the sources and one level below the ports.
	CONTIGUOUS_SIBLINGS = [('nw_src', ['10.0.0.1', '10.0.0.2'], '10.0.0.1-10.0.0.2'),
		('tp_dst', ['80', '81'], '80-81')]

	def sibling_rules(self, field, values, actions):
		# Rules that are identical apart from `field` and their action.
		base = {'nw_src': '10.0.0.1', 'tp_src': '1-10', 'nw_dst': '10.0.1.1', 'tp_dst': '80'}
		return [Rule(actions=action, **dict(base, **{field: value}))
			for value, action in zip(values, actions)]

	def test_contiguous_siblings_with_different_actions_do_not_merge(self):
		# The signature keeps each path's terminal action, so siblings whose
		# paths differ only in ALLOW and DENY stay separate.
		for field, values, _ in self.CONTIGUOUS_SIBLINGS:
			with self.subTest(field=field):
				paths = self.merge(self.sibling_rules(field, values, ['ALLOW', 'DENY']))
				index = ['direction', 'nw_proto', 'nw_src', 'tp_src', 'nw_dst', 'tp_dst'].index(field)
				self.assertEqual([(path[index], path[-1]) for path in paths],
					[(values[0], 'ALLOW'), (values[1], 'DENY')])

	def test_contiguous_siblings_with_the_same_action_merge(self):
		for field, values, merged in self.CONTIGUOUS_SIBLINGS:
			with self.subTest(field=field):
				paths = self.merge(self.sibling_rules(field, values, ['ALLOW', 'ALLOW']))
				expected = dict({'nw_src': '10.0.0.1', 'tp_dst': '80'}, **{field: merged})
				self.assertEqual(paths, [['IN', 'TCP', expected['nw_src'], '1-10', '10.0.1.1',
					expected['tp_dst'], 'ALLOW']])

	def test_merging_keeps_every_rule_in_random_variants_of_issue_5(self):
		# Each source gets a full tp_src range plus two halves that merge into
		# it, with random destinations and actions, listed in a random order.
		generator = random.Random(9)
		sources = ['10.0.0.1', '10.0.0.2']
		for _ in range(150):
			rules = list()
			for source in sources:
				pieces = [Rule(nw_src=source, tp_src='1-10', tp_dst='80',
					nw_dst='10.0.1.%d' % generator.randrange(1, 4),
					actions=generator.choice(['ALLOW', 'DENY']))]
				destination = '10.0.1.%d' % generator.randrange(1, 4)
				action = generator.choice(['ALLOW', 'DENY'])
				for ports in ['1-5', '6-10']:
					pieces.append(Rule(nw_src=source, tp_src=ports, tp_dst='80',
						nw_dst=destination, actions=action))
				generator.shuffle(pieces)
				rules.extend(pieces)
			expected = set((rule.nw_src, rule.nw_dst, rule.actions) for rule in rules)
			merged = set()
			for path in self.merge(rules):
				addresses = Rule.ipstr2range(path[2])
				for source in sources:
					if Rule.ipstr2range(source)[0] in addresses:
						merged.add((source, path[4], path[6]))
			self.assertEqual(merged, expected, '%s -> %s' % (rules, self.paths()))

	# Values drawn from aligned pieces so that merges are common, plus
	# overlapping ones such as 3 and 2-3 that made merging order-dependent.
	RANDOM_CHOICES = {'nw_src': ['10.0.0.0', '10.0.0.1', '10.0.0.0-10.0.0.1'],
		'tp_src': ['1-2', '3-4', '1-4', '3', '2-3'], 'nw_dst': ['10.0.1.0-10.0.1.1',
		'10.0.1.2-10.0.1.3', '10.0.1.0-10.0.1.3', '10.0.1.1-10.0.1.2'], 'tp_dst': ['1', '2', '1-2', '2-3']}
	RANDOM_ORDER = ['nw_src', 'tp_src', 'nw_dst', 'tp_dst']

	def random_rules(self, generator):
		rules = dict()
		for _ in range(generator.randrange(3, 10)):
			key = tuple(generator.choice(self.RANDOM_CHOICES[field]) for field in self.RANDOM_ORDER)
			rules.setdefault(key, generator.choice(['ALLOW', 'ALLOW', 'DENY']))
		return [Rule(actions=action, **dict(zip(self.RANDOM_ORDER, key))) for key, action in rules.items()]

	def test_merged_rules_do_not_depend_on_insertion_order(self):
		# The same rules give exactly the same merged rules, repeats included,
		# whatever order they were inserted in. Sorted lists, not sets, so a
		# different number of copies of a rule would fail too. Besides the
		# general random rules, rules with overlapping destination port ranges
		# exercise the case that merging only contiguous pairs got wrong.
		generator = random.Random(6)
		ports = ['1-5', '6-10', '6-8', '3-7', '11', '9-12']

		def overlapping_port_rules():
			return [Rule(nw_src=generator.choice(['10.0.0.1', '10.0.0.2']), tp_src='80',
				nw_dst=generator.choice(['2.2.2.2', '2.2.2.3']), tp_dst=port,
				actions=generator.choice(['ALLOW', 'ALLOW', 'DENY']))
				for port in generator.sample(ports, generator.randrange(2, 7))]

		for make_rules in [lambda: self.random_rules(generator), overlapping_port_rules]:
			for _ in range(100):
				rules = make_rules()
				shuffled = rules[:]
				generator.shuffle(shuffled)
				self.assertEqual(self.merge(rules), self.merge(shuffled))

	def test_merging_keeps_the_actions_every_packet_can_reach(self):
		# Every root-to-leaf path is a rule, so a merge must not change which
		# actions each packet can reach.
		generator = random.Random(5)
		order = self.RANDOM_ORDER

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
			self.resolver.construct_rule_tree(self.random_rules(generator), plot=False)
			before, paths_before = reachable(), len(self.paths())
			self.resolver.merge(self.resolver.get_rule_tree_root())
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

	def test_icmpv6_lines_are_ipv6_rules(self):
		# Issue #15: the file's addresses are IPv4, and ICMPv6 runs over IPv6,
		# so an ICMPv6 line was an IPv4 rule that matched nothing. Without
		# addresses, the protocol alone decides the family: the line is an
		# IPv6 rule. With an IPv4 address it can't match anything, and is
		# rejected with the conflict named.
		for line in ['1. <IN, ICMPv6, ANY, ANY, ANY, ANY, ACCEPT>', '1. <IN, icmpv6, any, *, *, ANY, ACCEPT>']:
			with self.subTest(line=line):
				rule = self.parse(line)[0]
				self.assertEqual((rule.dl_type, rule.nw_proto, rule.nw_src, rule.nw_dst, rule.actions),
					('IPv6', 'ICMPv6', '*', '*', 'ALLOW'))
		for line, direction in [('1. <IN, ICMPv6, 10.0.0.1, ANY, ANY, ANY, ACCEPT>', 'source'),
				('1. <IN, ICMPv6, ANY, ANY, 10.0.1.0/24, ANY, ACCEPT>', 'destination')]:
			with self.subTest(line=line):
				with self.assertRaises(ValueError) as error:
					self.parse(line, '2. <IN, TCP, 10.0.0.1, ANY, ANY, ANY, REJECT>')
				message = str(error.exception)
				self.assertIn('ICMPv6 rule', message)
				self.assertIn('IPv4 %s address' % direction, message)
				self.assertIn('on line 1', message)
		for line, expected in [('1. <IN, ICMP, 10.0.0.1, ANY, ANY, ANY, ACCEPT>', ('IPv4', 'ICMP', '10.0.0.1')),
				('1. <IN, TCP, 10.0.0.1, ANY, ANY, 80, REJECT>', ('IPv4', 'TCP', '10.0.0.1'))]:
			with self.subTest(line=line):
				rule = self.parse(line)[0]
				self.assertEqual((rule.dl_type, rule.nw_proto, rule.nw_src), expected)

	def test_address_free_icmpv6_rule_is_detected_and_resolved_as_ipv6(self):
		# The ICMPv6 rule matches IPv6 packets only, so it doesn't overlap the
		# IPv4 ICMP rule, but a later ICMPv6 rule shadows it.
		resolver = AnomalyResolver(log_level='CRITICAL')
		# Look the list up when cleaning up: assertLogs below puts a copy of it
		# back on the logger, so clearing the list seen now would leave the
		# handler, and a later resolver that reuses this id() would get two.
		self.addCleanup(lambda: resolver.resolver_logger.handlers.clear())
		icmpv6, icmp = self.parse('1. <IN, ICMPv6, ANY, ANY, ANY, ANY, ACCEPT>',
			'2. <IN, ICMP, ANY, ANY, ANY, ANY, REJECT>')
		self.assertTrue(icmpv6.disjoint(icmp))
		resolved = resolver.resolve_anomalies([icmpv6, icmp])
		self.assertEqual(first_match(resolved, Rule(dl_type='IPv6', nw_proto='ICMPv6')), 'ALLOW')
		self.assertEqual(first_match(resolved, Rule(nw_proto='ICMP', nw_src='10.0.0.1')), 'DENY')
		self.assertIsNone(first_match(resolved, Rule(nw_proto='TCP')))
		later_icmpv6 = self.parse('3. <IN, ICMPv6, ANY, ANY, ANY, ANY, REJECT>')[0]
		with self.assertLogs(resolver.resolver_logger, 'INFO') as logs:
			resolver.detect_anomalies([icmpv6, icmp, later_icmpv6])
		reports = [record.getMessage() for record in logs.records if 'Anomaly' in record.getMessage()]
		self.assertEqual(reports, ['Shadowing Anomaly\n\t%s\n\t%s' % (icmpv6, later_icmpv6)])

	def test_icmp_line_with_ports_is_rejected(self):
		# Issue #40: only TCP and UDP have ports.
		for line, parts in [('1. <IN, ICMP, 10.0.0.1, 80, ANY, 8080, ACCEPT>', ['ICMP rule', "tp_src '80'"]),
				('1. <IN, ICMPv6, ANY, ANY, ANY, 80, ACCEPT>', ['ICMPv6 rule', "tp_dst '80'"])]:
			with self.subTest(line=line):
				with self.assertRaises(ValueError) as error:
					self.parse(line)
				for part in parts + ["can't have ports", 'on line 1']:
					self.assertIn(part, str(error.exception))
		for line in ['1. <IN, ICMP, 10.0.0.1, ANY, ANY, ANY, ACCEPT>',
				'1. <IN, ICMP, 10.0.0.1, 0-65535, ANY, *, ACCEPT>']:
			with self.subTest(line=line):
				rule = self.parse(line)[0]
				self.assertEqual((rule.nw_proto, rule.tp_src, rule.tp_dst), ('ICMP', '*', '*'))

	def test_port_errors_quote_the_token_as_written(self):
		# The value is normalized to check it, but the error points back at
		# what the file says, so '080' can be found on its line.
		for line, token in [('1. <IN, ICMP, 10.0.0.1, 080, ANY, ANY, ACCEPT>', "tp_src '080'"),
				('1. <IN, ICMP, 10.0.0.1, ANY, ANY, 80-80, ACCEPT>', "tp_dst '80-80'")]:
			with self.subTest(line=line):
				with self.assertRaises(ValueError) as error:
					self.parse(line)
				self.assertIn("An ICMP rule can't have ports: %s on line 1" % token, str(error.exception))

	def test_any_protocol_is_rejected(self):
		# A rules-file rule is IPv4 or IPv6, and needs a protocol: ANY would
		# mean it has none, which only an ARP rule can.
		with self.assertRaises(ValueError) as error:
			self.parse('1. <IN, ANY, 10.0.0.1, ANY, ANY, ANY, ACCEPT>')
		self.assertIn("Invalid protocol value 'ANY'", str(error.exception))
		self.assertIn('on line 1', str(error.exception))

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
			'nw_proto': ['ANY', 'SCTP', '', 'ıcmp', None],
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
			('nw_proto', 'udp', 'UDP'), ('nw_proto', 'ICMP', 'ICMP'),
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
			('nw_proto', 'Tcp', 'TCP'), ('nw_proto', 'icmp', 'ICMP'),
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
		self.addCleanup(first.resolver_logger.handlers.clear)
		self.addCleanup(second.resolver_logger.handlers.clear)
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

	def test_directly_assigned_ipv6_is_not_rewritten_as_ipv4(self):
		# Splitting '::5-::a' against '::8-::f' through integer bounds gave
		# 0.0.0.5-0.0.0.7, 0.0.0.11-0.0.0.15 and 0.0.0.8-0.0.0.10: other hosts,
		# with no error. Resolution raises instead.
		deny = Rule(actions='DENY')
		deny.nw_src = '::5-::a'
		allow = Rule(actions='ALLOW')
		allow.nw_src = '::8-::f'
		with self.assertRaises(ValueError):
			self.resolver.resolve_anomalies([deny, allow])
		with self.assertRaises(ValueError):
			self.resolver.split(deny, allow, 'nw_src', [])
		self.assertEqual((deny.nw_src, allow.nw_src), ('::5-::a', '::8-::f'))


class SplitOrderTests(unittest.TestCase):

	def test_rules_are_split_in_a_fixed_order(self):
		rule = Rule(nw_src='10.0.0.1', tp_src='1', nw_dst='10.0.1.1', tp_dst='80')
		other = Rule(in_port='3', nw_src='10.0.0.2', tp_src='2', nw_dst='10.0.1.2', tp_dst='81')
		self.assertEqual(rule.find_attribute_set(other), ['tp_dst', 'nw_dst', 'tp_src', 'nw_src', 'in_port'])
		self.assertEqual(rule.find_attribute_set(Rule(nw_src='10.0.0.2', tp_src='1',
			nw_dst='10.0.1.1', tp_dst='81')), ['tp_dst', 'nw_src'])

	# The fields compared for each resolved rule, and the rules expected from
	# resolving the two rules in the test below. The DENY pieces make up the
	# first rule; the ALLOW pieces are the second rule minus the overlap
	# (sources .2-.5, destinations .2-.3, ports 2-4), which is DENY.
	FIELDS = ['direction', 'nw_proto', 'in_port', 'nw_src', 'tp_src', 'nw_dst', 'tp_dst', 'actions']
	EXPECTED = [
		['IN', 'TCP', '1', '10.0.0.0-10.0.0.7', '1', '10.0.1.0-10.0.1.3', '1', 'DENY'],
		['IN', 'TCP', '1', '10.0.0.2-10.0.0.5', '1', '10.0.1.2-10.0.1.6', '5-6', 'ALLOW'],
		['IN', 'TCP', '1', '10.0.0.0-10.0.0.7', '1', '10.0.1.0-10.0.1.1', '2-4', 'DENY'],
		['IN', 'TCP', '1', '10.0.0.2-10.0.0.5', '1', '10.0.1.4-10.0.1.6', '2-4', 'ALLOW'],
		['IN', 'TCP', '1', '10.0.0.0-10.0.0.1', '1', '10.0.1.2-10.0.1.3', '2-4', 'DENY'],
		['IN', 'TCP', '1', '10.0.0.6-10.0.0.7', '1', '10.0.1.2-10.0.1.3', '2-4', 'DENY'],
		['IN', 'TCP', '1', '10.0.0.2-10.0.0.5', '1', '10.0.1.2-10.0.1.3', '2-4', 'DENY'],
	]

	def test_every_hash_seed_gives_the_expected_rules(self):
		# Issue #6: the split order used to follow a set's iteration order,
		# which changes with PYTHONHASHSEED. These two rules differ in three
		# split attributes. On master, seeds 0, 1 and 3 each gave a different
		# result, and seed 4 gave the same result as seed 3. The seed is fixed
		# when Python starts, so each seed runs in its own process, and every
		# run must give exactly the expected rules.
		code = ("import json\n"
			"from anomaly_resolver import AnomalyResolver, Rule\n"
			"rules = [Rule(in_port='1', tp_src='1', nw_src='10.0.0.0-10.0.0.7',\n"
			"    nw_dst='10.0.1.0-10.0.1.3', tp_dst='1-4', actions='DENY'),\n"
			"  Rule(in_port='1', tp_src='1', nw_src='10.0.0.2-10.0.0.5',\n"
			"    nw_dst='10.0.1.2-10.0.1.6', tp_dst='2-6', actions='ALLOW')]\n"
			"resolved = AnomalyResolver(log_level='CRITICAL').resolve_anomalies(rules)\n"
			"print(json.dumps([[getattr(rule, field) for field in %r] for rule in resolved]))\n"
			% (self.FIELDS,))
		root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
		for seed in ['0', '1', '3', '4']:
			with self.subTest(seed=seed):
				environment = dict(os.environ, PYTHONHASHSEED=seed, PYTHONDONTWRITEBYTECODE='1')
				result = subprocess.run([sys.executable, '-c', code], cwd=root, env=environment,
					capture_output=True, text=True, timeout=60)
				self.assertEqual(result.returncode, 0, result.stderr)
				self.assertEqual(json.loads(result.stdout), self.EXPECTED)


class ReadmeTests(unittest.TestCase):

	def test_resolve_example_matches_the_resolved_rules(self):
		# The README shows the resolved rules for rules/example_rules_1 as the
		# exact output of --resolve, so it must change whenever that output does.
		root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
		with open(os.path.join(root, 'README.md'), encoding='utf-8') as handle:
			example = handle.read().split('After anomaly resolving')[1].split('```')[1]
		resolver = AnomalyResolver(log_level='CRITICAL')
		self.addCleanup(resolver.resolver_logger.handlers.clear)
		rules = SimpleRuleParser(os.path.join(root, 'rules', 'example_rules_1')).rules
		self.assertEqual([line.strip() for line in example.splitlines() if line.strip()],
			[str(rule) for rule in resolver.resolve_anomalies(rules)])


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

	def test_reversed_range_raises_when_its_field_is_compared(self):
		# Rule() rejects a reversed range, but assigning the field directly
		# still works. The range checks always raise ValueError for one, instead
		# of reading it as an empty range. A rule comparison raises only if it
		# gets to that field: issubset() and disjoint() stop at the first field
		# that decides, so against a rule on another subnet the reversed range is
		# never read, and the rule is kept as it is. A reversed address range
		# behaves the same way, raising netaddr's AddrFormatError.
		for check in [Rule.portinrange, Rule.portdisjoint]:
			with self.assertRaises(ValueError):
				check('80-20', '1-100')
			with self.assertRaises(ValueError):
				check('1-100', '80-20')
		reversed_range = Rule(nw_src='10.0.0.1', tp_dst='20-80', actions='DENY')
		reversed_range.tp_dst = '80-20'
		# The later rule's nw_src contains the first rule's, so tp_dst is compared.
		subnet = Rule(nw_src='10.0.0.0/24', tp_dst='1-100', actions='DENY')
		with self.assertRaises(ValueError):
			self.resolver.remove_redundant_rules([reversed_range, subnet])

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


class SwitchAndVlanTests(unittest.TestCase):
	# Issue #12: Ryu installs a rule for switch or vlan 'all' on every switch
	# and for every VLAN, so 'all' overlaps each specific value, and a rule
	# for one switch is the more specific. The expected decisions come from
	# the helpers below, which compare the generated values directly rather
	# than with Rule.issubset: a rule strictly inside another wins, and DENY
	# wins between rules that only overlap.

	def setUp(self):
		self.resolver = AnomalyResolver(log_level='CRITICAL')

	def tearDown(self):
		self.resolver.resolver_logger.handlers.clear()

	@staticmethod
	def fields(rule):
		return {'switch': rule.switch, 'vlan': rule.vlan, 'actions': rule.actions,
			'nw_src': Rule.range_bounds('ip', rule.nw_src),
			'tp_dst': Rule.range_bounds('port', rule.tp_dst)}

	@staticmethod
	def matches(rule_fields, packet):
		switch, vlan, source, port = packet
		return rule_fields['switch'] in ('all', switch) and rule_fields['vlan'] in ('all', vlan) and \
			rule_fields['nw_src'][0] <= source <= rule_fields['nw_src'][1] and \
			rule_fields['tp_dst'][0] <= port <= rule_fields['tp_dst'][1]

	@staticmethod
	def inside(inner, outer):
		return all(outer[key] in ('all', inner[key]) for key in ('switch', 'vlan')) and \
			all(outer[key][0] <= inner[key][0] and inner[key][1] <= outer[key][1]
				for key in ('nw_src', 'tp_dst'))

	def expected(self, originals, packet):
		matching = [rule_fields for rule_fields in originals if self.matches(rule_fields, packet)]
		most_specific = [rule_fields for rule_fields in matching if not any(
			self.inside(other, rule_fields) and not self.inside(rule_fields, other)
			for other in matching)]
		if not most_specific:
			return None
		return 'DENY' if any(rule_fields['actions'] == 'DENY'
			for rule_fields in most_specific) else 'ALLOW'

	def decision(self, resolved, packet):
		return next((rule_fields['actions'] for rule_fields in resolved
			if self.matches(rule_fields, packet)), None)

	def assertDecisionsFollowThePolicy(self, rules, resolved, packets):
		originals = [self.fields(rule) for rule in rules]
		resolved = [self.fields(rule) for rule in resolved]
		for packet in packets:
			self.assertEqual(self.decision(resolved, packet), self.expected(originals, packet),
				'%s for %s -> %s' % (packet, originals, resolved))

	def decisions(self, rules, packets):
		resolved = [self.fields(rule) for rule in self.resolver.resolve_anomalies(rules)]
		return dict((packet, self.decision(resolved, packet)) for packet in packets)

	def test_all_holds_every_switch_and_vlan(self):
		for field in ['switch', 'vlan']:
			with self.subTest(field=field):
				everywhere = Rule(**{field: 'all'})
				one, same, other = Rule(**{field: '1'}), Rule(**{field: '1'}), Rule(**{field: '2'})
				self.assertFalse(everywhere.disjoint(one))
				self.assertFalse(one.disjoint(everywhere))
				self.assertFalse(one.disjoint(same))
				self.assertTrue(one.disjoint(other))
				self.assertTrue(one.issubset(everywhere))
				self.assertFalse(everywhere.issubset(one))
				self.assertTrue(one.issubset(same))
				self.assertFalse(one.issubset(other))

	def test_issue_example(self):
		# The ALLOW for 'all' counted as disjoint from the switch 1 rules, so
		# the host DENY was removed as redundant and 10.0.0.1:80 became allowed
		# on switch 1. The rest of 10.0.0.0/24 on switch 1 is DENY too: the
		# catch-all for switch 1 and the /24 for 'all' are each more specific
		# in one field, so they only overlap, and DENY wins, as since #4.
		host = Rule.range_bounds('ip', '10.0.0.1')[0]
		rules = [Rule(switch='1', nw_src='10.0.0.1', tp_dst='80', actions='DENY'),
			Rule(switch='all', nw_src='10.0.0.0/24', tp_dst='80', actions='ALLOW'),
			Rule(switch='1', nw_src='*', tp_dst='80', actions='DENY')]
		packets = [(switch, 'all', host + offset, 80) for switch in ['1', '2'] for offset in [0, 1, 256]]
		self.assertEqual(list(self.decisions(rules, packets).values()),
			['DENY', 'DENY', 'DENY', 'ALLOW', 'ALLOW', None])

	def test_exception_for_one_switch_survives_the_same_rule_for_all(self):
		# The rules match the same packets, but the switch 1 rule is more
		# specific, so switch 1 allows 10.0.0.1 while other switches deny it.
		host = Rule.range_bounds('ip', '10.0.0.1')[0]
		for field in ['switch', 'vlan']:
			with self.subTest(field=field):
				rules = [Rule(nw_src='10.0.0.1', actions='DENY'),
					Rule(nw_src='10.0.0.1', actions='ALLOW', **{field: '1'})]
				packets = [('1', 'all', host, 80), ('2', 'all', host, 80)] if field == 'switch' \
					else [('all', '1', host, 80), ('all', '2', host, 80)]
				self.assertEqual(list(self.decisions(rules, packets).values()), ['ALLOW', 'DENY'])

	def test_detection_and_resolution_agree_across_switches(self):
		# Detection compares the rules as written. Resolution decides from
		# the same rules, so a host for switch 1 inside a subnet for 'all' is
		# nested for both, and a host for 'all' against a subnet for switch 1
		# is a correlation for both, resolved to DENY.
		host = Rule.range_bounds('ip', '10.0.0.1')[0]
		cases = [('1', 'all', 'Shadowing Anomaly', 'ALLOW'),
			('all', '1', 'Correlation Anomaly', 'DENY')]
		for host_switch, subnet_switch, anomaly, decision in cases:
			with self.subTest(host_switch=host_switch):
				rules = [Rule(switch=host_switch, nw_src='10.0.0.1', actions='ALLOW'),
					Rule(switch=subnet_switch, nw_src='10.0.0.0/24', actions='DENY')]
				with self.assertLogs(self.resolver.resolver_logger, 'INFO') as logs:
					self.resolver.detect_anomalies(rules)
				self.assertIn('%s\n\t%s\n\t%s' % (anomaly, rules[0], rules[1]),
					[record.getMessage() for record in logs.records])
				self.assertEqual(self.decisions(rules, [('1', 'all', host, 80)]),
					{('1', 'all', host, 80): decision})

	def test_correlated_overlap_across_switches_fails_closed(self):
		# Each rule is more specific in one field. Whichever one allows, the
		# packets both match are denied; each rule decides the rest alone.
		host = Rule.range_bounds('ip', '10.0.0.1')[0]
		packets = [('1', 'all', host, 80), ('1', 'all', host + 1, 80), ('2', 'all', host, 80)]
		for host_action, subnet_action in [('ALLOW', 'DENY'), ('DENY', 'ALLOW')]:
			with self.subTest(host_action=host_action):
				rules = [Rule(nw_src='10.0.0.1', actions=host_action),
					Rule(switch='1', nw_src='10.0.0.0/24', actions=subnet_action)]
				self.assertEqual(list(self.decisions(rules, packets).values()),
					['DENY', subnet_action, host_action])

	def test_scopes_list_specific_pairs_first(self):
		# Switch 1 with any VLAN has no rules of its own: they all apply to
		# ('all', 'all') as well, so that pair decides it.
		rules = [Rule(switch='2'), Rule(vlan='5'), Rule(switch='1', vlan='5')]
		self.assertEqual(AnomalyResolver.scopes(rules), [('1', '5', '*', '*'), ('2', '5', '*', '*'),
			('2', 'all', '*', '*'), ('all', '5', '*', '*'), ('all', 'all', '*', '*')])
		self.assertEqual(AnomalyResolver.scopes([Rule(), Rule()]), [('all', 'all', '*', '*')])

	def test_pairs_without_rules_of_their_own_are_not_made(self):
		# Every named switch was combined with every named VLAN, and each pair
		# got copies of the rules for 'all', so these four rules became 19.
		rules = [Rule(switch='1', vlan='5', nw_src='10.0.0.1', actions='DENY'),
			Rule(switch='2', vlan='6', nw_src='10.0.0.2', actions='ALLOW'),
			Rule(nw_src='10.0.0.0/24', actions='ALLOW'),
			Rule(nw_src='10.0.0.0/16', actions='DENY')]
		self.assertEqual(AnomalyResolver.scopes(rules),
			[('1', '5', '*', '*'), ('2', '6', '*', '*'), ('all', 'all', '*', '*')])
		resolved = self.resolver.resolve_anomalies(rules)
		self.assertEqual([(rule.switch, rule.vlan, rule.nw_src, rule.actions) for rule in resolved], [
			('1', '5', '10.0.0.1', 'DENY'), ('1', '5', '10.0.0.0/24', 'ALLOW'),
			('1', '5', '10.0.0.0/16', 'DENY'), ('2', '6', '10.0.0.0/24', 'ALLOW'),
			('2', '6', '10.0.0.0/16', 'DENY'), ('all', 'all', '10.0.0.0/24', 'ALLOW'),
			('all', 'all', '10.0.0.0/16', 'DENY')])
		base = Rule.range_bounds('ip', '10.0.0.0')[0]
		packets = itertools.product(['1', '2', '3'], ['5', '6', '7'],
			[base, base + 1, base + 2, base + 256, base + 65536], [80])
		self.assertDecisionsFollowThePolicy(rules, resolved, packets)

	def test_pair_with_rules_of_its_own_gets_the_rules_for_all(self):
		rules = [Rule(vlan='5', nw_src='10.0.0.1', actions='DENY'),
			Rule(nw_src='10.0.0.0/24', actions='ALLOW'),
			Rule(nw_src='10.0.0.0/16', actions='DENY')]
		self.assertEqual(AnomalyResolver.scopes(rules), [('all', '5', '*', '*'), ('all', 'all', '*', '*')])
		resolved = [(rule.vlan, rule.nw_src, rule.actions)
			for rule in self.resolver.resolve_anomalies(rules)]
		self.assertEqual(resolved[:3], [('5', '10.0.0.1', 'DENY'),
			('5', '10.0.0.0/24', 'ALLOW'), ('5', '10.0.0.0/16', 'DENY')])

	def test_none_sorts_before_named_switches_and_vlans(self):
		# None is kept as a value of its own, like any other ID: it just
		# sorts first, and the order doesn't depend on the order of the rules.
		for field in ['switch', 'vlan']:
			for named in [['1'], ['2', '1']]:
				with self.subTest(field=field, named=named):
					rules = [Rule(nw_src='10.0.0.%d' % index, **{field: value})
						for index, value in enumerate([None] + named)]
					order = [None] + sorted(named) + ['all']
					expected = [(value, 'all', '*', '*') if field == 'switch'
						else ('all', value, '*', '*') for value in order]
					for permutation in itertools.permutations(rules):
						self.assertEqual(AnomalyResolver.scopes(list(permutation)), expected)
					resolved = self.resolver.resolve_anomalies(rules)
					self.assertEqual(collections.Counter((getattr(rule, field), rule.nw_src)
						for rule in resolved), collections.Counter((getattr(rule, field), rule.nw_src)
						for rule in rules), 'each rule is kept with its own ' + field)

	def test_detection_reports_an_overlap_with_a_rule_for_all(self):
		host = Rule(switch='1', nw_src='10.0.0.1', tp_dst='80', actions='DENY')
		subnet = Rule(nw_src='10.0.0.0/24', tp_dst='80', actions='ALLOW')
		with self.assertLogs(self.resolver.resolver_logger, 'INFO') as logs:
			self.resolver.detect_anomalies([host, subnet])
		self.assertIn('Shadowing Anomaly\n\t%s\n\t%s' % (host, subnet),
			[record.getMessage() for record in logs.records])

	def test_redundancy_removal_compares_switches(self):
		# A rule for one switch inside a later rule for 'all' with the same
		# action is redundant, but not the other way around.
		host = Rule(switch='1', nw_src='10.0.0.1', actions='DENY')
		everyone = Rule(nw_src='*', actions='DENY')
		kept = self.resolver.remove_redundant_rules([host, everyone])
		self.assertEqual(len(kept), 1)
		self.assertIs(kept[0], everyone)
		host = Rule(nw_src='10.0.0.1', actions='DENY')
		everyone = Rule(switch='1', nw_src='*', actions='DENY')
		self.assertEqual(len(self.resolver.remove_redundant_rules([host, everyone])), 2)

	def test_copies_of_rules_for_all_are_removed_when_redundant(self):
		# Switch 1 is resolved with a copy of the subnet ALLOW for 'all'. The
		# rule for 'all' that follows makes that copy redundant.
		host = Rule(switch='1', nw_src='10.0.0.1', actions='DENY')
		subnet = Rule(nw_src='10.0.0.0/24', actions='ALLOW')
		resolved = self.resolver.resolve_anomalies([host, subnet])
		self.assertEqual([(rule.switch, rule.nw_src, rule.actions) for rule in resolved],
			[('1', '10.0.0.1', 'DENY'), ('all', '10.0.0.0/24', 'ALLOW')])

	def test_resolved_decisions_follow_the_policy_on_every_switch_and_vlan(self):
		# Rules for 'all' and for named switches and VLANs, checked for every
		# packet in a small space, on named and unnamed switches and VLANs.
		generator = random.Random(12)
		base = Rule.range_bounds('ip', '10.0.0.0')[0]

		def random_range(low, high):
			first = generator.randint(low, high)
			return first, generator.randint(first, high)

		def random_rule():
			source, port = random_range(0, 3), random_range(1, 3)
			return Rule(switch=generator.choice(['1', '2', 'all', 'all']),
				vlan=generator.choice(['5', '6', 'all', 'all']),
				nw_src='*' if generator.random() < 0.15 else '10.0.0.%d-10.0.0.%d' % source,
				tp_dst='*' if generator.random() < 0.15 else '%d-%d' % port,
				actions=generator.choice(['ALLOW', 'DENY']))

		packets = list(itertools.product(['1', '2', '3'], ['5', '6', '7'],
			[base + source for source in range(5)], range(5)))
		mixed = 0
		for _ in range(150):
			rules = [random_rule() for _ in range(generator.randrange(2, 7))]
			before = [rule.__repr__('detail') for rule in rules]
			resolved = self.resolver.resolve_anomalies(rules)
			self.assertEqual([rule.__repr__('detail') for rule in rules], before)
			self.assertDecisionsFollowThePolicy(rules, resolved, packets)
			originals = [self.fields(rule) for rule in rules]
			mixed += sum(len(set(rule_fields['switch'] == 'all' for rule_fields in originals
				if self.matches(rule_fields, packet))) == 2 for packet in packets)
		# Rules for 'all' and for one switch often match the same packet.
		self.assertGreater(mixed, 500)


class LinkLayerAndIpv6Tests(unittest.TestCase):
	# Issue #13: dl_type, dl_src, dl_dst, ipv6_src and ipv6_dst were ignored,
	# so rules for different Ethernet types, MAC addresses or IPv6 networks
	# counted as matching the same packets.

	def setUp(self):
		self.resolver = AnomalyResolver(log_level='CRITICAL')

	def tearDown(self):
		self.resolver.resolver_logger.handlers.clear()

	def test_issue_example(self):
		ipv4 = Rule(dl_type='IPv4', nw_src='10.0.0.1', tp_dst='80', actions='ALLOW')
		arp = Rule(dl_type='ARP', actions='ALLOW')
		self.assertFalse(ipv4.issubset(arp))
		self.assertTrue(ipv4.disjoint(arp))
		mac_a = Rule(dl_src='aa:aa:aa:aa:aa:aa', actions='ALLOW')
		mac_b = Rule(dl_src='bb:bb:bb:bb:bb:bb', actions='DENY')
		self.assertFalse(mac_a.issubset(mac_b))
		self.assertTrue(mac_a.disjoint(mac_b))
		# The IPv4 ALLOW was removed as redundant with the ARP ALLOW.
		resolved = self.resolver.resolve_anomalies([ipv4, arp])
		self.assertEqual([(rule.dl_type, rule.nw_src, rule.tp_dst, rule.actions) for rule in resolved],
			[('IPv4', '10.0.0.1', '80', 'ALLOW'), ('ARP', '*', '*', 'ALLOW')])

	def test_ethernet_types_are_equal_or_disjoint(self):
		for first, second in itertools.product(['ARP', 'IPv4', 'IPv6'], repeat=2):
			with self.subTest(first=first, second=second):
				one, other = Rule(dl_type=first), Rule(dl_type=second)
				self.assertIs(one.disjoint(other), first != second)
				self.assertIs(one.issubset(other), first == second)

	def test_any_mac_address_holds_every_address(self):
		for field in ['dl_src', 'dl_dst']:
			with self.subTest(field=field):
				everyone = Rule(**{field: '*'})
				one = Rule(**{field: 'aa:aa:aa:aa:aa:aa'})
				same = Rule(**{field: 'AA:AA:AA:AA:AA:AA'})
				other = Rule(**{field: 'bb:bb:bb:bb:bb:bb'})
				self.assertTrue(one.issubset(everyone))
				self.assertFalse(everyone.issubset(one))
				self.assertFalse(everyone.disjoint(one))
				self.assertTrue(one.issubset(same))
				self.assertTrue(one.disjoint(other))
				self.assertFalse(one.issubset(other))

	def test_ipv6_ranges_nest_and_overlap(self):
		for field in ['ipv6_src', 'ipv6_dst']:
			with self.subTest(field=field):
				def rule(value):
					return Rule(dl_type='IPv6', **{field: value})
				network, host = rule('2001:db8::/32'), rule('2001:db8::1')
				subnet, other = rule('2001:db8:1::/48'), rule('2001:db9::/32')
				across = rule('2001:db8:ffff:ffff:ffff:ffff:ffff:fff0-2001:db9::f')
				self.assertTrue(host.issubset(network))
				self.assertTrue(subnet.issubset(network))
				self.assertFalse(network.issubset(subnet))
				self.assertTrue(network.disjoint(other))
				self.assertTrue(host.disjoint(subnet))
				self.assertFalse(across.disjoint(network))
				self.assertFalse(across.disjoint(other))
				self.assertFalse(across.issubset(network))
				self.assertTrue(network.issubset(rule('*')))

	def test_mac_and_ipv6_values_are_checked_and_normalized(self):
		for field, value, expected in [('dl_src', 'ANY', '*'),
				('dl_src', 'AA:BB:CC:DD:EE:FF', 'aa:bb:cc:dd:ee:ff'),
				('dl_dst', 'aa:bb:cc:dd:ee:ff', 'aa:bb:cc:dd:ee:ff'),
				('ipv6_src', 'any', '*'), ('ipv6_src', '2001:DB8:0::0001', '2001:db8::1'),
				('ipv6_src', '2001:db8::/32', '2001:db8::/32'), ('ipv6_src', '2001:db8::1/128', '2001:db8::1'),
				('ipv6_dst', '2001:db8::1-2001:db8::9', '2001:db8::1-2001:db8::9'),
				('ipv6_dst', '2001:db8::5-2001:db8::5', '2001:db8::5')]:
			with self.subTest(field=field, value=value):
				dl_type = 'IPv6' if field.startswith('ipv6') else 'IPv4'
				self.assertEqual(getattr(Rule(dl_type=dl_type, **{field: value}), field), expected)
		for field, value in [('dl_src', 'aa:bb:cc:dd:ee'), ('dl_src', 'aa-bb-cc-dd-ee-ff'),
				('dl_src', 'aabb.ccdd.eeff'), ('dl_src', 'gg:bb:cc:dd:ee:ff'), ('dl_dst', 'a:bb:cc:dd:ee:ff'),
				('dl_dst', ' aa:bb:cc:dd:ee:ff'), ('dl_dst', ''), ('dl_dst', None),
				('ipv6_src', '10.0.0.1'), ('ipv6_src', '2001:db8::1/32'), ('ipv6_src', '2001:db8::/129'),
				('ipv6_src', '2001:db8::9-2001:db8::1'), ('ipv6_src', '2001:db8::1-'),
				('ipv6_dst', 'fe80::1%eth0'), ('ipv6_dst', '2001:db8::g'), ('ipv6_dst', '1')]:
			with self.subTest(field=field, value=value):
				with self.assertRaises(ValueError):
					Rule(dl_type='IPv6' if field.startswith('ipv6') else 'IPv4', **{field: value})

	def test_ipv6_ranges_are_split_as_ipv6(self):
		# The pieces of a split must stay IPv6: bounds are integers, and a small
		# address such as ::5 would otherwise be written as 0.0.0.5.
		rules = [Rule(dl_type='IPv6', ipv6_src='::/120', tp_dst='80-90', actions='DENY'),
			Rule(dl_type='IPv6', ipv6_src='::5-::a', tp_dst='85-100', actions='ALLOW')]
		resolved = self.resolver.resolve_anomalies(rules)
		self.assertEqual(sorted((rule.ipv6_src, rule.tp_dst, rule.actions) for rule in resolved), [
			('::-::4', '85-90', 'DENY'), ('::/120', '80-84', 'DENY'), ('::5-::a', '85-90', 'DENY'),
			('::5-::a', '91-100', 'ALLOW'), ('::b-::ff', '85-90', 'DENY')])

	def test_address_family_must_match_dl_type(self):
		# IPv4 addresses match only IPv4 packets, and IPv6 addresses only IPv6
		# ones, so any other combination could match nothing. dl_type defaults
		# to IPv4.
		rejected = [(dict(ipv6_src='2001:db8::1'), 'ipv6_src .* needs dl_type IPv6, not IPv4'),
			(dict(ipv6_dst='2001:db8::/32'), 'ipv6_dst .* needs dl_type IPv6, not IPv4'),
			(dict(dl_type='IPv4', ipv6_src='2001:db8::1'), 'ipv6_src .* needs dl_type IPv6, not IPv4'),
			(dict(dl_type='IPv4', ipv6_dst='2001:db8::1'), 'ipv6_dst .* needs dl_type IPv6, not IPv4'),
			(dict(dl_type='IPv6', nw_src='10.0.0.1'), 'nw_src .* needs dl_type IPv4, not IPv6'),
			(dict(dl_type='IPv6', nw_dst='10.0.0.0/24'), 'nw_dst .* needs dl_type IPv4, not IPv6'),
			(dict(dl_type='ARP', nw_src='10.0.0.1'), 'nw_src .* needs dl_type IPv4, not ARP'),
			(dict(dl_type='ARP', ipv6_dst='2001:db8::1'), 'ipv6_dst .* needs dl_type IPv6, not ARP')]
		for fields, message in rejected:
			with self.subTest(fields=fields):
				with self.assertRaisesRegex(ValueError, message):
					Rule(**fields)
		accepted = [dict(nw_src='10.0.0.1', nw_dst='10.0.1.0/24'),
			dict(dl_type='IPv4', nw_src='10.0.0.1', nw_dst='10.0.1.1'),
			dict(dl_type='IPv6', ipv6_src='2001:db8::1', ipv6_dst='2001:db8::/32'),
			dict(dl_type='IPv6'), dict(dl_type='ARP')]
		for fields in accepted:
			with self.subTest(fields=fields):
				rule = Rule(**fields)
				self.assertEqual(dict((field, getattr(rule, field)) for field in fields), fields)

	def test_icmp_version_must_match_dl_type(self):
		# ICMP runs over IPv4 and ICMPv6 over IPv6, so any other combination
		# matches nothing. TCP and UDP run over both.
		for fields, message in [(dict(nw_proto='ICMPv6'), 'ICMPv6 needs dl_type IPv6, not IPv4'),
				(dict(dl_type='IPv4', nw_proto='ICMPv6'), 'ICMPv6 needs dl_type IPv6, not IPv4'),
				(dict(dl_type='IPv6', nw_proto='ICMP'), 'ICMP needs dl_type IPv4, not IPv6'),
				(dict(dl_type='ARP', nw_proto='ICMP'), 'ICMP needs dl_type IPv4, not ARP'),
				(dict(dl_type='ARP', nw_proto='ICMPv6'), 'ICMPv6 needs dl_type IPv6, not ARP')]:
			with self.subTest(fields=fields):
				with self.assertRaisesRegex(ValueError, message):
					Rule(**fields)
		for fields, expected in [(dict(dl_type='IPv6', nw_proto='icmpv6'), 'ICMPv6'),
				(dict(nw_proto='icmp'), 'ICMP'), (dict(dl_type='IPv4', nw_proto='ICMP'), 'ICMP'),
				(dict(dl_type='IPv6', nw_proto='UDP'), 'UDP'), (dict(dl_type='IPv6', nw_proto='TCP'), 'TCP')]:
			with self.subTest(fields=fields):
				self.assertEqual(Rule(**fields).nw_proto, expected)

	def test_conflicting_families_are_named_whatever_the_dl_type(self):
		# ICMPv6 with an IPv4 address, or IPv4 with IPv6 addresses, fits no
		# dl_type. The error names the conflict, the same for every dl_type,
		# rather than suggesting a dl_type that another check then rejects.
		for fields, parts in [(dict(nw_proto='ICMPv6', nw_src='10.0.0.1'), ['ICMPv6 rule', 'IPv4 source']),
				(dict(nw_proto='ICMPv6', nw_dst='10.0.0.0/24'), ['ICMPv6 rule', 'IPv4 destination']),
				(dict(nw_proto='ICMP', ipv6_src='2001:db8::1'), ['ICMP rule', 'IPv6 source']),
				(dict(nw_src='10.0.0.1', ipv6_dst='2001:db8::1'), ['both IPv4 and IPv6'])]:
			messages = set()
			for dl_type in ['IPv4', 'IPv6', 'ARP']:
				with self.subTest(fields=fields, dl_type=dl_type):
					with self.assertRaises(ValueError) as error:
						Rule(dl_type=dl_type, **fields)
					messages.add(str(error.exception))
			self.assertEqual(len(messages), 1, messages)
			message = messages.pop()
			self.assertNotIn('dl_type', message)
			for part in parts:
				self.assertIn(part, message)

	def test_rules_with_the_wrong_address_family_cannot_be_built(self):
		# An IPv6 source on the default IPv4 rule counted as disjoint from the
		# same source on an IPv6 rule, and as inside the IPv4 rule for every
		# packet. Such a rule is now rejected, and written with dl_type IPv6
		# it compares as expected.
		with self.assertRaises(ValueError):
			Rule(ipv6_src='2001:db8::1', actions='DENY')
		with self.assertRaises(ValueError):
			Rule(dl_type='IPv6', nw_src='10.0.0.1')
		host = Rule(dl_type='IPv6', ipv6_src='2001:db8::1', actions='DENY')
		network = Rule(dl_type='IPv6', ipv6_src='2001:db8::/32', actions='DENY')
		self.assertTrue(host.issubset(network))
		self.assertFalse(host.disjoint(network))
		self.assertFalse(host.issubset(Rule()))
		self.assertTrue(host.disjoint(Rule()))

	def test_range_helpers_handle_ipv6(self):
		# IPv6 ranges have their own path, with 128-bit bounds, rather than
		# being read as ports or as IPv4.
		self.assertEqual(Rule.range_bounds('ipv6', '::5'), (5, 5))
		self.assertEqual(Rule.range_bounds('ipv6', '::/126'), (0, 3))
		self.assertEqual(Rule.range_bounds('ipv6', '::5-::a'), (5, 10))
		self.assertEqual(Rule.range_bounds('ipv6', '*'), (0, 2 ** 128 - 1))
		for value in ['::5', '::5-::a', '2001:db8::/32', '2001:db8::1', '*']:
			with self.subTest(value=value):
				bounds = Rule.range_bounds('ipv6', value)
				self.assertEqual(Rule.range_bounds('ipv6', Rule.bounds_range('ipv6', *bounds)), bounds)
		self.assertEqual(Rule.bounds_range('ipv6', 5, 10), '::5-::a')
		self.assertEqual(Rule.bounds_range('ip', 5, 10), '0.0.0.5-0.0.0.10')
		self.assertEqual(Rule.bounds_range('port', 5, 10), '5-10')
		for attribute, first, second, kind in [('ipv6_src', '::1', '*', 'ipv6'),
				('ipv6_dst', '*', '*', 'ipv6'), (None, '::1', '::2', 'ipv6'),
				(None, '::ffff:1.2.3.4', '*', 'ipv6'), (None, '10.0.0.1', '*', 'ip'),
				('nw_src', '*', '*', 'ip'), (None, '80', '81-90', 'port'), ('tp_dst', '*', '*', 'port')]:
			with self.subTest(attribute=attribute, first=first, second=second):
				self.assertEqual(Rule._range_type(attribute, first, second), kind)
		top = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
		for first, second, expected in [('::1-::4', '::5-::8', True), ('::1', '::2', True),
				('::1', '::3', False), ('::1-::5', '::5-::8', False), ('*', '::5-::a', False),
				('2001:db8::/33', '2001:db8:8000::/33', True), (top, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe', True),
				('*', top, False), ('*', '*', False)]:
			for attribute in ['ipv6_src', None]:
				with self.subTest(first=first, second=second, attribute=attribute):
					self.assertIs(Rule.contiguous(first, second, attribute=attribute), expected)
					self.assertIs(Rule.contiguous(second, first, attribute=attribute), expected)
		self.assertEqual(Rule.combine_range('::1-::4', '::5-::8', attribute='ipv6_dst'), '::1-::8')
		with self.assertRaises(ValueError):
			Rule.contiguous('10.0.0.1', '::1', attribute='ipv6_src')

	def test_detection_and_resolution_agree_on_ipv6_ranges(self):
		# A host inside a /32 is shadowing for detection and keeps the host's
		# action; a host for every port against the /32 for one port is a
		# correlation for both, resolved to DENY where they meet.
		cases = [('*', '*', 'Shadowing Anomaly', 'ALLOW'), ('*', '80', 'Correlation Anomaly', 'DENY')]
		for host_port, network_port, anomaly, decision in cases:
			with self.subTest(network_port=network_port):
				rules = [Rule(dl_type='IPv6', ipv6_src='2001:db8::1', tp_dst=host_port, actions='ALLOW'),
					Rule(dl_type='IPv6', ipv6_src='2001:db8::/32', tp_dst=network_port, actions='DENY')]
				with self.assertLogs(self.resolver.resolver_logger, 'INFO') as logs:
					self.resolver.detect_anomalies(rules)
				self.assertIn('%s\n\t%s\n\t%s' % (anomaly, rules[0], rules[1]),
					[record.getMessage() for record in logs.records])
				resolved = self.resolver.resolve_anomalies(rules)
				packet = Rule(dl_type='IPv6', ipv6_src='2001:db8::1', tp_dst='80')
				self.assertEqual(first_match(resolved, packet), decision)

	def test_resolved_decisions_follow_the_policy(self):
		# Random rules over Ethernet types, MAC addresses, IPv6 ranges and
		# ports, and every packet in a small space checked against the policy:
		# a rule strictly inside another wins, and DENY wins between rules that
		# only overlap. Matching is computed from the generated values, not
		# with Rule.issubset.
		generator = random.Random(13)
		macs = {'dl_src': ['aa:aa:aa:aa:aa:aa', 'bb:bb:bb:bb:bb:bb', 'cc:cc:cc:cc:cc:cc'],
			'dl_dst': ['dd:dd:dd:dd:dd:dd', 'ee:ee:ee:ee:ee:ee']}

		def random_range(low, high):
			first = generator.randint(low, high)
			return first, generator.randint(first, high)

		def random_rule():
			# IPv6 addresses and ports only on IPv6 rules: an ARP rule can't
			# have either. Every value is still drawn, in the order it always
			# was, and dropped for ARP rules: a draw skipped or moved would
			# shift every later one, so Random(13) would stop producing the
			# policies this test was checked with.
			source, port = random_range(0, 4), random_range(1, 3)
			dl_type = generator.choice(['IPv6', 'IPv6', 'ARP'])
			ipv6_src = generator.choice(['*', '::/126', '::4-::7']) if generator.random() < 0.3 \
				else '::%x-::%x' % source
			dl_src = generator.choice(macs['dl_src'][:2] + ['*', '*'])
			dl_dst = generator.choice(macs['dl_dst'][:1] + ['*', '*'])
			tp_dst = '*' if generator.random() < 0.15 else '%d-%d' % port
			return Rule(dl_type=dl_type, dl_src=dl_src, dl_dst=dl_dst,
				ipv6_src=ipv6_src if dl_type == 'IPv6' else '*',
				tp_dst=tp_dst if dl_type == 'IPv6' else '*',
				actions=generator.choice(['ALLOW', 'DENY']))

		def fields(rule):
			return {'dl_type': rule.dl_type, 'dl_src': rule.dl_src, 'dl_dst': rule.dl_dst,
				'ipv6_src': Rule.range_bounds('ipv6', rule.ipv6_src),
				'tp_dst': Rule.range_bounds('port', rule.tp_dst), 'actions': rule.actions}

		def matches(rule_fields, packet):
			return all(rule_fields[key] in ('*', packet[key]) for key in ('dl_src', 'dl_dst')) and \
				rule_fields['dl_type'] == packet['dl_type'] and all(
				rule_fields[key][0] <= packet[key] <= rule_fields[key][1] for key in ('ipv6_src', 'tp_dst'))

		def inside(inner, outer):
			return all(outer[key] in ('*', inner[key]) for key in ('dl_src', 'dl_dst')) and \
				inner['dl_type'] == outer['dl_type'] and all(outer[key][0] <= inner[key][0] and
				inner[key][1] <= outer[key][1] for key in ('ipv6_src', 'tp_dst'))

		def expected(matching):
			most_specific = [rule_fields for rule_fields in matching if not any(
				inside(other, rule_fields) and not inside(rule_fields, other) for other in matching)]
			if not most_specific:
				return None
			return 'DENY' if any(rule_fields['actions'] == 'DENY'
				for rule_fields in most_specific) else 'ALLOW'

		keys = ('dl_type', 'dl_src', 'dl_dst', 'ipv6_src', 'tp_dst')
		packets = [dict(zip(keys, values)) for values in itertools.product(['IPv6', 'ARP'],
			macs['dl_src'], macs['dl_dst'], range(9), range(5))]
		outcomes = collections.Counter()
		for _ in range(120):
			rules = [random_rule() for _ in range(generator.randrange(2, 7))]
			before = [rule.__repr__('detail') for rule in rules]
			originals = [fields(rule) for rule in rules]
			resolved_rules = self.resolver.resolve_anomalies(rules)
			resolved = [fields(rule) for rule in resolved_rules]
			self.assertEqual([rule.__repr__('detail') for rule in rules], before)
			outcomes['ipv6 split'] += any(rule.ipv6_src not in set(original.ipv6_src
				for original in rules) for rule in resolved_rules)
			for packet in packets:
				matching = [rule_fields for rule_fields in originals if matches(rule_fields, packet)]
				outcomes['mixed macs'] += len(set(rule_fields['dl_src'] == '*'
					for rule_fields in matching)) == 2
				got = next((rule_fields['actions'] for rule_fields in resolved
					if matches(rule_fields, packet)), None)
				if got != expected(matching):
					self.fail('%s gives %s instead of %s for %s -> %s' % (
						packet, got, expected(matching), originals, resolved))
		# IPv6 ranges are often split, and rules for one MAC address and for
		# every address often match the same packet.
		self.assertGreater(outcomes['ipv6 split'], 20, outcomes)
		self.assertGreater(outcomes['mixed macs'], 200, outcomes)


class ArpTests(unittest.TestCase):
	# Issue #36: ARP packets carry no IP protocol and no ports, but every rule
	# had nw_proto TCP and ports, so ARP rules that differ only in those
	# counted as disjoint, although both match every ARP packet.

	def setUp(self):
		self.resolver = AnomalyResolver(log_level='CRITICAL')

	def tearDown(self):
		self.resolver.resolver_logger.handlers.clear()

	def test_arp_rules_have_no_protocol_or_ports(self):
		rule = Rule(dl_type='ARP', actions='ALLOW')
		self.assertEqual((rule.nw_proto, rule.tp_src, rule.tp_dst), ('*', '*', '*'))
		self.assertEqual(str(rule), '<IN, *, *, *, *, *, ALLOW>')
		for value in ['*', 'ANY', 'any']:
			with self.subTest(nw_proto=value):
				self.assertEqual(Rule(dl_type='ARP', nw_proto=value).nw_proto, '*')
		# Ports that don't constrain the rule are accepted too.
		rule = Rule(dl_type='ARP', tp_src='0-65535', tp_dst='ANY')
		self.assertEqual((rule.tp_src, rule.tp_dst), ('*', '*'))
		# Other rules keep TCP as the default, and '*' is still not a protocol.
		self.assertEqual(Rule().nw_proto, 'TCP')
		self.assertEqual(Rule(dl_type='IPv6').nw_proto, 'TCP')
		for dl_type in ['IPv4', 'IPv6']:
			with self.subTest(dl_type=dl_type):
				with self.assertRaisesRegex(ValueError, "Invalid protocol value '\\*': only an ARP rule"):
					Rule(dl_type=dl_type, nw_proto='*')

	def test_explicit_missing_protocol_is_rejected(self):
		# nw_proto=None is a missing value, not the default: a rule built from
		# data without a protocol must fail rather than become a TCP rule.
		for dl_type in ['IPv4', 'IPv6', 'ARP']:
			with self.subTest(dl_type=dl_type):
				with self.assertRaisesRegex(ValueError, 'Invalid protocol value None'):
					Rule(dl_type=dl_type, nw_proto=None)
		row = {'nw_src': '10.0.0.1', 'actions': 'DENY'}
		with self.assertRaisesRegex(ValueError, 'Invalid protocol value None'):
			Rule(nw_src=row['nw_src'], nw_proto=row.get('nw_proto'), actions=row['actions'])
		# Leaving nw_proto out gives the documented default.
		self.assertEqual(Rule().nw_proto, 'TCP')
		self.assertEqual(Rule(dl_type='IPv6').nw_proto, 'TCP')
		self.assertEqual(Rule(dl_type='ARP').nw_proto, '*')
		for fields, expected in [(dict(nw_proto='TCP'), 'TCP'), (dict(nw_proto='udp'), 'UDP'),
				(dict(nw_proto='ICMP'), 'ICMP'), (dict(dl_type='IPv6', nw_proto='ICMPv6'), 'ICMPv6'),
				(dict(dl_type='ARP', nw_proto='ANY'), '*'), (dict(dl_type='ARP', nw_proto='*'), '*')]:
			with self.subTest(fields=fields):
				self.assertEqual(Rule(**fields).nw_proto, expected)

	def test_protocols_and_ports_on_arp_rules_are_rejected(self):
		for fields, parts in [(dict(nw_proto='TCP'), ['ARP rule', 'IP protocol', 'TCP']),
				(dict(nw_proto='udp'), ['ARP rule', 'IP protocol', 'UDP']),
				(dict(tp_dst='80'), ['ARP rule', 'ports', "tp_dst '80'"]),
				(dict(tp_src='1024-65535'), ['ARP rule', 'ports', "tp_src '1024-65535'"]),
				(dict(nw_proto='ICMP'), ['ICMP needs dl_type IPv4, not ARP'])]:
			with self.subTest(fields=fields):
				with self.assertRaises(ValueError) as error:
					Rule(dl_type='ARP', **fields)
				for part in parts:
					self.assertIn(part, str(error.exception))

	def test_equivalent_arp_rules_overlap(self):
		# The issue's rules can't be built any more. Without a protocol, two
		# ARP rules with opposite actions match the same packets: detection
		# reports it, and resolution keeps one rule, which denies.
		with self.assertRaises(ValueError):
			Rule(dl_type='ARP', nw_proto='UDP', actions='ALLOW')
		with self.assertRaises(ValueError):
			Rule(dl_type='ARP', tp_dst='80', actions='ALLOW')
		allow = Rule(dl_type='ARP', actions='ALLOW')
		deny = Rule(dl_type='ARP', actions='DENY')
		self.assertFalse(allow.disjoint(deny))
		self.assertTrue(allow.issubset(deny) and deny.issubset(allow))
		with self.assertLogs(self.resolver.resolver_logger, 'INFO') as logs:
			self.resolver.detect_anomalies([allow, deny])
		self.assertIn('Shadowing Anomaly\n\t%s\n\t%s' % (allow, deny),
			[record.getMessage() for record in logs.records])
		resolved = self.resolver.resolve_anomalies([allow, deny])
		self.assertEqual([(rule.dl_type, rule.nw_proto, rule.actions) for rule in resolved],
			[('ARP', '*', 'DENY')])
		# ARP rules still differ by MAC address, and never overlap IP rules.
		self.assertTrue(Rule(dl_type='ARP', dl_src='aa:aa:aa:aa:aa:aa').disjoint(
			Rule(dl_type='ARP', dl_src='bb:bb:bb:bb:bb:bb')))
		self.assertTrue(allow.disjoint(Rule(actions='DENY')))


class IcmpPortTests(unittest.TestCase):
	# Issue #40: tp_src and tp_dst are TCP and UDP ports in this rule model,
	# but ICMP and ICMPv6 rules could still carry them, and they were compared
	# as if they applied: a rule for port 80 counted as inside the rule for
	# any port, not the other way round, and rules for ports 80 and 81 as
	# disjoint.

	def setUp(self):
		self.resolver = AnomalyResolver(log_level='CRITICAL')

	def tearDown(self):
		self.resolver.resolver_logger.handlers.clear()

	def parse(self, *lines):
		with tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8') as handle:
			handle.write(''.join(line + '\n' for line in lines))
			path = handle.name
		self.addCleanup(os.remove, path)
		return SimpleRuleParser(path).rules

	def anomalies(self, rules):
		with self.assertLogs(self.resolver.resolver_logger, 'INFO') as logs:
			self.resolver.detect_anomalies(rules)
		return [record.getMessage() for record in logs.records if 'Anomaly' in record.getMessage()]

	def assertNoIcmpPorts(self, rules):
		for rule in rules:
			if rule.nw_proto in ('ICMP', 'ICMPv6'):
				self.assertEqual((rule.tp_src, rule.tp_dst), ('*', '*'), str(rule))

	def test_rules_file_through_detection_and_resolution(self):
		# ICMP and ICMPv6 lines with each spelling of ports that don't
		# constrain the rule, next to TCP rules with real ports.
		rules = self.parse('1. <IN, ICMP, 10.0.0.1, ANY, ANY, ANY, ACCEPT>',
			'2. <IN, ICMP, 10.0.0.0/24, *, ANY, *, REJECT>',
			'3. <IN, ICMP, ANY, 0-65535, ANY, 0-65535, REJECT>',
			'4. <IN, ICMPv6, ANY, ANY, ANY, *, ACCEPT>',
			'5. <IN, TCP, 10.0.0.0/24, ANY, ANY, 80-90, REJECT>',
			'6. <IN, TCP, 10.0.0.0/24, ANY, ANY, 85-100, ACCEPT>')
		icmp_host, icmp_subnet, icmp_everyone, icmpv6, tcp_deny, tcp_allow = rules
		self.assertNoIcmpPorts(rules)
		self.assertEqual((tcp_deny.tp_dst, tcp_allow.tp_dst), ('80-90', '85-100'))
		# The host is inside the subnet with the other action; the TCP rules
		# overlap on ports 85-90; the ICMPv6 rule overlaps no IPv4 rule.
		reports = self.anomalies(rules)
		self.assertIn('Shadowing Anomaly\n\t%s\n\t%s' % (icmp_host, icmp_subnet), reports)
		self.assertIn('Correlation Anomaly\n\t%s\n\t%s' % (tcp_deny, tcp_allow), reports)
		self.assertFalse([report for report in reports if str(icmpv6) in report])
		resolved = self.resolver.resolve_anomalies(rules)
		self.assertNoIcmpPorts(resolved)
		self.assertTrue(any(rule.nw_proto == 'TCP' and rule.tp_dst != '*' for rule in resolved))
		for fields, decision in [(dict(nw_proto='ICMP', nw_src='10.0.0.1'), 'ALLOW'),
				(dict(nw_proto='ICMP', nw_src='10.0.0.2'), 'DENY'),
				(dict(nw_proto='ICMP', nw_src='10.9.9.9'), 'DENY'),
				(dict(dl_type='IPv6', nw_proto='ICMPv6'), 'ALLOW'),
				(dict(nw_proto='TCP', nw_src='10.0.0.5', tp_dst='80'), 'DENY'),
				(dict(nw_proto='TCP', nw_src='10.0.0.5', tp_dst='85'), 'DENY'),
				(dict(nw_proto='TCP', nw_src='10.0.0.5', tp_dst='95'), 'ALLOW'),
				(dict(nw_proto='TCP', nw_src='10.0.0.5', tp_dst='101'), None),
				(dict(nw_proto='UDP', nw_src='10.0.0.5', tp_dst='85'), None)]:
			with self.subTest(fields=fields):
				self.assertEqual(first_match(resolved, Rule(**fields)), decision)

	def test_correlated_icmp_rules_fail_closed(self):
		# Each rule is more specific in one address, so the packets both match
		# are denied, whichever of them allows.
		for source_action, destination_action in [('ALLOW', 'DENY'), ('DENY', 'ALLOW')]:
			with self.subTest(source_action=source_action):
				rules = [Rule(nw_proto='ICMP', nw_src='10.0.0.0/24', actions=source_action),
					Rule(nw_proto='ICMP', nw_dst='10.0.1.1', actions=destination_action)]
				self.assertIn('Correlation Anomaly\n\t%s\n\t%s' % tuple(rules), self.anomalies(rules))
				resolved = self.resolver.resolve_anomalies(rules)
				self.assertNoIcmpPorts(resolved)
				for source, destination, decision in [('10.0.0.5', '10.0.1.1', 'DENY'),
						('10.0.0.5', '10.0.1.2', source_action), ('10.9.9.9', '10.0.1.1', destination_action)]:
					self.assertEqual(first_match(resolved, Rule(nw_proto='ICMP', nw_src=source,
						nw_dst=destination)), decision)

	def test_nested_icmpv6_rules_resolve_to_the_inner_action(self):
		host = Rule(dl_type='IPv6', nw_proto='ICMPv6', ipv6_src='2001:db8::1', actions='ALLOW')
		network = Rule(dl_type='IPv6', nw_proto='ICMPv6', ipv6_src='2001:db8::/32', tp_src='0-65535',
			tp_dst='ANY', actions='DENY')
		self.assertIn('Shadowing Anomaly\n\t%s\n\t%s' % (host, network), self.anomalies([host, network]))
		resolved = self.resolver.resolve_anomalies([host, network])
		self.assertNoIcmpPorts(resolved)
		for source, decision in [('2001:db8::1', 'ALLOW'), ('2001:db8::2', 'DENY'), ('2001:db9::1', None)]:
			self.assertEqual(first_match(resolved, Rule(dl_type='IPv6', nw_proto='ICMPv6',
				ipv6_src=source)), decision)

	def test_icmp_rules_have_no_ports(self):
		for fields, parts in [(dict(nw_proto='ICMP', tp_dst='80'), ['ICMP rule', 'ports', "tp_dst '80'"]),
				(dict(nw_proto='icmp', tp_src='1024-65535'), ['ICMP rule', 'ports', "tp_src '1024-65535'"]),
				(dict(dl_type='IPv6', nw_proto='ICMPv6', tp_dst='8080'), ['ICMPv6 rule', 'ports', "tp_dst '8080'"])]:
			with self.subTest(fields=fields):
				with self.assertRaises(ValueError) as error:
					Rule(**fields)
				for part in parts:
					self.assertIn(part, str(error.exception))
		# Ports that don't constrain the rule are accepted, and are the default.
		for fields in [dict(nw_proto='ICMP'), dict(nw_proto='ICMP', tp_src='0-65535', tp_dst='ANY'),
				dict(dl_type='IPv6', nw_proto='ICMPv6', tp_dst='*')]:
			with self.subTest(fields=fields):
				rule = Rule(**fields)
				self.assertEqual((rule.tp_src, rule.tp_dst), ('*', '*'))
		# TCP and UDP keep their ports, over IPv4 and IPv6.
		for fields, expected in [(dict(nw_proto='TCP', tp_dst='80'), ('*', '80')),
				(dict(nw_proto='UDP', tp_src='53'), ('53', '*')),
				(dict(dl_type='IPv6', nw_proto='UDP', tp_dst='53'), ('*', '53'))]:
			with self.subTest(fields=fields):
				rule = Rule(**fields)
				self.assertEqual((rule.tp_src, rule.tp_dst), expected)

	def test_icmp_rules_compare_on_the_fields_that_apply(self):
		# The issue's rules can't be built any more. ICMP rules now differ only
		# in fields that apply to ICMP, such as the addresses.
		for port in ['80', '81']:
			with self.assertRaises(ValueError):
				Rule(nw_proto='ICMP', tp_dst=port)
		host = Rule(nw_proto='ICMP', nw_src='10.0.0.1', actions='ALLOW')
		everyone = Rule(nw_proto='ICMP', tp_src='0-65535', actions='DENY')
		self.assertTrue(host.issubset(everyone))
		self.assertFalse(everyone.issubset(host))
		self.assertFalse(host.disjoint(everyone))
		self.assertTrue(Rule(nw_proto='ICMP').issubset(Rule(nw_proto='ICMP', tp_dst='ANY')))


def product_scopes(rules):
	# scopes() before PR #35's review: every combination of the named values
	# of every scope field, pruned the same way. Kept as the reference.
	fields = AnomalyResolver.scope_fields

	def named(field, everything):
		values = set(getattr(rule, field) for rule in rules) - {everything}
		return sorted(values, key=lambda value: (value is not None, value or '')) + [everything]

	def applicable(scope):
		return frozenset(index for index, rule in enumerate(rules)
			if AnomalyResolver.applies(rule, scope))

	def covers(general, specific):
		return all(Rule.scopeinrange(value, other, everything)
			for (_, everything), value, other in zip(fields, specific, general))

	combinations = sorted(itertools.product(*[named(field, everything) for field, everything in fields]),
		key=lambda scope: sum(value == everything for (_, everything), value in zip(fields, scope)))
	kept = list()
	for scope in reversed(combinations):
		fallback = next((later for later in kept if covers(later, scope)), None)
		if fallback is None or applicable(scope) != applicable(fallback):
			kept.insert(0, scope)
	return kept


class ScopeTests(unittest.TestCase):
	# scopes() lists the combinations of switch, VLAN and MAC addresses that
	# resolution handles separately. It used to go through the product of
	# every named value of the four fields.

	def setUp(self):
		self.resolver = AnomalyResolver(log_level='CRITICAL')

	def tearDown(self):
		self.resolver.resolver_logger.handlers.clear()

	def host_rules(self, count):
		# Rules that each name their own switch, VLAN and MAC addresses, and a
		# rule for every packet.
		return [Rule(switch='s%d' % index, vlan='%d' % index, dl_src='aa:aa:aa:aa:aa:%02x' % index,
			dl_dst='bb:bb:bb:bb:bb:%02x' % index, nw_src='10.0.0.%d' % index, actions='DENY')
			for index in range(count)] + [Rule(actions='ALLOW')]

	def test_scopes_match_the_product_of_every_value(self):
		generator = random.Random(35)
		values = {'switch': ['1', '2', 'all', None], 'vlan': ['5', '6', 'all'],
			'dl_src': ['aa:aa:aa:aa:aa:aa', 'bb:bb:bb:bb:bb:bb', '*'], 'dl_dst': ['dd:dd:dd:dd:dd:dd', '*']}
		for _ in range(400):
			rules = list()
			for _ in range(generator.randrange(1, 7)):
				rule = Rule()
				for field, choices in values.items():
					setattr(rule, field, generator.choice(choices))
				rules.append(rule)
			with self.subTest(scopes=[tuple(getattr(rule, field) for field in values) for rule in rules]):
				self.assertEqual(AnomalyResolver.scopes(rules), product_scopes(rules))

	def test_candidates_follow_the_scopes_rules_carry(self):
		# 16 rules naming 16 values in each of four fields made 17 ** 4 = 83,521
		# combinations, and applies() ran for every rule on each.
		rules = self.host_rules(16)
		with mock.patch.object(AnomalyResolver, 'applies', wraps=AnomalyResolver.applies) as applies:
			scopes = AnomalyResolver.scopes(rules)
		self.assertEqual(len(scopes), 17)
		self.assertLess(applies.call_count, 1000)

	def test_rules_for_every_scope_still_apply_everywhere(self):
		# The rule for every packet decides the rest of each named scope, and
		# the scopes no rule names.
		rules = self.host_rules(16)
		resolved = self.resolver.resolve_anomalies(rules)
		for index in [0, 7, 15]:
			scope = dict(switch='s%d' % index, vlan='%d' % index, dl_src='aa:aa:aa:aa:aa:%02x' % index,
				dl_dst='bb:bb:bb:bb:bb:%02x' % index)
			self.assertEqual(first_match(resolved, Rule(nw_src='10.0.0.%d' % index, **scope)), 'DENY')
			self.assertEqual(first_match(resolved, Rule(nw_src='10.0.0.99', **scope)), 'ALLOW')
		self.assertEqual(first_match(resolved, Rule(switch='s99', nw_src='10.0.0.1')), 'ALLOW')
		self.assertEqual(first_match(resolved, Rule(switch='s1', vlan='2', nw_src='10.0.0.1')), 'ALLOW')


class SpeedTests(unittest.TestCase):
	# Issue #10: every port check built a set of up to 65,536 values, address
	# checks built IPSets, split() listed every port of the range it split, and
	# each tree step copied the attributes of the whole tree. On these rules,
	# detection, resolution and building the tree each took about 15 s, and
	# each now takes under 0.1 s. Rather than time the runs, which
	# depends on the machine, these tests make those slow calls fail.

	def setUp(self):
		self.resolver = AnomalyResolver(log_level='CRITICAL')

	def tearDown(self):
		self.resolver.resolver_logger.handlers.clear()

	def rules(self, count, source):
		# The rules from the issue's reproducer, with sources from source().
		generator = random.Random(10)
		return [Rule(nw_src=source(generator), nw_dst='10.1.0.%d' % generator.randrange(8),
			tp_dst=generator.choice(['*', '22', '80', '443', '1000-2000']),
			actions=generator.choice(['ALLOW', 'DENY'])) for _ in range(count)]

	def forbid(self, target, name):
		# Until the test ends, calling target.name fails the test.
		patcher = mock.patch.object(target, name,
			side_effect=AssertionError('%s must not be called' % name))
		patcher.start()
		self.addCleanup(patcher.stop)

	def forbid_value_sets(self):
		self.forbid(Rule, 'portstr2range')
		self.forbid(anomaly_resolver, 'IPSet')

	def test_detection_compares_bounds(self):
		rules = self.rules(100, lambda generator: '10.0.%d.0/24' % generator.randrange(4))
		self.forbid_value_sets()
		self.resolver.detect_anomalies(rules)

	def test_resolution_compares_bounds(self):
		# Some sources are '*', so that rules overlap without one containing the
		# other, and split() runs, including on '*' ports.
		rules = self.rules(40, lambda generator: generator.choice(['*',
			'10.0.%d.0/24' % generator.randrange(4)]))
		self.forbid_value_sets()
		with self.assertLogs(self.resolver.resolver_logger, 'INFO') as logs:
			self.resolver.resolve_anomalies(rules)
		# The rules overlap, so split() ran as well.
		self.assertTrue(any(record.getMessage().startswith('Overlapping rule')
			for record in logs.records))

	def test_building_the_rule_tree_reads_single_edges(self):
		# Single hosts, so that the tree has many edges.
		rules = self.rules(400, lambda generator: '10.0.%d.%d' % (generator.randrange(4),
			generator.randrange(256)))
		self.forbid(nx, 'get_node_attributes')
		self.forbid(nx, 'get_edge_attributes')
		self.resolver.construct_rule_tree(rules, plot=False)
		self.assertGreater(self.resolver.tree.number_of_edges(), 400)
