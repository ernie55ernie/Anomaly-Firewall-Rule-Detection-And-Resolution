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


class ResolverTests(unittest.TestCase):

	def test_resolver_instances_do_not_stack_handlers(self):
		first = AnomalyResolver(log_level='CRITICAL')
		second = AnomalyResolver(log_level='CRITICAL')
		self.assertEqual(len(first.resolver_logger.handlers), 1)
		self.assertEqual(len(second.resolver_logger.handlers), 1)


class RedundancyRemovalTests(unittest.TestCase):

	def setUp(self):
		self.resolver = AnomalyResolver(log_level='CRITICAL')

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
		# Explicit in_port and tp_src values keep the port checks small.
		generator = random.Random(2)

		def address_range():
			first = generator.randrange(8)
			last = generator.randrange(first, 8)
			if first == 0 and last == 7:
				return '*'
			if first == last:
				return '10.0.0.%d' % first
			return '10.0.0.%d-10.0.0.%d' % (first, last)

		def port_range():
			first = generator.randrange(1, 5)
			last = generator.randrange(first, 5)
			return str(first) if first == last else '%d-%d' % (first, last)

		def random_rule():
			return Rule(in_port='1', nw_src=address_range(), tp_src='1',
				tp_dst=port_range(), actions=generator.choice(['ALLOW', 'DENY']))

		packets = [Rule(in_port='1', nw_src='10.0.0.%d' % host, tp_src='1',
			nw_dst='8.8.8.8', tp_dst=str(port))
			for host in range(9) for port in range(6)]
		for _ in range(150):
			rules = [random_rule() for _ in range(generator.randrange(2, 7))]
			kept = self.resolver.remove_redundant_rules(rules)
			remaining = iter(rules)
			self.assertTrue(all(any(rule is other for other in remaining) for rule in kept),
				'kept rules must stay in their original order')
			for packet in packets:
				self.assertEqual(first_match(kept, packet), first_match(rules, packet),
					'%s changed for %s -> %s' % (packet, rules, kept))
