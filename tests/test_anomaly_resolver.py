import os
import tempfile
import unittest

from anomaly_resolver import AnomalyResolver, Rule, SimpleRuleParser


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
