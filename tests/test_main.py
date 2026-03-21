import unittest

import main


class MainParserTests(unittest.TestCase):

	def test_defaults_to_detect_when_no_action_is_selected(self):
		parser = main.build_parser()
		args = parser.parse_args([])
		self.assertEqual(main.determine_action(args), 'detect')

	def test_merge_action_is_selected_explicitly(self):
		parser = main.build_parser()
		args = parser.parse_args(['--merge'])
		self.assertEqual(main.determine_action(args), 'merge')

	def test_actions_are_mutually_exclusive(self):
		parser = main.build_parser()
		with self.assertRaises(SystemExit):
			parser.parse_args(['--detect', '--resolve'])
