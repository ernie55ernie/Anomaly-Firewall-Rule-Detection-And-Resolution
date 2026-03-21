import argparse


def build_parser():
	parser = argparse.ArgumentParser(
		description='Anomaly Firewall Rule Detection and Resolution'
	)
	parser.add_argument(
		'--path',
		type=str,
		action='store',
		default='rules/example_rules_1',
		help='path of firewall rules file'
	)
	action_group = parser.add_mutually_exclusive_group()
	action_group.add_argument(
		'--detect',
		action='store_true',
		default=False,
		help='detect anomaly firewall rule'
	)
	action_group.add_argument(
		'--resolve',
		action='store_true',
		default=False,
		help='resolve anomaly firewall rule'
	)
	action_group.add_argument(
		'--merge',
		action='store_true',
		default=False,
		help='merge contiguous firewall rule'
	)
	return parser


def determine_action(args):
	if args.resolve:
		return 'resolve'
	if args.merge:
		return 'merge'
	return 'detect'


def main(argv=None):
	parser = build_parser()
	args = parser.parse_args(argv)

	# Import the heavy runtime only after parsing so `--help` works without
	# optional plotting dependencies being installed.
	from anomaly_resolver import AnomalyResolver, SimpleRuleParser

	srp = SimpleRuleParser(args.path)
	rules_list = srp.rules
	resolver = AnomalyResolver()
	action = determine_action(args)

	if action == 'detect':
		resolver.detect_anomalies(rules_list)
	elif action == 'resolve':
		resolver.resolve_anomalies(rules_list)
	else:
		resolver.merge_contiguous_rules(rules_list)

	return 0


if __name__ == '__main__':
	raise SystemExit(main())
