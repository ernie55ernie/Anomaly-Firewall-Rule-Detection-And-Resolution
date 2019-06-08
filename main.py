import argparse
from anomaly_resolver import *

parser = argparse.ArgumentParser(description='Anomaly Firewall Rule Detection and Resolution')
parser.add_argument('--path', type=str, action='store', default='rules/example_rules_1',
	help='path of firewall rules file')
parser.add_argument('--detect', action='store_true', default=True,
	help='detect anomaly firewall rule')
parser.add_argument('--resolve', action='store_true', default=False,
	help='resolve anomaly firewall rule')
parser.add_argument('--merge', action='store_true', default=False,
	help='merge contiguous firewall rule')
args = parser.parse_args()
srp = SimpleRuleParser(args.path)
rules_list = srp.rules
a = AnomalyResolver()
if args.detect:
	a.detect_anomalies(rules_list)
if args.resolve:
	a.resolve_anomalies(rules_list)
if args.merge:
	a.merge_contiguous_rules(rules_list)