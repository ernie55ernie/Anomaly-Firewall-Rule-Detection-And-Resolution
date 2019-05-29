# Firewall Rule Anomaly Resolver for Ryu restfull firewall 
# https://github.com/osrg/ryu/blob/master/ryu/app/rest_firewall.py
import logging
import logging.handlers
import itertools
import ctypes
from netaddr import IPSet, IPRange, IPNetwork, IPGlob
from netaddr import	cidr_merge, valid_ipv4, valid_glob, glob_to_cidrs
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from utils import hierarchy_pos

STRING_TYPE = ctypes.c_wchar_p

class RuleParser():

	rules = []
	
	def __init__(self):
		pass

	def parse_file(self, file_name):
		pass

	def get_rules(self):
		return self.rules

class SimpleRuleParser(RuleParser):

	def __init__(self, file_name):
		self.parse_file(file_name)
		super(SimpleRuleParser, self).__init__()

	def parse_file(self, file_name):
		with open(file_name, 'r') as f:
			for line in f:
				priority = int(line[:line.find('.')])
				rule_start = line.find('<')
				rule_end = line.find('>')
				rule_string = line[rule_start + 1:rule_end]
				rule_string = rule_string.replace(' ', '')
				fields = rule_string.split(',')
				rule = Rule(priority = priority,
					direction = fields[0], 
					nw_proto = fields[1], 
					nw_src = fields[2], 
					nw_dst = fields[4], 
					tp_src = fields[3], 
					tp_dst = fields[5], 
					actions = fields[6])
				self.rules.append(rule)

class Rule(ctypes.Structure):
	# https://osrg.github.io/ryu-book/en/html/rest_firewall.html#id10
	_fields_ = [('switch', STRING_TYPE),
	 			 # REST_SWITCHID, [ 'all' | Switch ID ]
				('vlan', STRING_TYPE),
				 # REST_VLANID, [ 'all' | VLAN ID ]
				('priority', ctypes.c_int),
				 # REST_PRIORITY, [ 0 - 65535 ]
				('in_port', STRING_TYPE),
				 # REST_IN_PORT, [ 0 - 65535 ]
				('dl_src', STRING_TYPE),
				 # REST_SRC_MAC, '<xx:xx:xx:xx:xx:xx>'
				('dl_dst', STRING_TYPE),
				 # REST_DST_MAC, '<xx:xx:xx:xx:xx:xx>'
				('dl_type', STRING_TYPE),
				 # REST_DL_TYPE, [ 'ARP' | 'IPv4' | 'IPv6' ]
				('nw_src', STRING_TYPE),
				 # REST_SRC_IP, '<xxx.xxx.xxx.xxx/xx>'
				('nw_dst', STRING_TYPE),
				 # REST_DST_IP, '<xxx.xxx.xxx.xxx/xx>'
				('ipv6_src', STRING_TYPE),
				 # REST_SRC_IPV6, '<xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xx>'
				('ipv6_dst', STRING_TYPE),
				 # REST_DST_IPV6, '<xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xx>'
				('nw_proto', STRING_TYPE),
				 # REST_NW_PROTO, [ 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' ]
				('tp_src', STRING_TYPE),
				 # REST_TP_SRC, [ 0 - 65535 ]
				('tp_dst', STRING_TYPE),
				 # REST_TP_DST, [ 0 - 65535 ]
				('direction', STRING_TYPE),
				 # [ 'IN' | 'OUT' ]
				('actions', STRING_TYPE)
				 # REST_ACTION, [ 'ALLOW' | 'DENY' ]
				]

	def __init__(self, switch = 'all', vlan = 'all', priority = 0, \
		in_port = '*', dl_src = '*', dl_dst = '*', \
		dl_type = 'IPv4', nw_src = '*', nw_dst = '*', ipv6_src = '*', \
		ipv6_dst = '*', nw_proto = 'TCP', tp_src = '0-65535', \
		tp_dst = '*', direction = 'IN', actions = 'DENY', id = 0, rule_id=0):

		priority = Rule._sanity_check(priority, field = 'priority')
		in_port = Rule._sanity_check(in_port, field = 'port')
		nw_src = Rule._sanity_check(nw_src, field = 'ipv4')
		nw_dst = Rule._sanity_check(nw_dst, field = 'ipv4')
		tp_src = Rule._sanity_check(tp_src, field = 'port')
		tp_dst = Rule._sanity_check(tp_dst, field = 'port')
		direction = Rule._sanity_check(direction, field = 'direction')
		actions = Rule._sanity_check(actions, field = 'action')

		super(Rule, self).__init__(switch, vlan, priority, in_port, \
			dl_src, dl_dst, dl_type, nw_src, nw_dst, ipv6_src, ipv6_dst, \
			nw_proto, tp_src, tp_dst, \
			direction, actions)

	def _sanity_check(value, field):
		if field == 'priority':
			try:
				if isinstance(value, int) and value >= 0 and value < 65536:
					return value
			except:
				return value

		if field == 'port':
			if '-' in value and value != '0-65535':
				first, second = value.split('-')
				if first.isdigit() and second.isdigit():
					return value
			elif value.isdigit():
				return value
			return '*' # 'ANY' or '*' or '0-65535':

		if field == 'dl_type':
			if value.upper() in ['ARP', 'IPv4', 'IPv6']:
				return value.upper()
			return 'IPv4'

		if field == 'ipv4':
			if '-' in value:
				first, second = value.split('-')
				if valid_ipv4(first) and valid_ipv4(second):
					return value
			if valid_glob(value):
				return str(glob_to_cidrs(value)[0])
			if valid_ipv4(value) or \
				('/'in value and valid_ipv4(value[:value.find('/')])):
				return value
			return '*' # 'ANY'

		if field == 'nw_proto':
			if value.upper() in ['TCP', 'UDP', 'ICMP', 'ICMPv6']:
				return value.upper()
			return 'TCP'

		if field == 'direction':
			if value.upper() in ['IN']:
				return 'IN'
			if value.upper() in ['OUT']:
				return 'OUT'
			return 'IN'

		if field == 'action':
			if value.upper() in ['DENY', 'REJECT']:
				return 'DENY'
			if value.upper() in ['ALLOW', 'ACCEPT']:
				return 'ALLOW'
			return 'DENY'

	def __repr__(self, format='basic'):
		if format == 'detail':
			return '<switch:%s, vlan:%s, priority:%d, in_port:%s, dl_src:%s, dl_dst:%s,' \
					' dl_type:%s, nw_src:%s, nw_dst:%s, ipv6_src:%s, ipv6_dst:%s,' \
					' nw_proto:%s, tp_src:%s, tp_dst:%s, actions:%s>' \
					% (self.switch, self.vlan, self.priority, self.in_port, \
						self.dl_src, self.dl_dst, self.dl_type, self.nw_src, self.nw_dst, \
						self.ipv6_src, self.ipv6_dst, self.nw_proto, self.tp_src, \
						self.tp_dst, self.direction, self.actions)
		if format == 'no description':
			return '<%s, %s, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s>' \
				% (self.switch, self.vlan, self.priority, self.in_port, self.dl_src, \
					self.dl_dst, self.dl_type, self.nw_src, self.nw_dst, self.ipv6_src, \
					self.ipv6_dst, self.nw_proto, self.tp_src, self.tp_dst, self.actions)
		return '<%s, %s, %s, %s, %s, %s, %s>' \
			% (self.nw_src, self.nw_dst, \
				self.nw_proto, self.tp_src, self.tp_dst, self.direction, self.actions)

	def __eq__(self, rhs):
		return self.issubset(rhs) and self.issubset(rhs)

	def disjoint(self, subset_rule):
		# TODO support for
		# dl_src, dl_dst, dl_type, ipv6_src, ipv6_dst, multiple protocol
		if not self.switch == subset_rule.switch or \
			not self.vlan == subset_rule.vlan or \
			Rule.portdisjoint(self.in_port, subset_rule.in_port) or \
			Rule.ipdisjoint(self.nw_src, subset_rule.nw_src) or \
			Rule.ipdisjoint(self.nw_dst, subset_rule.nw_dst) or \
			not self.nw_proto == subset_rule.nw_proto or \
			Rule.portdisjoint(self.tp_src, subset_rule.tp_src) or \
			Rule.portdisjoint(self.tp_dst, subset_rule.tp_dst) or \
			not self.direction == subset_rule.direction:
			return True
		return False

	def issubset(self, subset_rule):
		# TODO support for
		# dl_src, dl_dst, dl_type, ipv6_src, ipv6_dst, multiple protocol
		if self.switch == subset_rule.switch and self.vlan == subset_rule.vlan and \
			Rule.portinrange(self.in_port, subset_rule.in_port) and \
			Rule.ipinrange(self.nw_src, subset_rule.nw_src) and \
			Rule.ipinrange(self.nw_dst, subset_rule.nw_dst) and \
			self.nw_proto == subset_rule.nw_proto and \
			Rule.portinrange(self.tp_src, subset_rule.tp_src) and \
			Rule.portinrange(self.tp_dst, subset_rule.tp_dst) and \
			self.direction == subset_rule.direction:
			return True
		return False

	def portinrange(first, second):
		first_set = set(Rule.portstr2range(first))
		second_set = set(Rule.portstr2range(second))
		return first_set.issubset(second_set)

	def portstr2range(x):
		res = list()
		if x == '*':
			x = '0-65535'
		if '-' in x:
			first, second = x.split('-')
			first, second = int(first), int(second)
			res.extend(range(first, second + 1))
		else:
			num = int(x)
			res.append(num)
		return res

	def ipinrange(first, second):
		first_set = Rule.ipstr2range(first, format='set')
		second_set = Rule.ipstr2range(second, format='set')
		return first_set.issubset(second_set)

	def portdisjoint(first, second):
		if first == '0-65535' or second == '0-65535':
			return False
		first_set = set(Rule.portstr2range(first))
		second_set = set(Rule.portstr2range(second))
		return not first_set.intersection(second_set)

	def ipdisjoint(first, second):
		first_set = Rule.ipstr2range(first, format='set')
		second_set = Rule.ipstr2range(second, format='set')
		return not first_set.intersection(second_set)

	def find_attribute_set(self, subset_rule):
		attribute_set = set()
		for field in self._fields_:
			if not getattr(self, field[0]) == getattr(subset_rule, field[0]) and \
				(field[0] == 'in_port' or field[0] == 'nw_src' or 
				field[0] == 'nw_dst' or field[0] == 'tp_src' or field[0] == 'tp_dst'):
				attribute_set.add(field[0])
		return attribute_set

	def get_attribute_range(self, attribute, format = 'range'):
		if attribute == 'in_port' or attribute == 'tp_src' or attribute == 'tp_dst':
			range_list = Rule.portstr2range(getattr(self, attribute))
			if format == 'string':
				if len(range_list) < 2:
					return str(range_list[0])
				return '%d-%d' % (range_list[0], range_list[-1])
			return range_list
		elif attribute == 'nw_src' or attribute == 'nw_dst':
			iprange = Rule.ipstr2range(getattr(self, attribute))
			if format == 'string':
				last = str(iprange[-1])
				return str(iprange[0]) + '-' + last[last.rindex('.') + 1:]
			return iprange
		else:
			return eval('self.' + attribute)

	def set_attribute_range(self, attribute, start, end, offset):
		if attribute == 'in_port' or attribute == 'tp_src' or attribute == 'tp_dst':
			if offset == -1:
				new_range = range(start, end)
			elif offset == 1:
				new_range = range(start + 1, end + 1)
			else:
				new_range = range(start, end + 1)
			if len(new_range) > 1:
				new_str = '%d-%d' % (new_range[0], new_range[-1])
			else:
				new_str = '%d' % (new_range[0], )
			setattr(self, attribute, new_str)
		else:
			if offset == -1:
				new_range = IPRange(start, end - 1)
			elif offset == 1:
				new_range = IPRange(start + 1, end)
			else:
				new_range = IPRange(start, end)
			new_range = Rule.iprange2str(new_range)
			setattr(self, attribute, new_range)

	def iprange2str(ip_range):
		if len(ip_range) > 1:
			return '%s-%s/32' % (str(ip_range[0]), str(ip_range[-1]))
		else:
			return str(ip_range[0])

	def ipstr2range(ip_str, format='range'):
		init = IPRange if format == 'range' else IPSet
		if ip_str == '*':
			ip_str = '0.0.0.0/0'
		if '*' in ip_str:
			ipglob = IPGlob(ip_str)
			iprange = IPRange(ipglob[0], ipglob[-1])
			return iprange if format == 'range' else init(iprange)
		if '-' in ip_str:
			start, end = ip_str.split('-')
			iprange = IPRange(start, start[:start.rindex('.') + 1] + end)
			return iprange if format == 'range' else init(iprange)
		else:
			if format == 'range':
				network = IPNetwork(ip_str)
				return init(network[0], network[-1])
			return init([ip_str])

	def set_fields(self, other):
		for field in other._fields_:
			setattr(self, field[0], getattr(other, field[0]))

	def contiguous(r_1, r_2):
		if '.' in r_1 or '*' == r_1:
			range_1 = Rule.ipstr2range(r_1)
			range_2 = Rule.ipstr2range(r_2)
		else:
			range_1 = Rule.portstr2range(r_1)
			range_2 = Rule.portstr2range(r_2)

class AnomalyResolver:

	# TODO support for
	# dl_src, dl_dst, dl_type, ipv6_src, ipv6_dst, multiple protocol
	attr_list = ['direction', 'nw_proto', 'nw_src', 'tp_src', 'nw_dst', 'tp_dst', 'actions', 'None']
	attr_dict = {}
	tree = None

	def __init__(self, log_output = 'console', log_level = 'INFO'):

		for key in self.attr_list:
			self.attr_dict[key] = 0

		self.resolver_logger = logging.getLogger('AnomalyResolver')
		self.resolver_logger.setLevel(logging.DEBUG)
		formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s' \
			' - %(message)s')
		if log_level not in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'NOTSET']:
			log_level = 'INFO'
		log_level = eval('logging.' + log_level)
		if 'file' in log_output:
			self.LOG_FILENAME = 'anomaly_resolver.log'
			file_handler = logging.FileHandler(self.LOG_FILENAME)
			file_handler.setFormatter(formatter)
			file_handler.setLevel(log_level)
			self.resolver_logger.addHandler(file_handler)
		if 'console' in log_output:
			console_handler = logging.StreamHandler()
			console_handler.setFormatter(formatter)
			console_handler.setLevel(log_level)
			self.resolver_logger.addHandler(console_handler)
		self.resolver_logger.info('Start Anomaly Resolver')

	def detect_anomalies(self, rules_list):
		self.resolver_logger.info('Perform Detection\nRules list:\n\t' + \
			'\n\t'.join(map(str, rules_list)))

		combination_list = list(itertools.combinations(rules_list, 2))
		for rule_tuple in combination_list:
			rule_0 = rule_tuple[0]
			rule_1 = rule_tuple[1]
			if rule_0.disjoint(rule_1):
				continue
			if rule_0.issubset(rule_1) or rule_1.issubset(rule_0):
				if rule_0.actions == rule_1.actions:
					self.resolver_logger.info('Redundancy Anomaly\n\t%s\n\t%s', \
						str(rule_0), str(rule_1))
				else:
					self.resolver_logger.info('Shadowing Anomaly\n\t%s\n\t%s', \
						str(rule_0), str(rule_1))
				continue
			if not rule_0.disjoint(rule_1) and not rule_0.issubset(rule_1) and \
				not rule_1.issubset(rule_0):
				self.resolver_logger.info('Correlation Anomaly\n\t%s\n\t%s', \
					str(rule_0), str(rule_1))
				continue
	
	def resolve_anomalies(self, old_rules_list):
		'''
		Resolve anomalies in firewall rules file
		'''
		self.resolver_logger.info('Perform Resolving\nOld rules list:\n\t' + \
			'\n\t'.join(map(str, old_rules_list)))
		new_rules_list = list()

		for rule in old_rules_list:
			self.insert(rule, new_rules_list)

		combination_list = list(itertools.combinations(new_rules_list, 2))
		removed_rules = list()
		for rule_tuple in combination_list:
			rule = rule_tuple[0]
			if rule in removed_rules:
				continue
			subset_rule = rule_tuple[1]

			if rule.issubset(subset_rule) and \
				rule.actions == subset_rule.actions:
				if rule in new_rules_list:
					self.resolver_logger.info('Redundant rule %s', str(rule))
					new_rules_list.remove(rule)
					removed_rules.append(rule)
		# TODO reassign priority
		
		self.resolver_logger.info('New rules list:\n\t' + \
			'\n\t'.join(map(str, new_rules_list)))
		self.resolver_logger.info('Finish anomalies resolving')
		return new_rules_list


	def insert(self, rule, new_rules_list):
		'''
		Insert the rule r into new_rules_list
		'''
		if not new_rules_list:
			new_rules_list.append(r)
		else:
			inserted = False
			for subset_rule in new_rules_list:

				if not r.disjoint(subset_rule):
					inserted = self.resolve(r, subset_rule, new_rules_list)
					if inserted:
						break
			if not inserted:
				new_rules_list.append(r)

	def resolve(self, rule, subset_rule, new_rules_list):
		'''
		Resolve anomalies between two rules r and s
		'''
		if rule.issubset(subset_rule) and subset_rule.issubset(rule):
			if not rule.actions == subset_rule.actions:
				subset_rule.actions = 'DENY'
			else:
				self.resolver_logger.info('Remove rule %s' % (str(rule),))
			return True
		if rule.issubset(subset_rule):
			self.resolver_logger.info('Reodering %s before %s' % \
				(str(rule), str(subset_rule)))
			new_rules_list.insert(0, rule)
			return True
		if subset_rule.issubset(rule):
			return False
		if subset_rule in new_rules_list:
			new_rules_list.remove(subset_rule)
		attribute_set = rule.find_attribute_set(subset_rule)

		for attribute in attribute_set:
			self.split(rule, subset_rule, attribute, new_rules_list)
		if not rule.actions == subset_rule.actions:
			subset_rule.actions = 'DENY'
		self.insert(subset_rule, new_rules_list)
		return True

	def split(self, rule, subset_rule, attribute, new_rules_list):
		'''
		Split overlapping rules r and s based on attribute a
		'''
		self.resolver_logger.info('Correlation rule %s, %s' % (str(rule), str(subset_rule)))
		rule_range = rule.get_attribute_range(attribute)
		rule_start = rule_range[0]
		rule_end = rule_range[-1]
		subset_rule_range = subset_rule.get_attribute_range(attribute)
		subset_rule_start = subset_rule_range[0]
		subset_rule_end = subset_rule_range[-1]

		left = min(rule_start, subset_rule_start)
		right = max(rule_end, subset_rule_end)
		common_start = max(rule_start, subset_rule_start)
		common_end = min(rule_end, subset_rule_end)

		if rule_start > subset_rule_start:
			copy_rule = Rule()
			copy_rule.set_fields(subset_rule)
			copy_rule.set_attribute_range(attribute, left, common_start, -1)
			self.insert(copy_rule, new_rules_list)
		elif rule_start < subset_rule_start:
			copy_rule = Rule()
			copy_rule.set_fields(rule)
			copy_rule.set_attribute_range(attribute, left, common_start, -1)
			self.insert(copy_rule, new_rules_list)
		if rule_end > subset_rule_end:
			copy_rule = Rule()
			copy_rule.set_fields(rule)
			copy_rule.set_attribute_range(attribute, common_end, right, 1)
			self.insert(copy_rule, new_rules_list)
		elif rule_end < subset_rule_end:
			copy_rule = Rule()
			copy_rule.set_fields(subset_rule)
			copy_rule.set_attribute_range(attribute, common_end, right, 1)
			self.insert(copy_rule, new_rules_list)
		rule.set_attribute_range(attribute, common_start, common_end, 0)
		subset_rule.set_attribute_range(attribute, common_start, common_end, 0)
	
	def merge_contiguous_rules(self, rule_list):
		self.construct_rule_tree(rule_list)
		self.merge(self.get_rule_tree_root())
		
	def construct_rule_tree(self, rule_list, plot=True):
		'''
		'''
		self.tree = nx.DiGraph()
		attr = self.attr_list[0]
		self.attr_dict[attr] = self.attr_dict[attr] + 1
		root_node = str(self.attr_dict[attr]) + '. ' + attr
		self.tree.add_node(root_node, attr = attr)
		for rule in rule_list:
			self.tree_insert(root_node, rule)
		if plot:
			self.plot_firewall_rule_tree()
		print('Nodes', self.tree.nodes())
		print('Edges', self.tree.edges())

	def get_rule_tree_root(self):
		'''
		'''
		attr_list = self.attr_list
		if self.tree:
			return '1. ' + attr_list[0]
		return None

	def plot_firewall_rule_tree(self, file_name = 'firewall_rule_tree.png'):
		plt.figure(figsize = (16, 16))
		tree = self.tree
		pos = hierarchy_pos(tree)
		nx.draw(tree, pos, with_labels = True)
		nx.draw_networkx_edge_labels(tree, 
			pos, 
			rotate = False,
			edge_labels = nx.get_edge_attributes(tree, 'range'))
		plt.savefig(file_name)

	def tree_insert(self, node, rule):
		'''
		Inserts rule r into the node n of the rule tree
		'''
		tree = self.tree
		attr_list = self.attr_list
		attr_dict = self.attr_dict
		attr = nx.get_node_attributes(tree, 'attr')[node]
		for snode in tree.successors(node):
			edge_range = nx.get_edge_attributes(tree, 'range')[(node, snode)]
			
			if rule.get_attribute_range(attr, format = 'string') == edge_range:
				self.tree_insert(snode, rule)
				return
		idx = attr_list.index(attr) + 1 if attr in attr_list else len(attr_list) + 1
		if idx > len(attr_list):
			return
		else:
			next_attr = attr_list[idx]
			attr_dict[next_attr] = attr_dict[next_attr] + 1
			next_node = str(attr_dict[next_attr]) + ('. ' + next_attr if next_attr != 'None' else '')
		tree.add_node(next_node, attr = next_attr)
		tree.add_edge(node, next_node, range = rule.get_attribute_range(attr, format = 'string'))
		if next_attr == 'None':
			return
		self.tree_insert(next_node, rule)

	def merge(self, n):
		'''
		Merges edges of node n representing a continuous range
		for all edge e in n.edges:
			merge(e.node)
		for all edge e in n.edges:
			for all edge e' != e in n.edges:
				if e and e' range are contiguous and Subtree(e)=Subtree(e'):
					Merge e.range and e'.range into e.range
					Remove e' from n.edges
		'''
		tree = self.tree
		edges = tree.edges()
		print(tree.edges([n]))
		for e in tree.edges([n]):
			self.merge(e[1])
		combination_list = list(itertools.combinations(tree.edges([n]), 2))
		for edge_tuple in combination_list:
			edge_1 = edge_tuple[0]
			edge_2 = edge_tuple[1]
			range_1 = edges[edge_1]['range']
			range_2 = edges[edge_2]['range']
			if Rule.contiguous(range_1, range_2) \
				and self.subtree_equal(edge_1, edge_2):
				pass

	def subtree_equal(self, e_1, e_2):
		'''
		'''
		pass

if __name__ == '__main__':

	# usage of detection and resolving
	# srp = SimpleRuleParser('./rules/example_rules_1')
	# old_rules_list = srp.rules

	a = AnomalyResolver()

	# a.detect_anomalies(old_rules_list)
	# new_rules_list = a.resolve_anomalies(old_rules_list)

	# usage of merging rules
	srp = SimpleRuleParser('./rules/example_rules_2')
	rules_list = srp.get_rules()
	
	print(a.merge_contiguous_rules(rules_list))
	
	print('\n\n')