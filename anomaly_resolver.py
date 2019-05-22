# Firewall Rule Anomaly Resolver for Ryu restfull firewall 
# https://github.com/osrg/ryu/blob/master/ryu/app/rest_firewall.py
import logging
import logging.handlers
import itertools
import ctypes
from netaddr import IPSet, IPRange, IPNetwork, cidr_merge

STRING_TYPE = ctypes.c_wchar_p

class RuleParser():
	pass

class RULE(ctypes.Structure):
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
		in_port = '0-65536', dl_src = '*', dl_dst = '*', \
		dl_type = 'IPv4', nw_src = '*', nw_dst = '*', ipv6_src = '*', \
		ipv6_dst = '*', nw_proto = 'TCP', tp_src = '0-65536', \
		tp_dst = '0-65536',direction = 'IN', actions = 'DENY', id = 0, rule_id=0):

		super(RULE, self).__init__(switch, vlan, priority, RULE._portwildcard2range(in_port), \
			dl_src, dl_dst, dl_type, nw_src, nw_dst, ipv6_src, ipv6_dst, \
			nw_proto, RULE._portwildcard2range(tp_src), RULE._portwildcard2range(tp_dst), \
			direction, actions)

	def _portwildcard2range(port):
		if port == '*':
			return '0-65536'
		return port

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

	def disjoint(self, subset_rule):
		# TODO dl_src, dl_dst, dl_type not yet implemented
		# TODO ipv6_src, ipv6_dst not yet implemented
		# TODO multiple protocol
		if not self.switch == subset_rule.switch or \
			not self.vlan == subset_rule.vlan or \
			self.portdisjoint(self.in_port, subset_rule.in_port) or \
			self.ipdisjoint(self.nw_src, subset_rule.nw_src) or \
			self.ipdisjoint(self.nw_dst, subset_rule.nw_dst) or \
			not self.nw_proto == subset_rule.nw_proto or \
			self.portdisjoint(self.tp_src, subset_rule.tp_src) or \
			self.portdisjoint(self.tp_dst, subset_rule.tp_dst) or \
			not self.direction == subset_rule.direction:
			return True
		return False

	def issubset(self, subset_rule):
		# TODO dl_src, dl_dst, dl_type not yet implemented
		# TODO ipv6_src, ipv6_dst not yet implemented
		# TODO multiple protocol
		if self.switch == subset_rule.switch and self.vlan == subset_rule.vlan and \
			self.portinrange(self.in_port, subset_rule.in_port) and \
			self.ipinrange(self.nw_src, subset_rule.nw_src) and \
			self.ipinrange(self.nw_dst, subset_rule.nw_dst) and \
			self.nw_proto == subset_rule.nw_proto and \
			self.portinrange(self.tp_src, subset_rule.tp_src) and \
			self.portinrange(self.tp_dst, subset_rule.tp_dst) and \
			self.direction == subset_rule.direction:
			return True
		return False

	def portinrange(self, first, second):
		first_set = set(self.portstr2range(first))
		second_set = set(self.portstr2range(second))
		return first_set.issubset(second_set)

	def portstr2range(self, x):
		res = list()
		if '-' in x:
			first, second = x.split('-')
			first, second = int(first), int(second)
			res.extend(range(first, second + 1))
		else:
			num = int(x)
			res.append(num)
		return res

	def ipinrange(self, first, second):
		first_set = self.ipstr2range(first, format='set')
		second_set = self.ipstr2range(second, format='set')
		return first_set.issubset(second_set)

	def portdisjoint(self, first, second):
		if first == '0-65535' or second == '0-65535':
			return False
		first_set = set(self.portstr2range(first))
		second_set = set(self.portstr2range(second))
		return not first_set.intersection(second_set)

	def ipdisjoint(self, first, second):
		if first == '0.0.0.0/0' or second == '0.0.0.0/0':
			return False
		first_set = self.ipstr2range(first, format='set')
		second_set = self.ipstr2range(second, format='set')
		return not first_set.intersection(second_set)

	def find_attribute_set(self, subset_rule):
		attribute_set = set()
		for field in self._fields_:
			if not getattr(self, field[0]) == getattr(subset_rule, field[0]) and \
				(field[0] == 'in_port' or field[0] == 'nw_src' or 
				field[0] == 'nw_dst' or field[0] == 'tp_src' or field[0] == 'tp_dst'):
				attribute_set.add(field[0])
		return attribute_set

	def get_attribute_range(self, attribute):
		if attribute == 'in_port' or attribute == 'tp_src' or attribute == 'tp_dst':
			return self.portstr2range(getattr(self, attribute))
		else:
			return self.ipstr2range(getattr(self, attribute))

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
			new_range = self.iprange2str(new_range)
			setattr(self, attribute, new_range)

	def iprange2str(self, ip_range):
		if len(ip_range) > 1:
			return '%s-%s/32' % (str(ip_range[0]), str(ip_range[-1]))
		else:
			return str(ip_range[0])

	def ipstr2range(self, ip_str, format='range'):
		if ip_str == '*' or ip_str.upper() == 'ANY':
			ip_str = '0.0.0.0/0'
		init = IPRange if format == 'range' else IPSet
		if '-' in ip_str:
			start, end = ip_str.split('-')
			iprange = IPRange(start, end[:-3])
			return iprange if format == 'range' else init(iprange)
		else:
			if format == 'range':
				network = IPNetwork(ip_str)
				return init(network[0], network[-1])
			return init([ip_str])

	def set_fields(self, other):
		for field in other._fields_:
			setattr(self, field[0], getattr(other, field[0]))

class AnomalyResolver:

	def __init__(self, log_output = 'console', log_level = 'INFO'):

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
		if not new_rules_list:
			new_rules_list.append(rule)
		else:
			inserted = False
			for subset_rule in new_rules_list:

				if not rule.disjoint(subset_rule):
					inserted = self.resolve(rule, subset_rule, new_rules_list)
					if inserted:
						break
			if not inserted:
				new_rules_list.append(rule)

	def resolve(self, rule, subset_rule, new_rules_list):

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
			copy_rule = RULE()
			copy_rule.set_fields(subset_rule)
			copy_rule.set_attribute_range(attribute, left, common_start, -1)
			self.insert(copy_rule, new_rules_list)
		elif rule_start < subset_rule_start:
			copy_rule = RULE()
			copy_rule.set_fields(rule)
			copy_rule.set_attribute_range(attribute, left, common_start, -1)
			self.insert(copy_rule, new_rules_list)
		if rule_end > subset_rule_end:
			copy_rule = RULE()
			copy_rule.set_fields(rule)
			copy_rule.set_attribute_range(attribute, common_end, right, 1)
			self.insert(copy_rule, new_rules_list)
		elif rule_end < subset_rule_end:
			copy_rule = RULE()
			copy_rule.set_fields(subset_rule)
			copy_rule.set_attribute_range(attribute, common_end, right, 1)
			self.insert(copy_rule, new_rules_list)
		rule.set_attribute_range(attribute, common_start, common_end, 0)
		subset_rule.set_attribute_range(attribute, common_start, common_end, 0)
		# TODO

if __name__ == '__main__':
	a = AnomalyResolver()
	old_rules_list = list()
	old_rules_list.append(RULE(priority = 1, nw_proto = 'TCP', nw_src = '129.110.96.117/32', \
		tp_dst = '80', actions = 'DENY'))
	old_rules_list.append(RULE(priority = 2, nw_proto = 'TCP', nw_src = '129.110.96.0/24', \
		tp_dst = '80', actions = 'ALLOW'))
	old_rules_list.append(RULE(priority = 3, nw_proto = 'TCP', nw_dst = '129.110.96.80/32', \
		tp_dst = '80', actions = 'ALLOW'))
	old_rules_list.append(RULE(priority = 4, nw_proto = 'TCP', nw_src = '129.110.96.0/24', \
		nw_dst = '129.110.96.80/32', tp_dst = '80', actions = 'DENY'))
	old_rules_list.append(RULE(priority = 5, nw_proto = 'TCP', nw_src = '129.110.96.80/32', \
		tp_src = '22', actions = 'DENY' ,direction = 'out'))
	old_rules_list.append(RULE(priority = 6, nw_proto = 'TCP', nw_src = '129.110.96.117/32', \
		nw_dst = '129.96.96.80/32', tp_dst = '80', actions = 'DENY'))
	old_rules_list.append(RULE(priority = 7, nw_proto = 'UDP', nw_src = '129.110.96.117/32', \
		nw_dst = '129.110.96.0/24', tp_dst = '22', actions = 'DENY'))
	old_rules_list.append(RULE(priority = 8, nw_proto = 'UDP', nw_src = '129.110.96.117/32', \
		nw_dst = '129.110.96.80/32', tp_dst = '22', actions = 'DENY'))
	old_rules_list.append(RULE(priority = 9, nw_proto = 'UDP', nw_src = '129.110.96.117/32', \
		nw_dst = '129.110.96.117/32', tp_dst = '22', actions = 'ALLOW'))
	old_rules_list.append(RULE(priority = 10, nw_proto = 'UDP', nw_src = '129.110.96.117/32', \
		nw_dst = '129.110.96.117/32', tp_dst = '22', actions = 'DENY'))
	old_rules_list.append(RULE(priority = 11, nw_proto = 'UDP', actions = 'DENY', \
		direction = 'out'))

	a.detect_anomalies(old_rules_list)
	new_rules_list = a.resolve_anomalies(old_rules_list)
	print('\n\n')