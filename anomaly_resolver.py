# Firewall Rule Anomaly Resolver for Ryu restfull firewall 
# https://github.com/osrg/ryu/blob/master/ryu/app/rest_firewall.py
import ctypes
import itertools
import logging
import os
import tempfile

from netaddr import IPSet, IPRange, IPNetwork, IPGlob, IPAddress
from netaddr import AddrFormatError, valid_ipv4, valid_glob, glob_to_cidrs
import networkx as nx

from utils import hierarchy_pos

STRING_TYPE = ctypes.c_wchar_p

class RuleParser():
	
	def __init__(self):
		self.rules = []

	def parse_file(self, file_name):
		pass

class SimpleRuleParser(RuleParser):

	def __init__(self, file_name):
		super(SimpleRuleParser, self).__init__()
		self.parse_file(file_name)

	def parse_file(self, file_name):
		with open(file_name, 'r', encoding='utf-8') as f:
			for line_number, raw_line in enumerate(f, start=1):
				line = raw_line.strip()
				if not line or line.startswith('#'):
					continue
				if '.' not in line or '<' not in line or '>' not in line:
					raise ValueError(
						'Invalid rule format on line %d: %s' % (line_number, raw_line.rstrip())
					)
				priority = line[:line.find('.')].strip()
				if not (priority.isascii() and priority.isdecimal()):
					raise ValueError(
						'Invalid priority on line %d: %s' % (line_number, raw_line.rstrip())
					)
				priority = int(priority)
				rule_start = line.find('<')
				rule_end = line.find('>')
				rule_string = line[rule_start + 1:rule_end]
				# Strip around each field only. Whitespace inside a field is left in
				# place so it is rejected rather than joining two tokens into one.
				fields = [field.strip() for field in rule_string.split(',')]
				if len(fields) != 7:
					raise ValueError(
						'Expected 7 rule fields on line %d, got %d: %s'
						% (line_number, len(fields), raw_line.rstrip())
					)
				try:
					rule = Rule(priority = priority,
						direction = fields[0],
						nw_proto = fields[1],
						nw_src = fields[2],
						nw_dst = fields[4],
						tp_src = fields[3],
						tp_dst = fields[5],
						actions = fields[6])
				except ValueError as exc:
					raise ValueError(
						'%s on line %d: %s' % (exc, line_number, raw_line.rstrip())
					) from exc
				self.rules.append(rule)

class Rule(ctypes.Structure):
	# https://osrg.github.io/ryu-book/en/html/rest_firewall.html#id10
	# https://www.opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf
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
		dl_type = Rule._sanity_check(dl_type, field = 'dl_type')
		nw_src = Rule._sanity_check(nw_src, field = 'ipv4')
		nw_dst = Rule._sanity_check(nw_dst, field = 'ipv4')
		nw_proto = Rule._sanity_check(nw_proto, field = 'nw_proto')
		tp_src = Rule._sanity_check(tp_src, field = 'port')
		tp_dst = Rule._sanity_check(tp_dst, field = 'port')
		direction = Rule._sanity_check(direction, field = 'direction')
		actions = Rule._sanity_check(actions, field = 'action')

		super(Rule, self).__init__(switch, vlan, priority, in_port, \
			dl_src, dl_dst, dl_type, nw_src, nw_dst, ipv6_src, ipv6_dst, \
			nw_proto, tp_src, tp_dst, \
			direction, actions)

	def _sanity_check(value, field):
		# A value that doesn't parse raises ValueError. Falling back to a default
		# would silently widen a rule, e.g. a typo'd address becoming ANY.
		if field == 'priority':
			if isinstance(value, int) and not isinstance(value, bool) and \
				0 <= value < 65536:
				return value
			raise ValueError('Invalid priority %r' % (value,))

		error = 'Invalid %s value %r' % (
			{'ipv4': 'IPv4', 'nw_proto': 'protocol'}.get(field, field), value)
		# Non-ASCII digits and letters would otherwise pass isdecimal() or map
		# onto keywords through upper(), such as a dotless i in 'ın'.
		if not isinstance(value, str) or not value.isascii() or \
			any(character.isspace() for character in value):
			raise ValueError(error)
		upper_value = value.upper()
		wildcard = upper_value in ['ANY', '*']

		if field == 'port':
			if wildcard:
				return '*'
			try:
				low, high = Rule.range_bounds('port', value)
			except ValueError:
				raise ValueError(error) from None
			if (low, high) == (0, 65535):
				return '*'
			return Rule.portrange2str(range(low, high + 1))

		if field == 'dl_type':
			dl_types = {name.upper(): name for name in ['ARP', 'IPv4', 'IPv6']}
			if upper_value in dl_types:
				return dl_types[upper_value]
			raise ValueError(error)

		if field == 'ipv4':
			if wildcard:
				return '*'
			if value.count('-') == 1:
				first, last = value.split('-')
				if last.isdecimal() and '.' in first:
					last = first[:first.rindex('.') + 1] + last
				if valid_ipv4(first) and valid_ipv4(last) and \
					IPAddress(first) <= IPAddress(last):
					return first + '-' + last
			if '/' in value:
				# Only a prefix length, on the network address itself. Mask
				# notation is ambiguous (/0.0.0.0 would mean any address), and host
				# bits usually mean a typo, like /2 for /32, that widens the rule.
				address, _, prefix = value.partition('/')
				if valid_ipv4(address) and prefix.isdecimal() and int(prefix) <= 32:
					network = IPNetwork('%s/%d' % (address, int(prefix)))
					if network.ip == network.network:
						return address if network.prefixlen == 32 else str(network.cidr)
				raise ValueError(error)
			try:
				if valid_glob(value):
					cidrs = glob_to_cidrs(value)
					if len(cidrs) > 1:
						# A glob such as 10.0.1-2.* covers several CIDR blocks.
						glob = IPGlob(value)
						return '%s-%s' % (glob[0], glob[-1])
					if cidrs[0].prefixlen == 32:
						return str(cidrs[0].ip)
					return str(cidrs[0])
			except (AddrFormatError, ValueError):
				pass
			raise ValueError(error)

		if field == 'nw_proto':
			protocols = {name.upper(): name for name in ['TCP', 'UDP', 'ICMP', 'ICMPv6']}
			if upper_value in protocols:
				return protocols[upper_value]
			raise ValueError(error)

		if field == 'direction':
			if upper_value in ['IN', 'OUT']:
				return upper_value
			raise ValueError(error)

		if field == 'action':
			if upper_value in ['DENY', 'REJECT']:
				return 'DENY'
			if upper_value in ['ALLOW', 'ACCEPT']:
				return 'ALLOW'
			raise ValueError(error)

		raise ValueError('Unknown field %r' % (field,))

	def __repr__(self, format='basic'):
		if format == 'detail':
			return '<switch:%s, vlan:%s, priority:%d, in_port:%s, dl_src:%s, dl_dst:%s,' \
					' dl_type:%s, nw_src:%s, nw_dst:%s, ipv6_src:%s, ipv6_dst:%s,' \
					' nw_proto:%s, tp_src:%s, tp_dst:%s, direction:%s, actions:%s>' \
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
			% (self.direction, self.nw_proto, self.nw_src, self.tp_src, \
				self.nw_dst, self.tp_dst, self.actions)

	def __eq__(self, rhs):
		return self.issubset(rhs) and rhs.issubset(self)

	def disjoint(self, subset_rule):
		# TODO support for
		# dl_src, dl_dst, dl_type, ipv6_src, ipv6_dst, multiple protocol
		if Rule.scopedisjoint(self.switch, subset_rule.switch) or \
			Rule.scopedisjoint(self.vlan, subset_rule.vlan) or \
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
		if Rule.scopeinrange(self.switch, subset_rule.switch) and \
			Rule.scopeinrange(self.vlan, subset_rule.vlan) and \
			Rule.portinrange(self.in_port, subset_rule.in_port) and \
			Rule.ipinrange(self.nw_src, subset_rule.nw_src) and \
			Rule.ipinrange(self.nw_dst, subset_rule.nw_dst) and \
			self.nw_proto == subset_rule.nw_proto and \
			Rule.portinrange(self.tp_src, subset_rule.tp_src) and \
			Rule.portinrange(self.tp_dst, subset_rule.tp_dst) and \
			self.direction == subset_rule.direction:
			return True
		return False

	def scopeinrange(first, second):
		# A switch or VLAN: an ID, or 'all'. Ryu installs a rule posted to
		# 'all' on every switch, or for every VLAN, so 'all' holds every ID.
		return second == 'all' or first == second

	def scopedisjoint(first, second):
		return first != second and 'all' not in (first, second)

	def portinrange(first, second):
		# Compare bounds: building sets of values took milliseconds for '*',
		# which has 65,536 of them, and every pair of rules needs several checks.
		first_low, first_high = Rule.range_bounds('port', first)
		second_low, second_high = Rule.range_bounds('port', second)
		return second_low <= first_low and first_high <= second_high

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

	def portrange2str(x):
		if len(x) > 1:
			return '%d-%d' % (x[0], x[-1])
		return str(x[0])

	def ipinrange(first, second):
		# Every IPv4 address value is one contiguous range, so bounds decide
		# this as well as IPSets did, without building them. range_bounds()
		# rejects IPv6, which IPSets kept apart from IPv4.
		first_low, first_high = Rule.range_bounds('ip', first)
		second_low, second_high = Rule.range_bounds('ip', second)
		return second_low <= first_low and first_high <= second_high

	def portdisjoint(first, second):
		first_low, first_high = Rule.range_bounds('port', first)
		second_low, second_high = Rule.range_bounds('port', second)
		return first_high < second_low or second_high < first_low

	def ipdisjoint(first, second):
		first_low, first_high = Rule.range_bounds('ip', first)
		second_low, second_high = Rule.range_bounds('ip', second)
		return first_high < second_low or second_high < first_low

	def find_attribute_set(self, subset_rule):
		'''
		The attributes to split on where the two rules differ, in a fixed order
		'''
		# A list, not a set: a set of strings iterates in an order that changes
		# with PYTHONHASHSEED, which made the resolved rules differ between
		# runs. Splitting on the destination first tends to give fewer pieces.
		attributes = ['tp_dst', 'nw_dst', 'tp_src', 'nw_src', 'in_port']
		return [attribute for attribute in attributes
			if getattr(self, attribute) != getattr(subset_rule, attribute)]

	def get_attribute_range(self, attribute, format = 'range'):
		if attribute == 'in_port' or attribute == 'tp_src' or attribute == 'tp_dst':
			if format == 'string':
				return getattr(self, attribute)
			return Rule.portstr2range(getattr(self, attribute))
		elif attribute == 'nw_src' or attribute == 'nw_dst':
			if format == 'string':
				return getattr(self, attribute)
			return Rule.ipstr2range(getattr(self, attribute))
		else:
			return getattr(self, attribute)

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
			end = str(ip_range[-1])
			return '%s-%s' % (str(ip_range[0]), end) # end[end.rindex('.') + 1:]
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
			iprange = IPRange(start, end) # start[:start.rindex('.') + 1] + 
			return iprange if format == 'range' else init(iprange)
		else:
			if format == 'range':
				network = IPNetwork(ip_str)
				return init(network[0], network[-1])
			return init([ip_str])

	def set_fields(self, other):
		for field in other._fields_:
			setattr(self, field[0], getattr(other, field[0]))

	def _range_type(attribute, r_1, r_2):
		if attribute in ['nw_src', 'nw_dst']:
			return 'ip'
		if attribute in ['in_port', 'tp_src', 'tp_dst']:
			return 'port'
		if '.' in r_1 or '.' in r_2:
			return 'ip'
		if all(value == '*' or value.isdigit() or '-' in value for value in [r_1, r_2]):
			return 'port'
		return None

	def contiguous(r_1, r_2, attribute=None):
		range_type = Rule._range_type(attribute, r_1, r_2)
		if range_type is None:
			return False
		# Compare integers: adding 1 to the IPAddress 255.255.255.255 raises
		# IndexError, which made ANY and ranges ending there crash.
		start_1, end_1 = Rule.range_bounds(range_type, r_1)
		start_2, end_2 = Rule.range_bounds(range_type, r_2)
		return end_1 + 1 == start_2 or end_2 + 1 == start_1

	def combine_range(r_1, r_2, attribute=None):
		range_type = Rule._range_type(attribute, r_1, r_2)
		if range_type == 'ip':
			range_1 = Rule.ipstr2range(r_1)
			range_2 = Rule.ipstr2range(r_2)
			return Rule.iprange2str(
				IPRange(min(range_1[0], range_2[0]), max(range_1[-1], range_2[-1]))
			)
		if range_type == 'port':
			range_1 = Rule.portstr2range(r_1)
			range_2 = Rule.portstr2range(r_2)
			return Rule.portrange2str(
				range(min(range_1[0], range_2[0]), max(range_1[-1], range_2[-1]) + 1)
			)
		return None

	def range_bounds(kind, value):
		# The first and last value of an 'ip' or 'port' range, as integers.
		# Ports are parsed directly, without portstr2range's list of values, and
		# checked as _sanity_check checks them since #3: a malformed range such
		# as '80-' raises ValueError, and a reversed one such as '10-5' is not
		# reordered.
		if kind == 'ip':
			addresses = Rule.ipstr2range(value)
			# nw_src and nw_dst hold IPv4 only. Bounds are bare integers, so an
			# IPv6 range such as '::5-::a' would compare, and split() would
			# rebuild it, as the IPv4 range 0.0.0.5-0.0.0.10.
			if addresses.version != 4:
				raise ValueError('Invalid IPv4 range %r' % (value,))
			return addresses.first, addresses.last
		if value == '*':
			return 0, 65535
		# isascii() because isdecimal() also accepts digits such as '٨٠'.
		bounds = value.split('-') if isinstance(value, str) and value.isascii() else []
		if 1 <= len(bounds) <= 2 and all(bound.isdecimal() for bound in bounds):
			low, high = int(bounds[0]), int(bounds[-1])
			if low <= high <= 65535:
				return low, high
		raise ValueError('Invalid port range %r' % (value,))

	def bounds_range(kind, start, end):
		# The range string for integer bounds, written as split() writes ranges.
		if kind == 'ip':
			return Rule.iprange2str(IPRange(start, end))
		return Rule.portrange2str(range(start, end + 1))

class AnomalyResolver:

	# TODO support for
	# dl_src, dl_dst, dl_type, ipv6_src, ipv6_dst, multiple protocol
	attr_list = ['direction', 'nw_proto', 'nw_src', 'tp_src', 'nw_dst', 'tp_dst', 'actions', 'None']
	attr_dict = {}
	tree = None

	def __init__(self, log_output = 'console', log_level = 'INFO'):

		self.attr_dict = {key: 0 for key in self.attr_list}
		self.tree = None

		self.resolver_logger = logging.getLogger('AnomalyResolver.%s' % id(self))
		self.resolver_logger.propagate = False
		self.resolver_logger.setLevel(logging.DEBUG)
		formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s' \
			' - %(message)s')
		log_level = str(log_level).upper()
		if log_level not in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'NOTSET']:
			log_level = 'INFO'
		log_level = getattr(logging, log_level)
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

		combination_list = list(itertools.combinations(enumerate(rules_list), 2))
		rule_redundant = dict()
		for (index_0, rule_0), (_, rule_1) in combination_list:
			if rule_0.disjoint(rule_1):
				continue
			if rule_0.issubset(rule_1) or rule_1.issubset(rule_0):
				if rule_0.actions == rule_1.actions:
					# A later rule inside rule_0 never matches, but rule_0 inside
					# rule_1 may still be needed because of a rule in between.
					if not rule_1.issubset(rule_0):
						if index_0 not in rule_redundant:
							rule_redundant[index_0] = self.redundant(rule_0,
								rules_list[index_0 + 1:])
						if not rule_redundant[index_0]:
							continue
					self.resolver_logger.info('Redundancy Anomaly\n\t%s\n\t%s', \
						str(rule_0), str(rule_1))
				else:
					self.resolver_logger.info('Shadowing Anomaly\n\t%s\n\t%s', \
						str(rule_0), str(rule_1))
				continue
			if not rule_0.disjoint(rule_1) and not rule_0.issubset(rule_1) and \
				not rule_1.issubset(rule_0) and rule_0.actions != rule_1.actions:
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
		scopes = self.scopes(old_rules_list)
		for switch, vlan in scopes:
			if len(scopes) > 1:
				self.resolver_logger.info('Resolving switch %s, vlan %s', switch, vlan)
			# The rules that apply on this switch and VLAN, narrowed to it. Ryu
			# installs a rule for 'all' on every switch and for every VLAN, so
			# here it is just another rule; the pieces of a rule for 'all'
			# couldn't be split by switch or VLAN anyway.
			scope_rules = list()
			for rule in old_rules_list:
				if Rule.scopeinrange(switch, rule.switch) and Rule.scopeinrange(vlan, rule.vlan):
					scope_rule = Rule()
					scope_rule.set_fields(rule)
					scope_rule.switch, scope_rule.vlan = switch, vlan
					scope_rules.append(scope_rule)
			# insert() and split() change the rules they are given, so resolve
			# copies. The narrowed rules stay unchanged and decide the action of
			# each piece afterwards; the caller's rules are never changed.
			pieces = list()
			for rule in scope_rules:
				working_rule = Rule()
				working_rule.set_fields(rule)
				self.insert(working_rule, pieces)
			self.set_actions(pieces, scope_rules)
			new_rules_list.extend(pieces)
		new_rules_list = self.remove_redundant_rules(new_rules_list)
		# TODO reassign priority
		
		self.resolver_logger.info('New rules list:\n\t' + \
			'\n\t'.join(map(str, new_rules_list)))
		self.resolver_logger.info('Finish anomalies resolving')
		return new_rules_list

	@staticmethod
	def scopes(rules_list):
		'''
		The (switch, vlan) pairs to resolve separately, most specific first
		'''
		# Each switch and VLAN that a rule names is resolved with the rules
		# for 'all' added, and 'all' stands for the ones no rule names. The
		# resolved rules for a pair decide every packet there that any rule
		# matches, so pairs with more named parts come first, and each later
		# pair only decides packets that no earlier pair covers.
		switches = sorted(set(rule.switch for rule in rules_list) - {'all'}) + ['all']
		vlans = sorted(set(rule.vlan for rule in rules_list) - {'all'}) + ['all']
		return sorted(itertools.product(switches, vlans), key=lambda scope: scope.count('all'))

	def set_actions(self, rules_list, original_rules):
		'''
		Give each rule the action of the most specific original rules containing it
		'''
		# insert() decides conflicts between pieces of rules, and a piece can be
		# inside, equal to or outside another piece when their original rules
		# are related differently. Decide each piece from the original rules
		# instead: a rule strictly inside another wins, and among rules that
		# overlap without either containing the other, DENY wins.
		for rule in rules_list:
			covering = [original for original in original_rules if rule.issubset(original)]
			if not covering:
				# Every piece comes from an original rule, so this is a bug in
				# insert() or split(), not bad input.
				raise RuntimeError('No original rule contains %s' % (rule,))
			most_specific = [original for original in covering if not any(
				other.issubset(original) and not original.issubset(other)
				for other in covering)]
			# Fail closed: only an explicit ALLOW from every most specific
			# rule allows, so an unexpected action value can't open traffic.
			actions = set(original.actions for original in most_specific)
			action = 'ALLOW' if actions == {'ALLOW'} else 'DENY'
			if rule.actions != action:
				self.resolver_logger.info('Set action of %s to %s', str(rule), action)
				rule.actions = action

	def remove_redundant_rules(self, rules_list):
		'''
		Return rules_list without the rules that later rules make redundant
		'''
		# Walk from the end so every rule is checked against the rules that
		# actually remain after it.
		kept_rules = list()
		redundant_rules = list()
		for rule in reversed(rules_list):
			if self.redundant(rule, reversed(kept_rules)):
				redundant_rules.append(rule)
			else:
				kept_rules.append(rule)
		for rule in reversed(redundant_rules):
			self.resolver_logger.info('Redundant rule %s', str(rule))
		return kept_rules[::-1]

	@staticmethod
	def redundant(rule, later_rules):
		'''
		Whether the first later rule that contains rule has the same action,
		with no overlapping rule of a different action before it
		'''
		# Stop at the first later rule that contains rule, as in the paper. An
		# overlapping rule with a different action before it would take over
		# some of rule's packets. The check is conservative: a rule covered only
		# by several later rules together is kept. Only containment matters for
		# a later rule with the same action, and any overlap for one with a
		# different action, so each later rule needs a single check.
		for later_rule in later_rules:
			if rule.actions == later_rule.actions:
				if rule.issubset(later_rule):
					return True
			elif not rule.disjoint(later_rule):
				return False
		return False


	def insert(self, r, new_rules_list):
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
		# Actions are decided afterwards by set_actions(), so only the
		# placement of the rules matters here.
		if rule.issubset(subset_rule) and subset_rule.issubset(rule):
			self.resolver_logger.info('Remove rule %s' % (str(rule),))
			return True
		if rule.issubset(subset_rule):
			self.resolver_logger.info('Reodering %s before %s' % \
				(str(rule), str(subset_rule)))
			insert_idx = self.position(new_rules_list, subset_rule)
			new_rules_list.insert(insert_idx, rule)
			return True
		if subset_rule.issubset(rule):
			return False
		subset_idx = self.position(new_rules_list, subset_rule)
		if subset_idx is not None:
			del new_rules_list[subset_idx]
		attribute_set = rule.find_attribute_set(subset_rule)

		for attribute in attribute_set:
			self.split(rule, subset_rule, attribute, new_rules_list)
		self.insert(subset_rule, new_rules_list)
		return True

	@staticmethod
	def position(rules_list, rule):
		'''
		Index of rule in rules_list, compared by identity
		'''
		# list.index and list.remove use Rule.__eq__, which ignores the action
		# and would match another rule covering the same packets.
		for index, other_rule in enumerate(rules_list):
			if other_rule is rule:
				return index
		return None

	def split(self, rule, subset_rule, attribute, new_rules_list):
		'''
		Split overlapping rules r and s based on attribute a
		'''
		self.resolver_logger.info('Overlapping rule %s, %s' % (str(rule), str(subset_rule)))
		# Integer bounds, rather than get_attribute_range's list of every port.
		kind = 'ip' if attribute in ('nw_src', 'nw_dst') else 'port'
		rule_start, rule_end = Rule.range_bounds(kind, getattr(rule, attribute))
		subset_rule_start, subset_rule_end = Rule.range_bounds(kind,
			getattr(subset_rule, attribute))

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
		self.plot_firewall_rule_tree(file_name = 'img/merged_tree.png')
		
	def construct_rule_tree(self, rule_list, plot=True):
		'''
		'''
		self.attr_dict = {key: 0 for key in self.attr_list}
		self.tree = nx.DiGraph()
		attr = self.attr_list[0]
		self.attr_dict[attr] = self.attr_dict[attr] + 1
		root_node = str(self.attr_dict[attr]) + '. ' + attr
		self.tree.add_node(root_node, attr = attr)
		for rule in rule_list:
			self.tree_insert(root_node, rule)
		if plot:
			self.plot_firewall_rule_tree()
		self.resolver_logger.debug('Nodes %s', list(self.tree.nodes()))
		self.resolver_logger.debug('Edges %s', list(self.tree.edges()))

	def get_rule_tree_root(self):
		'''
		'''
		attr_list = self.attr_list
		if self.tree:
			return '1. ' + attr_list[0]
		return None

	def plot_firewall_rule_tree(self, file_name = 'img/firewall_rule_tree.png'):
		mpl_config_dir = os.path.join(tempfile.gettempdir(), 'anomaly-resolver-mpl')
		os.makedirs(mpl_config_dir, exist_ok=True)
		os.environ.setdefault('MPLCONFIGDIR', mpl_config_dir)

		import matplotlib
		matplotlib.use('Agg')
		import matplotlib.pyplot as plt

		output_dir = os.path.dirname(file_name)
		if output_dir:
			os.makedirs(output_dir, exist_ok=True)

		figure = plt.figure(figsize = (16, 16))
		tree = self.tree
		pos = hierarchy_pos(tree)
		nx.draw(tree, pos, with_labels = True)
		nx.draw_networkx_edge_labels(tree, 
			pos, 
			rotate = False,
			edge_labels = nx.get_edge_attributes(tree, 'range'))
		figure.savefig(file_name)
		plt.close(figure)

	def tree_insert(self, node, rule):
		'''
		Inserts rule r into the node n of the rule tree
		'''
		tree = self.tree
		attr_list = self.attr_list
		attr_dict = self.attr_dict
		# Look up this node and edge only: nx.get_node_attributes and
		# get_edge_attributes build a dict of the whole tree on every call.
		attr = tree.nodes[node]['attr']
		for snode in tree.successors(node):
			edge_range = tree.edges[node, snode]['range']
			if rule.get_attribute_range(attr, format = 'string') == edge_range:
				self.tree_insert(snode, rule)
				return
		idx = attr_list.index(attr) + 1
		if idx >= len(attr_list):
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
		Merges the edges of node n whose subtrees hold the same rules
		for all edge e in n.edges:
			merge(e.node)
		group n.edges by the rules in their subtrees
		for each group:
			join the ranges that overlap or are contiguous into intervals
			keep one edge per interval, with the interval as its range
		'''
		# The paper merges exactly contiguous ranges. Joining overlapping ranges
		# too is still safe, because edges in a group lead to the same rules,
		# and it makes the result depend only on the rules: not on the order
		# they were inserted in, nor on duplicate or overlapping spellings.
		tree = self.tree
		edges = tree.edges()
		attribute = tree.nodes[n]['attr']
		for e in tree.edges([n]):
			self.merge(e[1])
		if attribute in ('nw_src', 'nw_dst'):
			kind = 'ip'
		elif attribute in ('in_port', 'tp_src', 'tp_dst'):
			kind = 'port'
		else:
			return
		groups = dict()
		for edge in tree.edges([n]):
			groups.setdefault(self.subtree_signature(edge[1]), []).append(edge)
		for group in groups.values():
			if len(group) < 2:
				continue
			# Sort by bounds, then spelling, then subtree, never by node names,
			# which depend on insertion order.
			members = sorted((Rule.range_bounds(kind, edges[edge]['range']),
				edges[edge]['range'], self.subtree_paths(edge[1]), edge) for edge in group)
			# Each interval: the members it joins and its end so far.
			intervals = list()
			for member in members:
				(start, end) = member[0]
				if intervals and start <= intervals[-1][1] + 1:
					intervals[-1][0].append(member)
					intervals[-1][1] = max(intervals[-1][1], end)
				else:
					intervals.append([[member], end])
			for joined, end in intervals:
				if len(joined) < 2:
					continue
				start = joined[0][0][0]
				nx.set_edge_attributes(tree, {joined[0][3]: Rule.bounds_range(kind, start, end)}, 'range')
				for member in joined[1:]:
					self.removing_edges = []
					self.removing_nodes = []
					self.cut_edge(member[3])
					tree.remove_edges_from(self.removing_edges)
					tree.remove_nodes_from(self.removing_nodes)

	def cut_edge(self, edge):
		'''
		'''
		tree = self.tree
		self.removing_edges.append((edge[0], edge[1]))
		for e in tree.edges([edge[1]]):
			self.cut_edge(e)
		self.removing_nodes.append(edge[1])

	def subtree_equal(self, e_1, e_2):
		'''
		Whether the subtrees below edges e_1 and e_2 hold the same rules
		'''
		return self.subtree_signature(e_1[1]) == self.subtree_signature(e_2[1])

	def subtree_signature(self, node):
		'''
		The set of rules below node, each as the tuple of ranges on its path
		'''
		# A merge can leave two sibling edges with the same range, such as a
		# second 1-10 from merging 1-5 and 6-10. Comparing sets of paths keeps
		# both, where a dict keyed by range would drop one and match different
		# subtrees. A set also ignores the order and number of copies of a rule.
		tree = self.tree
		edges = list(tree.edges([node]))
		if not edges:
			return frozenset([()])
		return frozenset((tree.edges[edge]['range'],) + path
			for edge in edges for path in self.subtree_signature(edge[1]))

	def subtree_paths(self, node):
		'''
		Every rule below node, as a sorted tuple of range tuples, repeats kept
		'''
		tree = self.tree
		edges = list(tree.edges([node]))
		if not edges:
			return ((),)
		return tuple(sorted((tree.edges[edge]['range'],) + path
			for edge in edges for path in self.subtree_paths(edge[1])))

if __name__ == '__main__':

	# usage of detection and resolving
	srp = SimpleRuleParser('./rules/example_rules_1')
	old_rules_list = srp.rules

	a = AnomalyResolver()
	a.detect_anomalies(old_rules_list)
	new_rules_list = a.resolve_anomalies(old_rules_list)

	# usage of merging rules
	srp = SimpleRuleParser('./rules/example_rules_2')
	rules_list = srp.rules

	a = AnomalyResolver()
	a.merge_contiguous_rules(rules_list)
	
	print('\n\n')
