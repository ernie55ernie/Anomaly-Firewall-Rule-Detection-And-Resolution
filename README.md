# Anomaly Firewall Rule Detection and Resolution
This is an implementation of the [paper](https://link.springer.com/chapter/10.1007/11805588_2), M Abedin, et al. "Detection and resolution of anomalies in firewall policy rules" for Ryu restful [firewall](https://osrg.github.io/ryu-book/en/html/rest_firewall.html#id10).

Firewall rules define the security policy for network traffic. Any error can compromise the system security by letting unwanted traffic pass or blocking desired traffic.

> [!WARNING]
> Resolution applies the policy described below rather than keeping the input's first-match decisions, so a specific rule can override a broader one listed before it. Merging is a separate step: `--merge` works on the rules as given, whether or not they have been resolved, so a completed merge doesn't mean the rules are free of anomalies. Review resolved and merged rules before using them. See [Known Issues](#known-issues).

- [Usage](#usage)
- [Relation Between Two Rules](#relation-between-two-rules)
- [Possible Anomalies Between Two Rules](#possible-anomalies-between-two-rules)
- [Illustrative Example of the Resolve Algorithm](#illustrative-example-of-the-resolve-algorithm)
- [Illustrative Example of the Merge Algorithm](#illustrative-example-of-the-merge-algorithm)
- [Known Issues](#known-issues)
- [Task List](#task-list)
- [More about this program](#more-about-this-program)

## Usage
```
usage: main.py [-h] [--path PATH] [--detect] [--resolve] [--merge]

Anomaly Firewall Rule Detection and Resolution

optional arguments:
  -h, --help   show this help message and exit
  --path PATH  path of firewall rules file
  --detect     detect anomaly firewall rule
  --resolve    resolve anomaly firewall rule
  --merge      merge contiguous firewall rule
```
- Install dependency
```
pip install -r requirements.txt
```
- This will run the demo program
```
python anomaly_resolver.py
```
- This will perform anomaly detection
```
python main.py --path rules/example_rules_1 --detect
```
- This will perform anomaly resolving
```
python main.py --path rules/example_rules_1 --resolve
```
- This will perform rule merging
```
python main.py --path rules/example_rules_2 --merge
```

## Relation Between Two Rules

A rule is defined as a set of criteria and an action to perform when a packet matches a criteria. The criteria of a [Ryu restful firewall rule]((https://osrg.github.io/ryu-book/en/html/rest_firewall.html#id10)) consist of the elements VLAN, priority, input switch port, Ethernet source, Ethernet destination, Ethernet frame type, IP source, IP destination, IPv6 source, IPv6 destination, IP protocol, source port, and destination port. These are also the matching fields defined in [OpenFlow Switch Specification](https://www.opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf).

The relation between two rules is the relation between the set of packets they match. Assume a rule matches A packets and the other matches B packets.

![Rule Relation](https://raw.githubusercontent.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/master/img/rule_relation.png)

1. Disjoint: at least one criterion in the rules has completely disjoint values
2. Exactly Matching: every criterion in the rules match exactly
3. Inclusively Matching: a rule and the other rule have at least one criterion which is a subset of one another and for the rest of the attribute one is equal to the other
4. Correlated: two rules are not disjoint and not inclusively matching to one another

## Possible Anomalies Between Two Rules

1. Shadowing Anomaly: a rule is shadowed by the other if the other precedes the rule in the policy and the other can match all packets matched by the rule and they have different actions
2. Correlation Anomaly: two rules have different actions and one rule matches some packets that match the other and vice versa
3. Redundancy Anomaly: a redundant rule performs the same action on the same packets as another rule

This algorithm resolves the anomalies as follows:
- *shadowing anomaly*: When rules are *exactly matched*, keep the one with the reject action. When the rules are *inclusively matched*, the more specific rule wins, whatever its action and position.
- *correlation anomaly*: Break down the rules into disjoint parts and insert them into the list. Of the part that is common to the correlated rules, keep the one with the reject action.
- *redundancy anomaly*: Remove the redundant rule.

In general, each packet is decided by the original rules that match it. A rule that lies strictly inside another matching rule wins over it, and among the rules left, which overlap without nesting, reject wins. The order of the input rules doesn't affect these decisions.

## Illustrative Example of the Resolve Algorithm

Firewall rules are expected in the following format:
- priority. <direction, protocol, source IP, source port, destination IP, destination port, action>

Accepted values, which are case-insensitive ASCII with no whitespace inside:
- direction: `IN` or `OUT`
- protocol: `TCP`, `UDP`, `ICMP` or `ICMPv6`. The addresses in this format are IPv4, but ICMPv6 runs over IPv6 only. So an `ICMPv6` line with `ANY` source and destination is read as an IPv6 rule, because its protocol alone decides the network family. An `ICMPv6` line with an IPv4 address is rejected.
- IP: `ANY` or `*`, an address (`10.0.0.1`), a CIDR block (`10.0.0.0/24`), a range (`10.0.0.1-10.0.0.9` or `10.0.0.1-9`), or a glob (`10.0.0.*`). A CIDR block needs a prefix length from 0 to 32 on the network address itself: `10.0.0.5/24` and mask notation such as `10.0.0.0/255.255.255.0` are rejected.
- port: `ANY` or `*`, a port (`80`) or a range (`1000-2000`), within 0-65535
- action: `ACCEPT` or `ALLOW`, `REJECT` or `DENY`

Any other value is rejected with an error that names the line.
```
1. <IN, TCP, 129.110.96.117, ANY, ANY, 80, REJECT>
2. <IN, TCP, 129.110.96.*, ANY, ANY, 80, ACCEPT>
3. <IN, TCP, ANY, ANY, 129.110.96.80, 80, ACCEPT>
4. <IN, TCP, 129.110.96.*, ANY, 129.110.96.80, 80, REJECT>
5. <OUT, TCP, 129.110.96.80, 22, ANY, ANY, REJECT>
6. <IN, TCP, 129.110.96.117, ANY, 129.110.96.80, 22, REJECT>
7. <IN, UDP, 129.110.96.117, ANY, 129.110.96.*, 22, REJECT>
8. <IN, UDP, 129.110.96.117, ANY, 129.110.96.80, 22, REJECT>
9. <IN, UDP, 129.110.96.117, ANY, 129.110.96.117, 22, ACCEPT>
10. <IN, UDP, 129.110.96.117, ANY, 129.110.96.117, 22, REJECT>
11. <OUT, UDP, ANY, ANY, ANY, ANY, REJECT>
```
After anomaly resolving, the list is free from anomalies as the paper defines them. This is the output of `python main.py --path rules/example_rules_1 --resolve`, which is the same on every run:
```
        <IN, TCP, 129.110.96.117, *, 0.0.0.0-129.110.96.79, 80, DENY>
        <IN, TCP, 129.110.96.117, *, 129.110.96.81-255.255.255.255, 80, DENY>
        <IN, TCP, 129.110.96.0/24, *, 0.0.0.0-129.110.96.79, 80, ALLOW>
        <IN, TCP, 129.110.96.0/24, *, 129.110.96.81-255.255.255.255, 80, ALLOW>
        <IN, TCP, 0.0.0.0-129.110.95.255, *, 129.110.96.80, 80, ALLOW>
        <IN, TCP, 129.110.97.0-255.255.255.255, *, 129.110.96.80, 80, ALLOW>
        <IN, TCP, 129.110.96.0/24, *, 129.110.96.80, 80, DENY>
        <OUT, TCP, 129.110.96.80, 22, *, *, DENY>
        <IN, TCP, 129.110.96.117, *, 129.110.96.80, 22, DENY>
        <IN, UDP, 129.110.96.117, *, 129.110.96.0/24, 22, DENY>
        <OUT, UDP, *, *, *, *, DENY>
```
Running `--detect` on this list still reports two "Shadowing Anomaly" entries: the first and second rules, for host `129.110.96.117`, each come before the matching broader `129.110.96.0/24` rule, with a different action. A specific rule placed before a broader one like this is what the paper calls a generalization, which is not an anomaly. `--detect` reports it as shadowing because it doesn't yet take rule order into account (see [Known Issues](#known-issues)).

Rules built in code can also name a switch or a VLAN. The rules file has neither, so parsed rules apply to `all`. As in Ryu, a rule for `all` applies on every switch and for every VLAN. So it overlaps a rule for one switch, and the rule for one switch is the more specific of the two. Resolution can't split a rule for `all` into one switch and the rest. Instead it resolves each switch and VLAN that some rule names separately, with working copies of the rules for `all` narrowed to it, and then the rules for `all` for the switches and VLANs that no rule names. The copies only place the pieces: each piece's action still comes from the original rules, with the switch and VLAN they were written for. The output lists the more specific rules first. Every named switch and VLAN gets a copy of the rules for `all`, so the number of resolved rules can multiply (see [Known Issues](#known-issues)).

In code, `Rule()` also takes an Ethernet type in `dl_type` (`ARP`, `IPv4` or `IPv6`), MAC addresses in `dl_src` and `dl_dst`, and IPv6 addresses in `ipv6_src` and `ipv6_dst`. The rules file has none of these, so parsed rules are IPv4 rules for any MAC or IPv6 address.
- A MAC address is `*` or six pairs of hex digits separated by colons. It is stored in lower case, so each address has one spelling.
- An IPv6 value is `*`, an address, a range, or a CIDR block on its network address. It is stored in compressed form, and a zone such as `%eth0` is rejected.
- IPv4 addresses and `ICMP` need `dl_type` `IPv4`, the default. IPv6 addresses and `ICMPv6` need `dl_type` `IPv6`. A rule that mixes the two families, or whose `dl_type` doesn't match them, could match nothing, so it is rejected. This doesn't cover ARP yet: ARP rules still carry a protocol and ports, which don't apply to ARP ([#36](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/36)).
- Rules for different Ethernet types never overlap.
- IPv6 ranges are compared and split like IPv4 ranges.
- MAC addresses are handled like switches: `*` holds every address, and each MAC address that a rule names is resolved separately.

## Illustrative Example of the Merge Algorithm
```
1. <IN, TCP, 202.80.169.29-63, 483, 129.110.96.64-127, 100-110, ACCEPT>
2. <IN, TCP, 202.80.169.29-63, 483, 129.110.96.64-127, 111-127, ACCEPT>
3. <IN, TCP, 202.80.169.29-63, 483, 129.110.96.128-164, 100-127, ACCEPT>
4. <IN, TCP, 202.80.169.29-63, 484, 129.110.96.64-99, 100-127, ACCEPT>
5. <IN, TCP, 202.80.169.29-63, 484, 129.110.96.100-164, 100-127, ACCEPT>
6. <IN, TCP, 202.80.169.64-110, 483-484, 129.110.96.64-164, 100-127, ACCEPT>
```
From this rules list, we can generate the tree:
![Tree generated from the example rules list](https://raw.githubusercontent.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/master/img/firewall_rule_tree.png)
On this tree, the merge function is run and the result of the merged tree:
![Result of merged tree](https://raw.githubusercontent.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/master/img/merged_tree.png)

At each node, the paper merges two sibling edges when their ranges are exactly contiguous and their subtrees are equal. This implementation extends that rule: sibling edges whose subtrees hold the same rules are joined wherever their ranges overlap or touch, and each group becomes the smallest set of disjoint ranges that covers it. Siblings leading to different rules are never joined. Joining overlapping ranges this way doesn't change which packets each action applies to, and it makes the merged rules depend only on the rules themselves, not on the order they were inserted in or on duplicate or overlapping ranges.

## Known Issues
An audit of commit `67b819b` found the problems below. Each one was reproduced by running the code. The critical and high ones are tracked as GitHub issues, each with repro steps and a suggested fix.

### Critical and high
None are open. Fixed since the audit:
- [#2](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/2) (Critical): redundancy removal no longer deletes a rule when an overlapping rule with a different action comes before the rule that contains it.
- [#3](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/3) (Critical): values that don't parse are rejected with an error naming the line, instead of being read as `ANY`, TCP, `IN` or `DENY`.
- [#9](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/9) (High): `ICMPv6` and `dl_type` `IPv6` are no longer read as TCP and IPv4. Since [#15](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/15), an `ICMPv6` line in a rules file is an IPv6 rule, and one with an IPv4 address is rejected.
- [#4](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/4) (Critical): resolution decides each piece from the original rules that contain it, so a piece can no longer override the reject decision on a correlated overlap. Resolution also works on copies, so the caller's rules are no longer changed.
- [#5](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/5) (Critical): merging compares the full set of rules below two sibling edges, including children that share a range, so it no longer drops a rule.
- [#6](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/6) (High): rules are split on their attributes in a fixed order, so resolving gives the same rules on every run instead of depending on `PYTHONHASHSEED`.
- [#7](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/7) (High): merging groups sibling edges whose subtrees hold the same rules and joins their ranges wherever they overlap or touch, so it no longer raises `KeyError` at nodes with three or more children. The merged rules depend only on the rules themselves, not on the order they were inserted in.
- [#8](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/8) (High): `Rule.contiguous` compares integer bounds, so it no longer raises `IndexError` on ANY or on ranges that end at 255.255.255.255, and it gives the same answer in either argument order. Merging stopped calling it in #7's fix, so `--merge` already no longer crashed.
- [#10](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/10) (High): port and address checks compare the first and last value of each range instead of building sets of values, where `*` meant 65,536 ports. Building the rule tree reads each edge directly instead of copying every edge at each step. On rules like those in the issue, detecting anomalies in 100 rules takes about 0.06 s instead of 16 s, and building the tree for 400 rules about 0.02 s instead of 15 s.

### Medium
- `detect_anomalies` ignores rule order. A specific rule placed before a general one is reported as shadowing, although the paper calls that generalization, not an anomaly. The function also returns nothing.
- `--merge` runs on unresolved rules, but the rule tree ignores order, so the merged result may not match any ordering of the input.
- The parser ignores text after `>`, so a second rule on the same line is lost.
- The rule tree compares ranges as text, so `x.x.x.0/24` and `x.x.x.0-x.x.x.255` never merge.
- The rule tree ignores `switch`, `vlan`, `in_port`, `dl_type`, `dl_src`, `dl_dst`, `ipv6_src` and `ipv6_dst`. So `--merge` treats rules built in code that differ only in these fields as the same. Parsed rules never set them.
- Resolution copies every rule for `all`, and every rule for any MAC address, into each switch, VLAN and MAC address that some rule names, even rules that overlap nothing specific to it. `example_rules_1` plus 10 switch-specific and 10 VLAN-specific host rules resolves to 511 rules in 2.2 s ([#33](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/33)).
- Each `AnomalyResolver` gets a logger named after `id(self)`. Python reuses ids, so handlers pile up and later instances log every line several times.
- `python -m unittest` run from the repository root finds 0 tests (use `python -m unittest discover -s tests`). Resolution, merging and input checking are tested. Detection is tested for its redundancy reports, and for shadowing and correlation across switches; its other reports have no tests.

### Low
- The rule priority is parsed but ignored: file order decides, whereas in Ryu the higher priority wins. Resolved rules keep duplicate priorities.
- Results appear only as INFO log lines. `main.py` discards the return value, and merging only produces PNG images.
- Running `--merge` or `python anomaly_resolver.py` from the repository root overwrites the committed images in `img/`.
- `main.py` prints a raw traceback for a missing file or a parse error.
- `Rule` subclasses `ctypes.Structure`. Assigning an int to a string field (`rule.tp_dst = 80`) crashes the interpreter, and rules can't be copied, pickled or put in sets.
- Switch and VLAN IDs are compared as given. `'1'` and `'0000000000000001'` are different switches, and only the exact `'all'` means every switch or VLAN.
- ICMP rules that have ports are treated as port-specific. A rules file with a UTF-8 BOM is rejected.
- Plotting switches the global matplotlib backend and uses a predictable shared temp directory.
- `requirements.txt` needs Python 3.11 or later, which isn't documented, and lists `pydot`, which is never used.
- This README: the Usage block is out of date, the Ryu firewall link in [Relation Between Two Rules](#relation-between-two-rules) is broken, and the blog post link returns 404.
- `utils.hierarchy_pos` is licensed CC BY-SA (it comes from Stack Overflow), while the repository is licensed CC BY 4.0.

## Task List
- [x] A parser from firewall rule file to Rules
- [x] resolve_anomalies function which resolves anomalies in firewall rules file
- [x] insert function which inserts the rule r into new_rules_list
- [x] resolve function which resolves anomalies between two rules r and s
- [x] split function which split overlapping rules r and s based on attribute a
- [x] tree_insert function which inserts rule r into the node n of the rule tree
- [x] merge function which merges edges of node n representing a continuous range
- [ ] IP range representation to multiple CIDR representations
- [x] Support for handling dl_src, dl_dst, dl_type, ipv6_src, ipv6_dst
- [ ] Support for multiple nw_proto
- [ ] Output resolved and merged rules to firewall rules file

### More about this program
Detailed descrptions about this program is in this blog post [Anomaly Firewall Rule Detection and Resolution](https://ernie55ernie.github.io/python/2019/06/09/anomaly-firewall-rule-detection-and-resolution.html).