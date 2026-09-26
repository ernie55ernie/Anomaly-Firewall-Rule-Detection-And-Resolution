# Anomaly Firewall Rule Detection and Resolution
This is an implementation of the [paper](https://link.springer.com/chapter/10.1007/11805588_2), M Abedin, et al. "Detection and resolution of anomalies in firewall policy rules" for Ryu restful [firewall](https://osrg.github.io/ryu-book/en/html/rest_firewall.html#id10).

Firewall rules define the security policy for network traffic. Any error can compromise the system security by letting unwanted traffic pass or blocking desired traffic.

> [!WARNING]
> Resolution applies the policy described below rather than keeping the input's first-match decisions, so a specific rule can override a broader one listed before it. Merging still has open bugs, including one that can drop a DENY rule. Review resolved and merged rules before using them. See [Known Issues](#known-issues).

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
- protocol: `TCP`, `UDP`, `ICMP` or `ICMPv6`
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
After anomaly resolving, the list is free from anomalies.
```
        <IN, TCP, 129.110.96.0/24, *, 129.110.96.81-255.255.255.255, 80, ALLOW>
        <IN, TCP, 129.110.96.0/24, *, 0.0.0.0-129.110.96.79, 80, ALLOW>
        <IN, TCP, 129.110.96.117, *, 0.0.0.0-129.110.96.79, 80, DENY>
        <IN, TCP, 129.110.96.0-129.110.96.116, *, 129.110.96.80, 80, ALLOW>
        <IN, TCP, 0.0.0.0-129.110.95.255, *, 129.110.96.80, 80, ALLOW>
        <IN, TCP, 129.110.97.0-255.255.255.255, *, 129.110.96.80, 80, ALLOW>
        <IN, TCP, 129.110.96.118-129.110.96.255, *, 129.110.96.80, 80, ALLOW>
        <IN, TCP, 129.110.96.0/24, *, 129.110.96.80, 80, DENY>
        <OUT, TCP, 129.110.96.80, 22, *, *, DENY>
        <IN, TCP, 129.110.96.117, *, 129.110.96.80, 22, DENY>
        <IN, UDP, 129.110.96.117, *, 129.110.96.0/24, 22, DENY>
        <OUT, UDP, *, *, *, *, DENY>
```

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

## Known Issues
An audit of commit `67b819b` found the problems below. Each one was reproduced by running the code. The critical and high ones are tracked as GitHub issues, each with repro steps and a suggested fix.

### Critical and high
| Severity | Problem | Where | Issue |
|---|---|---|---|
| Critical | Merging can delete a DENY rule when two sibling edges have the same range | `subtree_equal` | [#5](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/5) |
| High | The resolved rule list changes shape between runs (depends on `PYTHONHASHSEED`); its decisions no longer do | `find_attribute_set` | [#6](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/6) |
| High | `--merge` raises `KeyError` at tree nodes with 3 or more children | `merge` | [#7](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/7) |
| High | `--merge` crashes on IP ranges ending at 255.255.255.255, including `rules/example_rules_1` | `Rule.contiguous` | [#8](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/8) |
| High | Detection and resolution are slow: each wildcard port check builds a 65,536-element set | `Rule.portstr2range` | [#10](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/10) |

Fixed since the audit:
- [#2](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/2) (Critical): redundancy removal no longer deletes a rule when an overlapping rule with a different action comes before the rule that contains it.
- [#3](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/3) (Critical): values that don't parse are rejected with an error naming the line, instead of being read as `ANY`, TCP, `IN` or `DENY`.
- [#9](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/9) (High): `ICMPv6` and `dl_type` `IPv6` are kept instead of being read as TCP and IPv4.
- [#4](https://github.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/issues/4) (Critical): resolution decides each piece from the original rules that contain it, so a piece can no longer override the reject decision on a correlated overlap. Resolution also works on copies, so the caller's rules are no longer changed.

### Medium
- `detect_anomalies` ignores rule order. A specific rule placed before a general one is reported as shadowing, although the paper calls that generalization, not an anomaly. The function also returns nothing.
- `--merge` runs on unresolved rules, but the rule tree ignores order, so the merged result may not match any ordering of the input.
- The parser ignores text after `>`, so a second rule on the same line is lost.
- The rule tree compares ranges as text, so `x.x.x.0/24` and `x.x.x.0-x.x.x.255` never merge.
- Each `AnomalyResolver` gets a logger named after `id(self)`. Python reuses ids, so handlers pile up and later instances log every line several times.
- `python -m unittest` run from the repository root finds 0 tests (use `python -m unittest discover -s tests`). Resolution, input checking and the redundancy reports of detection are tested; the rest of detection and merging have no tests.
- The resolved list in [Illustrative Example of the Resolve Algorithm](#illustrative-example-of-the-resolve-algorithm) is out of date and contains shadowing anomalies itself.

### Low
- The rule priority is parsed but ignored: file order decides, whereas in Ryu the higher priority wins. Resolved rules keep duplicate priorities.
- Results appear only as INFO log lines. `main.py` discards the return value, and merging only produces PNG images.
- Running `--merge` or `python anomaly_resolver.py` from the repository root overwrites the committed images in `img/`.
- `main.py` prints a raw traceback for a missing file or a parse error.
- `Rule` subclasses `ctypes.Structure`. Assigning an int to a string field (`rule.tp_dst = 80`) crashes the interpreter, and rules can't be copied, pickled or put in sets.
- `switch` or `vlan` set to `'all'` is treated as disjoint from a specific value. ICMP rules that have ports are treated as port-specific. A rules file with a UTF-8 BOM is rejected.
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
- [ ] Support for handling dl_src, dl_dst, dl_type, ipv6_src, ipv6_dst, multiple nw_proto
- [ ] Output resolved and merged rules to firewall rules file

### More about this program
Detailed descrptions about this program is in this blog post [Anomaly Firewall Rule Detection and Resolution](https://ernie55ernie.github.io/python/2019/06/09/anomaly-firewall-rule-detection-and-resolution.html).