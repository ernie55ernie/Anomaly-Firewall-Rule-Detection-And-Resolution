# Anomaly Firewall Rule Detection and Resolution
This is an implementation of the [paper](https://link.springer.com/chapter/10.1007/11805588_2), M Abedin, et al. "Detection and resolution of anomalies in firewall policy rules" for Ryu restful [firewall](https://osrg.github.io/ryu-book/en/html/rest_firewall.html#id10).

Firewall rules define the security policy for network traffic. Any error can compromise the system security by letting unwanted traffic pass or blocking desired traffic.

A rule is defined as a set of criteria and an action to perform when a packet matches a criteria. The criteria of a [Ryu restful firewall rule]((https://osrg.github.io/ryu-book/en/html/rest_firewall.html#id10)) consist of the elements VLAN, priority, input switch port, Ethernet source, Ethernet destination, Ethernet frame type, IP source, IP destination, IPv6 source, IPv6 destination, IP protocol, source port, and destination port. These are also the matching fields defined in [OpenFlow Switch Specification](https://www.opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf).

## Relation Between Two Rules

The relation between two rules is the relation between the set of packets they match. Assume a rule matches A packets and the other matches B packets.

![Rule Relation](https://raw.githubusercontent.com/ernie55ernie/Anomaly-Firewall-Rule-Detection-And-Resolution/master/img/rule_relation.png)

1. Disjoint: at least one criterion in the rules has completely disjoint values
2. Exactly Matching: every criterion in the rules match exactly
3. Inclusivly Matching: a rule and the other rule have at least one criterion which is a subset of one another and for the rest of the attribute one is equal to the other
4. Correlated: two rules are not disjoint and not inclusivly matching to one another

## Possible Anomalies Between Two Rules

1. Shadowing Anomaly: a rule is shadowed by the other if the other precedes the rule in the policy and the other can match all packets matched by the rule and they have different actions
2. Correlation Anomaly: two rules have different actions and one rule matches some packets that match the other and vice versa
3. Redundancy Anomaly: a redundant rule performs the same action on the same packets as another rule

This algorithm resolves the anomalies as follows:
- *shadowing anoamly*: When rules are *exactly matched*, keep the one with the reject action. When the rules are *inclusivly matched*, reorder the one with the reject action.
- *correlation anomaly*: Break down the rules into disjoint parts and insert them into the list. Of the part that is common to the correlated rules, keep the one with the reject action.
- *redundancy anomaly*: Remove the redundant rule.

## Illustrative Example

Firewall rules are expected in the following format: 
- priority. <direction, nw_src, tp_src, nw_dst, tp_dst, actions>
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