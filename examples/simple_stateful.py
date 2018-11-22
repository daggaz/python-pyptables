from pyptables import default_tables, restore
from pyptables.rules import Rule, Accept

# get a default set of tables and chains
tables = default_tables()

# get the forward chain of the filter tables
forward = tables['filter']['FORWARD']

# any packet matching an established connection should be allowed
forward.append(Accept(match='conntrack', ctstate='ESTABLISHED'))

# add rules to the forward chain for DNS, HTTP and HTTPS ports
forward.append(Accept(proto='tcp', dport='53'))
forward.append(Accept(proto='tcp', dport='80'))
forward.append(Accept(proto='tcp', dport='443'))

# any packet not matching a rules will be dropped
forward.policy = Rule.DROP

# write the rules into the kernel
restore(tables)

print(tables.to_iptables())
