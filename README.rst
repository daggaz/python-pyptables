================
python-pyptables
================

Python package for generating Linux iptables configurations.

**************
About Iptables
**************

Iptables is part of the Linux kernel, and is responsible for network packet filtering and manipulation.  It is commonly used for building Linux-based firewalls.  As packets traverse the Linux network stack, the kernel uses the rules defined in iptables decide what to do with the packet.

Using iptables involves configuring the rules that are contained in iptables.  Each table is composed of chains of rules.  Chains come in two flavours: built-in and user-defined.  A built-in chain is an entry point into the iptables rule set that is consulted by the kernel when packet reaches at a certain point in the Linux networking stack.  For example, the ``tables['filter']['OUTPUT']`` chain is consulted when a local process on the machine generates an outgoing packet.and each table/chain is consulted at different points in the network stack.  User-defined chains are only consulted if called from one of the built-in chains (or from another user chain the is called from a built-in chain).

Chains are then made up of an ordered set of rules.  A rule is composed of a set matching parameters (e.g. protocol, destination IP address/port, and many more), and an action (e.g. allow, drop, reject, log, modify the packet).  When ever a packet matches a rule, the corresponding action is taken.

***************
About PyPTables
***************

PyPTables is a python package to allow the generation of a set of iptables rules from a python script.

Basic usage
===========

The following code will create a simple set of rules for a stateful firewall allowing only HTTP, HTTPS and DNS traffic to be routed though the box:

  ::

    from pyptables import default_tables, restore
    from pyptables.rules import Rule, Accept

    # get a default set of tables and chains
    tables = default_tables()
    
    # get the forward chain of the filter tables
    forward = tables['filter']['FORWARD']

    # any packet matching an established connection should be allowed
    forward.append(Accept(match='conntrack', ctstate='ESTABLISHED')

    # add rules to the forward chain for DNS, HTTP and HTTPS ports
    forward.append(Accept(proto='tcp', dport='53'))
    forward.append(Accept(proto='tcp', dport='80'))
    forward.append(Accept(proto='tcp', dport='443'))

    # any packet not matching a rules will be dropped
    forward.policy = Rule.DROP

Rules in this case are added to the iptables ``fitler`` table (for packet filtering), in the ``FORWARD`` chain (for routed or bridged packets, going to and from external sources).

You can write the resulting rules into the kernel with the restore function:

  ::
    
    restore(tables)

Or you can use the ``tables.to_iptables()`` function to generate the resulting iptables commands as a string.

Tables
======

The top-level container in PyPTables is the ``Tables`` class, which represents a collection of iptables (i.e. filter, mangle, nat).  For the most part, you will want to start with a call to ``default_tables()``, which will create a basic structure of tables and chains that represent the built-in tables and chains available in the Linux kernel.

``Tables`` is a dictionary-like structure, and is indexable by table name using the ``[]`` operator:

  ::

    tables = default_tables()
    table = tables['filter']

An individual table is represented by the ``Table`` class, with contains a collection of chains (i.e. INPUT, OUTPUT, FORWARD).  This is also a dictionary-like structure, and is indexable by chain name using the ``[]`` operator:

  ::

    chain = tables['filter']['INPUT']

Chains
======

Chains hold an ordered list of rules.  As mentioned earlier, chains come in two flavours: built-in and user.  In PyPTables, these are represented by the ``BuiltinChain`` and ``UserChain`` classes respectively.  The only difference between ``BuiltinChain`` and ``UserChain`` chain is that a ``BuiltinChain`` has as default policy, which is enacted when no rule in the chain has matched and dealt with the packet.

The ``Chain`` classes are list-like structures, and most standard python list operations can be used on them (i.e. ``append(rule)``, ``remove(rule)``, ``insert(rule, position)``)  for example:

  :: 

    tables['filter']['INPUT'].append(Rule(...))
    tables['filter']['INPUT'].insert(Rule(...), 0)
    
For illustration of how the ``Tables``, ``Table`` and ``BuiltinChain`` classes are used, here is the code that implements ``default_tables()``:

  ::

    def default_tables():
        """Generate a set of iptables containing all the default tables and chains"""
        
        return Tables(Table('filter',
                            BuiltinChain('INPUT', 'ACCEPT'),
                            BuiltinChain('FORWARD', 'ACCEPT'),
                            BuiltinChain('OUTPUT', 'ACCEPT'),
                            ),
                      Table('nat',
                            BuiltinChain('PREROUTING', 'ACCEPT'),
                            BuiltinChain('OUTPUT', 'ACCEPT'),
                            BuiltinChain('POSTROUTING', 'ACCEPT'),
                            ),
                      Table('mangle',
                            BuiltinChain('PREROUTING', 'ACCEPT'),
                            BuiltinChain('INPUT', 'ACCEPT'),
                            BuiltinChain('FORWARD', 'ACCEPT'),
                            BuiltinChain('OUTPUT', 'ACCEPT'),
                            BuiltinChain('POSTROUTING', 'ACCEPT'),
                            ),
                      )

You can of course choose not to use the ``default_tables()`` function, and create the basic tables structure yourself.  This would be needed if for example you want to use ip6tables, or use non-standard tables.

Rules
=====

The ``Rule`` class represents an actual iptables rule.  Rules are created using a simple, pythonic syntax, and can then be added to a chain.  For example, the following call will produce a rule which matches traffic destined for tcp port 22 (SSH) and rejects it:

  ::

    reject_ssh = Rule(proto='tcp', dport='22', jump='REJECT')

We can then add that to the INPUT chain of the filter tables, to prevent access to SSH port on the local machine.

  ::

    tables['filter']['INPUT'].append(reject_ssh)

This would result in the following iptables commands being produced:

  ::

    * filter
    ...
    -A INPUT -p tcp -j REJECT --dport 22
    ...

There are various types of rule already defined that provide defaults for various common parameters.  For example, the common jump targets (ACCEPT, DROP, REJECT, etc) already have handy predefined rules with the ``jump`` parameter already set.  Using these above could be written:

  ::

    from pyptables.rules import Reject
    reject_ssh = Reject(proto='tcp', dport='22')

You can define new types of rule yourself, for example, you could create an SSH type for matching SSH packets, and use it in various ways:

  ::

    SSH = Rule(proto='tcp', dport='22')
    tables['filter']['INPUT'].append(SSH(jump='ACCEPT', source='1.1.1.1', comment='Allow SSH from my workstation'))
    tables['filter']['INPUT'].append(SSH(jump='REJECT', comment='Prevent any other access to local SSH'))
    tables['filter']['FORWARD'].append(SSH(jump='REJECT', comment='Don't route any SSH traffic '))

This would result in the following iptables configuration being generated:

  ::

    ###############################################################################
    # filter table (/blocker/share/python/iptables/__init__.py:14 default_tables) #
    ###############################################################################
    *filter
    :INPUT ACCEPT [0:0]
    :FORWARD ACCEPT [0:0]
    :OUTPUT ACCEPT [0:0]
    
    # Builtin Chain "INPUT" (/blocker/share/python/iptables/__init__.py:12 default_tables)"
    # Rule: Allow access to local SSH from my workstation (<stdin>:1 <module>)
    -A INPUT -p tcp -s 1.1.1.1 -j ACCEPT --dport 22 -m comment --comment "Allow SSH from my workstation"
    # Rule: Prevent any other access to local SSH (<stdin>:1 <module>)
    -A INPUT -p tcp -j REJECT --dport 22 -m comment --comment "Prevent any other access to local SSH"
    
    # Builtin Chain "FORWARD" (/blocker/share/python/iptables/__init__.py:13 default_tables)"
    # Rule: Prevent any SSH traffic being routed through this box (<stdin>:1 <module>)
    -A FORWARD -p tcp -j REJECT --dport 22 -m comment --comment "Don't route any SSH traffic"
    
    # Builtin Chain "OUTPUT" (/blocker/share/python/iptables/__init__.py:14 default_tables)"
    # No rules

Higher-Level Rules
==================

TODO

***********
Issues/Bugs
***********

Any issues or bug reports, please contact `jamie_cockburn@hotmail.co.uk <mailto:jamie_cockburn@hotmail.co.uk>`_
