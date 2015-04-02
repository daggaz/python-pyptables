import itertools
import os.path
import unittest

from StringIO import StringIO

from pyptables import default_tables, Rule, UserChain, Jump, CustomRule
from pyptables.rules import CompositeRule
from pyptables.rules.arguments import ArgumentList, CustomArgument
from pyptables.rules.marks import Mark, random_mark, Marked
from pyptables.rules.input import InputRule
from pyptables.rules.forwarding import ForwardingRule
from pyptables.rules.forwarding.hosts import HostList, HostRange
from pyptables.rules.forwarding.ipsets import IPSet
from pyptables.rules.forwarding.locations import Location
from pyptables.rules.forwarding.zones import Zone
from pyptables.rules.forwarding.channels import TCPChannel, UDPChannel, ICMPChannel

def compare(a, b):
    for line_no, lines in enumerate(itertools.izip_longest(a, b, fillvalue='')):
        lines = [line.strip() for line in lines]
        if all(line.startswith('#') for line in lines):
            continue
        for i, chars in enumerate(itertools.izip_longest(*lines)):
            if chars[0] != chars[1]:
                raise ValueError("line %s doesn't match:\n\t%s\n\t%s\n\t%s^" % (line_no, lines[0], lines[1], i*'_'))
    return True
        

class MainTest(unittest.TestCase):
    
    def test(self):
        self.assertRaisesRegexp(ValueError, "Only 'not' is supported", lambda: Rule(s__invalid=None).to_iptables())
        self.assertRaisesRegexp(ValueError, "This argument is not invertable", lambda: Rule(f__not=None).to_iptables())
        self.assertRaisesRegexp(ValueError, "Only 'not' is supported", lambda: Rule(custom__invalid=None).to_iptables())
        self.assertRaisesRegexp(ValueError, "badly formatted argument name", lambda: Rule(custom__not__invalid=None).to_iptables())
        Rule(custom__not=None).to_iptables()
        arg_list = ArgumentList(custom='1')
        self.assertIsInstance(arg_list['custom'], CustomArgument)
        self.assertRaises(KeyError, lambda: arg_list['missing'])
        arg_list = arg_list(another=None, args=(ArgumentList(custom='2'),))
        self.assertTrue('custom' in arg_list)
        self.assertFalse('missing' in arg_list)
        self.assertIsInstance(arg_list['custom'], CustomArgument)
        self.assertIsInstance(arg_list['another'], CustomArgument)
        self.assertEqual(arg_list.to_iptables(), "--another --custom 1 --custom 2")
        repr(Rule(j='DROP').arguments)
        tables = default_tables()
        chain = UserChain('test_chain', comment='A user chain')
        repr(chain)
        repr(Rule())
        Accept = Rule(j='ACCEPT')
        chain.append(Rule(i='eth0', s='1.1.2.1', d__not='1.1.1.2', jump='DROP', comment='A Rule'))
        def tables_set(): tables['filter'] = None
        self.assertRaises(TypeError, tables_set)
        print tables
        def table_set(): tables['filter']['INPUT'] = None
        self.assertRaises(TypeError, table_set)
        print tables['filter']
        tables['filter'].append(chain)
        tables['filter']['INPUT'].append(Jump(chain))
        tables['filter']['INPUT'].append(Jump('string_chain'))
        tables['filter']['OUTPUT'].append(CustomRule('a random string'))
        tables['filter']['OUTPUT'].append(CustomRule('a random string', comment='this is a custom rule with a comment'))
        tables['filter']['OUTPUT'].append(CustomRule('a random string', comment='this is a custom rule with a comment'))
        tables['filter']['OUTPUT'].append(CompositeRule([Accept(s='1.1.1.1'), Rule(j='DROP')]))
        tables['mangle']['OUTPUT'].append(Mark(123))
        random = random_mark()
        
        Log = Rule(j='LOG')
        simple_zone = Zone('A zone', 'eth0')
        repr(simple_zone)
        simple_location = Location('A location3', Zone('A zone', 'br0', physdev='eth0'))
        repr(simple_location)
        ip_set = IPSet('a_set')
        repr(ip_set)
        list_location = Location.from_ip_list('A location', None, '1.1.1.1,2.2.2.2')
        range_location = Location.from_ip_list('A location2', simple_zone, '3.1.1.1-3.2.2.2')
        tables['mangle']['OUTPUT'].append(Marked(random))
        tables['mangle']['INPUT'].append(InputRule(policy='DROP',
                                                   channels=[],
                                                   sources=itertools.chain(list_location,
                                                                           range_location,
                                                                           [simple_location, ip_set],
                                                                           ),
                                                   log=True,
                                                   log_cls=Log,
                                                   ))
        tcp = TCPChannel(sports='1', dports='2')
        udp = UDPChannel(states='ESTABLISHED')
        icmp1 = ICMPChannel(icmp_type='1')
        icmp2 = ICMPChannel()
        host_list = HostList(['1.1.1.1', '2.2.2.2'])
        repr(host_list)
        str(host_list)
        host_range = HostRange('1.1.1.1-2.2.2.2')
        repr(host_range)
        str(host_range)
        tables['mangle']['INPUT'].append(InputRule('ACCEPT',
                                                   channels=[tcp, udp, icmp1, icmp2],
                                                   ))
        tables['mangle']['INPUT'].append(InputRule('REJECT'))
        tables['mangle']['INPUT'].append(InputRule('NONE'))
        tables['filter']['FORWARD'].append(ForwardingRule(policy='DROP',
                                                          sources=[],
                                                          destinations=[simple_location, ip_set],
                                                          ))
        tables['filter']['FORWARD'].append(ForwardingRule(policy='ACCEPT',
                                                          sources=list_location,
                                                          destinations=[],
                                                          ))
        tables['filter']['FORWARD'].append(ForwardingRule(policy='REJECT',
                                                          sources=range_location,
                                                          destinations=list_location,
                                                          ))
        tables['filter']['FORWARD'].append(ForwardingRule(policy='REJECT',
                                                          sources=[],
                                                          destinations=range_location,
                                                          ))
        tables['filter']['FORWARD'].append(ForwardingRule(policy='NONE',
                                                          sources=[],
                                                          destinations=[],
                                                          channels=[tcp, udp, icmp1, icmp2],
                                                          args=[host_list.as_input(), host_range.as_input()],
                                                          log=True,
                                                          log_cls=Log,  
                                                          ))
        self.assertRaises(ValueError, lambda: InputRule('BAD').to_iptables())
        self.assertRaises(ValueError, lambda: ForwardingRule(policy='BAD', sources=[], destinations=[]).to_iptables())
        self.assertRaisesRegexp(ValueError, "Argument must be of type.*", lambda: Rule(p=1).to_iptables())
        result = tables.to_iptables()
        fixture_file = os.path.join(os.path.dirname(__file__), 'test.dat')
        with open(fixture_file, 'w') as fixture:
            fixture.write(result)
        with open(fixture_file) as fixture:
            try:
                compare(fixture, StringIO(result))
            except ValueError, e:
                self.fail(str(e))
