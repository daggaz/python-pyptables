from pyptables import default_tables, CustomRule, Jump, UserChain, colorize, add_line_numbers

import sys

if '--colorize' in sys.argv:
    output = colorize(sys.stdin.read())
else:
    tables = default_tables()
    
    tables['filter']['INPUT'].append(CustomRule('a rule'))
    
    my_chain = tables['mangle'].append(UserChain('my_chain', 'A chain to rule all chains', [CustomRule('init rule')]))
    tables['mangle']['POSTROUTING'].append(Jump(chain=my_chain, proto__not='tcp', comment='Jump to "%s" for all non-tcp packets' % my_chain.name))
    my_chain.append(CustomRule('another rule'))
    my_chain.append(CustomRule('a custom rule', comment='A comment "do stuff"'))
    
    if sys.stdout.isatty() or '--color' in sys.argv:
        output = colorize(tables.to_iptables())
    else:
        output = tables.to_iptables()
    
if '--line-numbers' in sys.argv:
    output = add_line_numbers(output) 
    
print output
