import re 
import subprocess

from tables import Tables, Table
from chains import BuiltinChain, UserChain
from rules import Rule, Accept, Drop, Jump, Redirect, Return, Log, CustomRule
from rules.matches import Match

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

def make_colorizer(code):
        def colorizer(string):
            return '\x1b[%(code)sm%(string)s\x1b[0m' % {'code': code, 'string': string}
        return colorizer

def colorize(string):
    """Util function to format iptables output for a tty"""
    
    heading = make_colorizer("1;32")
    comment = make_colorizer("32")
    bold = make_colorizer("33")
    table = make_colorizer("1;36")
    chain = make_colorizer("36")
    exclaimation = make_colorizer("1;31")
    commit = make_colorizer("36")
    
    result = []
    for line in string.split('\n'):
        if line.startswith('#'):
            if line.endswith('#'):
                result.append(heading(line))
            else:
                result.append(comment(line))
        elif line.startswith(':'):
            result.append(chain(line))
        elif line.startswith('*'):
            result.append(table(line))
        elif line == "COMMIT":
            result.append(commit(line))
        else:
            parts = []
            for part in line.split():
                if part == '!':
                    parts.append(exclaimation(part))
                elif part.startswith('-'):
                    parts.append(bold(part))
                else:
                    parts.append(part)
            result.append(" ".join(parts))
    return "\n".join(result)

strip_ANSI_escape_sequences_sub = re.compile(r"""
    \x1b     # literal ESC
    \[       # literal [
    [;\d]*   # zero or more digits or semicolons
    [A-Za-z] # a letter
    """, re.VERBOSE).sub

def uncolorize(string):
    return strip_ANSI_escape_sequences_sub("", string)

def add_line_numbers(string, start=1):
    """Util function to add line numbers to a string"""
    
    lines = string.split('\n')
    return "\n".join([("%0" + str(len(str(len(lines)))) + "s | %s") % i for i in enumerate(lines, start)])

def restore(tables):
    process = subprocess.Popen(["iptables-restore"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if hasattr(tables, 'to_iptables'):
        tables = tables.to_iptables()
    return process.communicate(tables)
