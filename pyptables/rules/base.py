import itertools

from ..base import DebugObject

from arguments import UnboundArgument, ArgumentList
from matches import Match

class AbstractRule(DebugObject):
    """Represents an iptables rule"""
    
    def __init__(self, comment=None):
        super(AbstractRule, self).__init__()
        self.comment = comment
        
    def to_iptables(self, prefix=''):
        """Return rule in iptables format, suitable for use with iptables-restore"""
        try: 
            return '%(header)s\n%(rules)s' % {
                'header': self._header(),
                'rules': self._rule_definition(prefix),
                }
        except Exception, e: # pragma: no cover
            e.iptables_path = getattr(e, 'iptables_path', [])
            e.iptables_path.insert(0, "Rule:\n    created: %s\n    comment: %s" % (self.debug_info(), self.comment))
            raise
        
    def _header(self):
        return '# Rule: %(comment)s(%(debug)s)' % {
                    'comment': self.comment + ' '  if self.comment else '',
                    'debug': self.debug_info(),
                    }
    
    def _rule_definition(self, prefix):
        if prefix:
            prefix += ' '
        return "\n".join(['%s%s' % (prefix, rule) for rule in self.rule_definitions()])
        
    def rule_definitions(self):
        """Return a list of individual iptables commands that implement this rule"""
        raise NotImplementedError() # pragma: no cover
    
    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.rule_definitions())

class CustomRule(AbstractRule):
    """An iptables rule with its content specified as a plain string"""
    def __init__(self, rule, comment=None):
        super(CustomRule, self).__init__(comment)
        self.rule = rule
    
    def rule_definitions(self):
        """Return a list of individual iptables commands that implement this rule"""
        if self.comment:
            return ['%s -m comment --comment "%s"' % (
                        self.rule,
                        self.comment.replace('"','\\"'),
                        )]
        return [self.rule]

class Rule(AbstractRule):
    """An iptables rule with rich pythonic interface for rule creation"""
    
    # Handy constants
    NONE = 'NONE'
    ACCEPT = 'ACCEPT'
    DROP = 'DROP'
    REJECT = 'REJECT'
    RETURN = 'RETURN'
    REDIRECT = 'REDIRECT'
    LOG = 'LOG'
    
    TCP = 'tcp'
    UDP = 'udp'
    ICMP = 'icmp'
    IGMP =  'igmp'

    # List of known arguments
    _known_args = (
        UnboundArgument('i', 'in_interface', invertable=True), 
        UnboundArgument('o', 'out_interface', invertable=True), 
        UnboundArgument('p', 'proto', invertable=True),
        UnboundArgument('s', 'source', invertable=True),
        UnboundArgument('d', 'destination', invertable=True),
        UnboundArgument('f', 'fragment'),
        UnboundArgument('j', 'jump'),
        UnboundArgument('g', 'goto'),
        )
    
    def __init__(self, comment=None, args=[], **kwargs):
        """Creates a Rule.
           
        comment - rule comment
        kwargs  - any iptables arguments, known or unknown
        args    - ArgumentList objects to add to this rule
        
        Some arguments are invertable by appending __not to the
        argument name (see Known Arugments below).
       
        Usage:
        Rule(jump='DROP', i='eth0', destination__not='192.168.23.0/24')
        """
        super(Rule, self).__init__(comment)
        self.arguments = ArgumentList(known_args=self._known_args, args=args, **kwargs)
    __init__.__doc__ = "%s\nKnown arguments:\n%s" % (__init__.__doc__,
                                                     "\n".join(arg.help() for arg in _known_args),
                                                     )
    
    def __call__(self, comment=None, args=[], **kwargs):
        """Returns a new rule based on this rule with the args and kwargs specified added to it"""
        rule = Rule()
        rule.comment = comment or self.comment
        rule.arguments = self.arguments(args=args, **kwargs)
        return rule
    
    def rule_definitions(self):
        """Return a list of individual iptables commands that implement this rule"""
        arguments = list(self.arguments)
        if self.comment:
            arguments.append(Match('comment', comment=self.comment))
        return [" ".join([arg.to_iptables() for arg in arguments])]

class CompositeRule(AbstractRule):
    """An iptables rule combining multiple other iptables rules (AbstractRule derivitives)"""
    def __init__(self, rules, comment=None):
        super(CompositeRule, self).__init__(comment)
        self._rules = rules
    
    def rule_definitions(self):
        """Return a list of individual iptables commands that implement this rule"""
        return itertools.chain(*(rule.rule_definitions() for rule in self._rules))
