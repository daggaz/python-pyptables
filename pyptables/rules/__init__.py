"""This package contains classes to generate
   rules for iptables.
"""

from base import AbstractRule, CustomRule, Rule, CompositeRule

from pyptables.chains import AbstractChain as _AbstractChain

class Jump(Rule):
    """A iptables Rule object that jumps to the specified chain"""
     
    def __init__(self, chain, comment=None, *args, **kwargs):
        """Creates a Jump rule.
        chain - a UserChain object or a literal chain name
        """
        if isinstance(chain, _AbstractChain):
            name = chain.name
            if comment is None:
                comment = chain.comment
        else:
            name = chain
        
        super(Jump, self).__init__(jump=name, comment=comment, *args, **kwargs)

Accept = Rule(jump=Rule.ACCEPT)
Drop = Rule(jump=Rule.DROP)
Reject = Rule(jump=Rule.REJECT)
Return = Rule(jump=Rule.RETURN)
Redirect = Rule(jump=Rule.REDIRECT)
Log = Rule(jump=Rule.LOG)
