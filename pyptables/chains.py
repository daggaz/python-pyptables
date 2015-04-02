import re
from collections import namedtuple

from base import DebugObject

class AbstractChain(DebugObject, list):
    """Represents an iptables Chain.  Holds a number of Rule objects in a list-like fashion"""
    Result = namedtuple('ChainResult', 'header_content rules')
    
    def __init__(self, name, comment=None, rules=[]):
        super(AbstractChain, self).__init__(rules)
        self.comment = comment
        self.name = name
    
    def to_iptables(self):
        """Returns this chain in a format compatible with iptables-restore"""
        try:
            prefix = '-A %s' % (self.name)
            if self:
                rule_output = [rule.to_iptables(prefix=prefix) for rule in self]
                rule_output = "\n".join(rule_output)
            else:
                rule_output = '# No rules'
            return AbstractChain.Result(header_content=self._chain_definition(),
                                        rules="%(comment)s\n%(rules)s" % {
                                              'comment': self._comment(),
                                              'rules': rule_output,
                                              },
                                        )
        except Exception, e: # pragma: no cover
            e.iptables_path = getattr(e, 'iptables_path', [])
            e.iptables_path.insert(0, self.name)
            raise
        
    def _chain_definition(self):
        """Return iptables-restore formatted instruction to create
        the chain (note: rules are added separately)
        """
         
        raise NotImplemented('Subclasses must define this method') # pragma: no cover

    def _comment(self):
        comment = '# %(type)s "%(name)s" (%(debug)s)"' % {
            'type': self._type_name(),
            'name': self.name,
            'debug': self.debug_info(),
            }
        if self.comment:
            comment = "%s\n# %s" % (comment, self.comment)
        return comment
    
    def _type_name(self):
        return " ".join(re.findall(r'[A-Z][^A-Z]*', self.__class__.__name__))
    
    def __repr__(self):
        truncated = map(str, self[:3]) + (['...'] if len(self) > 3 else [])
        return "<%s: %s - [%s]>" % (self.__class__.__name__, self.name, ", ".join(truncated))
    
class UserChain(AbstractChain):
    def __init__(self, *args, **kwargs):
        super(UserChain, self).__init__(*args, **kwargs)
        
    def _chain_definition(self):
        return ':%(name)s - [0:0]'  % {'name': self.name}
    

class BuiltinChain(AbstractChain):
    """Represents a built-in iptables chain
    Built-in chains can have a default policy"""
    
    def __init__(self, name, policy, *args, **kwargs):
        super(BuiltinChain, self).__init__(name, *args, **kwargs)
        self.policy = policy
    
    def _chain_definition(self):
        return ':%(name)s %(policy)s [0:0]'  % {'name': self.name, 'policy': self.policy}
