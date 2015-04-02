"""This module contains the IPSet class.
   
   IPSet represent an ipset.
"""

from pyptables.base import DebugObject
from pyptables.rules.matches import Match

class IPSet(DebugObject):
    """Represents a linux ipset"""
    
    def __init__(self, name):
        """Creates an ipset
        
        name - ipset name
        """
        super(IPSet, self).__init__()
        self.name = name
    
    def as_input(self):
        """Return iptables ArgumentLists for this ipset
        for matching against packet sources
        """
        return Match('set', match_set=[self.name, 'src'])
    
    def as_output(self):
        """Return iptables ArgumentLists for this ipset
        for matching against packet destinations
        """
        return Match('set', match_set=[self.name, 'dst'])

    def __repr__(self):
        return "<IPSet: %s>" % (self.name)
    
    def __str__(self):
        return self.name
