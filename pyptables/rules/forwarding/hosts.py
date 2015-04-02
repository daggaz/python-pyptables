"""This module contains the Hosts class.
   Hosts represent a collection of network addresses
"""

from pyptables.rules.arguments import ArgumentList
from pyptables.rules.matches import Match
from pyptables.base import DebugObject

class Hosts(DebugObject):
    """Represents a collection of network addresses"""
    
    def as_input(self):
        """Return iptables ArgumentLists for this group of
        hosts for matching against packet sources
        """
        raise NotImplementedError() # pragma: no cover
    
    def as_output(self):
        """Return iptables ArgumentLists for this group of
        hosts for matching against packet destinations
        """
        raise NotImplementedError() # pragma: no cover
    
    @staticmethod
    def from_ip_list(string):
        """Generate a list of Hosts objects from a string.
        
        The string may contain comma separated ips, subnets
        (in CIDR notation), or ip ranges (from-to).
        """
        if not string:
            return [] # pragma: no cover 
        parts = string.replace(' ', '').split(',')
        singles = [part for part in parts if '-' not in part]
        ranges = [part for part in parts if '-' in part]
        
        result = []
        if singles:
            result.append(HostList(singles))
        result.extend([HostRange(r) for r in ranges])
        return result
    
class HostList(Hosts):
    def __init__(self, hosts):
        super(HostList, self).__init__()
        self.hosts = hosts
    
    def as_input(self):
        return ArgumentList(source=",".join(self.hosts))
    
    def as_output(self):
        return ArgumentList(destination=",".join(self.hosts))
        
    def __repr__(self):
        return "<HostList: [%s]>" % (",".join(self.hosts))
    
    def __str__(self):
        return ",".join(self.hosts)

class HostRange(Hosts):
    def __init__(self, range):
        super(HostRange, self).__init__()
        self.range = range
    
    def as_input(self):
        return Match('iprange', src_range=self.range)
    
    def as_output(self):
        return Match('iprange', src_range=self.range)
    
    def __repr__(self):
        return "<HostRange: %s>" % self.range
    
    def __str__(self):
        return self.range

__all__ = [Hosts]
