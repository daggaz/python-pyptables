"""This module contains the Location class.

   Locations represent a network location.
"""

from ...base import DebugObject
from ..arguments import ArgumentList
from hosts import Hosts

class Location(DebugObject):
    """Represents a network location"""
    
    @staticmethod
    def from_ip_list(name, zone, ips):
        """Generate a list of Location objects from a string of ips
        and/or a zone.
        
        The string may contain comma separated ips, subnets
        (in CIDR notation), or ip ranges (from-to).
        """
        result = []
        for hosts in Hosts.from_ip_list(ips):
            result.append(Location(name, zone, hosts))
        return result
    
    def __init__(self, name, zone, hosts=None):
        """Creates a Location
           
        name  - location name
        zone  - network
        hosts - network addresses
           
        If no hosts are specified, this location contains the entire zone.
        """
        super(Location, self).__init__()
        self.name = name
        self.zone = zone
        self.hosts = hosts
    
    def as_input(self):
        """Return iptables ArgumentLists for this location
        for matching against packet sources
        """
        if self.hosts:
            if self.zone:
                return ArgumentList(args=[self.zone.as_input(), self.hosts.as_input()])
            else:
                return ArgumentList(args=[self.hosts.as_input()])
        else:
            return ArgumentList(args=[self.zone.as_input()])
    
    def as_output(self):
        """Return iptables ArgumentLists for this location
        for matching against packet destinations
        """
        if self.hosts:
            if self.zone:
                return ArgumentList(args=[self.zone.as_output(), self.hosts.as_output()])
            else:
                return ArgumentList(args=[self.hosts.as_output()])
        else:
            return ArgumentList(args=[self.zone.as_output()])

    def __repr__(self):
        return "<Location: %s, zone=%s, hosts=%s>" % (self.name, self.zone, self.hosts)
    
    def __str__(self):
        if self.hosts:
            return "%s: %s" % (self.zone and self.zone.name or "Anywhere", self.name)
        return self.name
