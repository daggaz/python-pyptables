"""This module contains the Zone class.
   
   Zones represent a network.
"""

from pyptables.base import DebugObject
from pyptables.rules.arguments import ArgumentList
from pyptables.rules.matches import Match

class Zone(DebugObject):
    """Represents a network"""
    
    def __init__(self, name, interface, physdev=None):
        """Creates a zone
        
        name      - zone name
        interface - the network interface name
        """
        super(Zone, self).__init__()
        self.name = name
        self.interface = interface
        self.physdev = physdev
    
    def as_input(self):
        """Return iptables ArgumentLists for this zone
        for matching against packet sources
        """
        if self.physdev is None:
            return ArgumentList(in_interface=self.interface)
        return ArgumentList(in_interface=self.interface, args=[Match('physdev', physdev_in=self.physdev)])
    
    def as_output(self):
        """Return iptables ArgumentLists for this zone
        for matching against packet sources
        """
        if self.physdev is None:
            return ArgumentList(out_interface=self.interface)
        return ArgumentList(out_interface=self.interface, args=[Match('physdev', physdev_out=self.physdev)])

    def __repr__(self):
        return "<Zone: %s>" % (self.name)
    
    def __str__(self):
        return self.name
