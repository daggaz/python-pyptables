"""This module contains the Channel classes.
   Channels represent a specification of a conduit in terms of
   a L2 protocol (or above).
"""

from pyptables.rules.arguments import ArgumentList, UnboundArgument
from pyptables.rules.matches import Match

class Channel(ArgumentList):
    """Channels represent a L3 network protocol"""
    
    def __init__(self, known_args=[], **kwargs):
        """Creates a Channel.
        
        p, proto - L3 protocol name (tcp, udp, etc.)
        kwargs   - Additional iptables arguments (see ArgumentList)
        """
        known_args += [UnboundArgument('p', 'proto')]
        super(Channel, self).__init__(known_args=known_args, **kwargs)
    
    def __str__(self):
        return "%s" % self['p'].value
    
class StatefulChannel(Channel):
    """A Channel capable of tracking connection state"""
    
    def __init__(self, states='', args=None, **kwargs):
        """Creates a StatefulChannel
        
           states - The states to match
           kwargs - Additional iptables arguments (see ArgumentList)
        """
        args = args or []
        if states:
            args.append(Match('conntrack', ctstate=states))
        super(StatefulChannel, self).__init__(args=args, **kwargs)
    
    def __str__(self):
        base_str = super(StatefulChannel, self).__str__()
        if 'ctstate' in self:
            return "%s, %s" % (base_str, self['ctstate'].value)
        return base_str
    
class PortChannel(StatefulChannel):
    """A StatefulChannel with port information. May only be used with "proto" that supports ports."""
    
    def __init__(self, sports='', dports='', args=None, **kwargs):
        """Creates a PortChannel
        
           sports - source ports to match
           dports - destination ports to match
        """
        args = args or []
        if sports or dports:
            multiport_args = {}
            if dports:
                dports = dports.replace('-', ':').replace(' ', '')
                multiport_args['dports'] = dports
            if sports:
                sports = sports.replace('-', ':').replace(' ', '')
                multiport_args['sports'] = sports
            args.append(Match('multiport', **multiport_args))
        super(PortChannel, self).__init__(args=args, **kwargs)
    
    def __str__(self):
        sports = self['sports'].value if 'sports' in self else 'any'
        dports = self['dports'].value if 'dports' in self else 'any'
        return "%s, ports %s -> %s" % (super(PortChannel, self).__str__(), sports, dports)

class TCPChannel(PortChannel):
    """A TCPChannel represents a TCP port and/or connection state specification"""
    
    def __init__(self, **kwargs):
        super(TCPChannel, self).__init__(proto='tcp', **kwargs)

class UDPChannel(PortChannel):
    """A UDPChannel represents a UDP port and/or connection state specification"""
    
    def __init__(self, **kwargs):
        super(UDPChannel, self).__init__(proto='udp', **kwargs)

class ICMPChannel(StatefulChannel):
    """A ICMPChannel represents a ICMP port and/or connection state specification"""
    
    def __init__(self, icmp_type='', args=None, **kwargs):
        if icmp_type:
            super(ICMPChannel, self).__init__(proto='icmp', icmp_type=icmp_type, **kwargs)
        else:
            super(ICMPChannel, self).__init__(proto='icmp', **kwargs)
    
    def __str__(self):
        icmp_type = self['icmp_type'].value if 'icmp_type' in self else 'any'
        return "%s, type %s" % (super(ICMPChannel, self).__str__(), icmp_type)
    
__all__ = [Channel, StatefulChannel, PortChannel, TCPChannel, UDPChannel, ICMPChannel]
