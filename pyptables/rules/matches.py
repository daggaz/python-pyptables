"""This module contains a utility class for handling iptables match extensions"""

from pyptables.rules.arguments import ArgumentList, UnboundArgument

class Match(ArgumentList):
    """An iptables ArgumentList for a match extension"""
    _known_args = [UnboundArgument('m', 'match')] 
    
    def __init__(self, name, known_args=[], args=(), **kwargs):
        """Creates a Match
        
        known_args - list of UnboundArguments known to this Match
                     mostly used by subclasses
        name       - the name of the match extension
        kwargs     - any iptables arguments, known or unknown
        args       - other ArgumentList objects to add to this ArgumentList
        """
        known_args = self._known_args + known_args
        super(Match, self).__init__(match=name, known_args=known_args, args=args, **kwargs)
