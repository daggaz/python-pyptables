"""This module contains utility classes for handling iptables marks"""

from functools import partial
from random import Random

from . import Rule

_marks = []
class Mark(Rule):
    """A Rule that marks matching packets with the specified mark value"""
    MARK = 'MARK'
    
    def __init__(self, mark, *args, **kwargs):
        """Creates a Mark rule
        
        mark - the value to mark matching packets with
        """
        super(Mark, self).__init__(jump=Mark.MARK, set_mark=str(mark), *args, **kwargs)
        self.mark = mark

class Marked(Rule):
    """A rule that matches packets with the specified mark"""
    
    def __init__(self, mark, *args, **kwargs):
        """Created a Marked rule
        
        mark - match this mark value (can be the the Mark
               rule used originally mark the packets, or
               a literal value
        """
        if not isinstance(mark, int):
            mark = mark.mark
        super(Marked, self).__init__(match='mark', mark=str(mark), *args, **kwargs)
        self.mark = mark

DropMarked = partial(Marked, jump=Rule.DROP)
AcceptMarked = partial(Marked, jump=Rule.ACCEPT)

_random_mark_value = partial(Random().randint, 1, 65535)
def random_mark():
    """Generate a Mark rule with a random value""" 
    mark = _random_mark_value()
    while mark in _marks:
        mark = _random_mark_value() # pragma: no cover
    return Mark(mark=mark)
