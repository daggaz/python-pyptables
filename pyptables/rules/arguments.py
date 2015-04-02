"""This modules contains classes related to rule arguments"""

from collections import namedtuple

class UnboundArgument(object):
    """This class represents an argument that the system is
    aware of, and can therefore provide additional apis for.
    """
    
    ParseResult = namedtuple('ParseResult', 'name inverse')
    
    def __init__(self, short_name, long_name, type=str, invertable=False):
        """Creates an UnboundArgument.
        
        short_name - short name
        long_name  - long name
        type       - argument type (str (default), bool, etc.)
        invertable - if true, argument can used with __not prefix
                     to invert the match (default: False)
        """
        super(UnboundArgument, self).__init__()
        self.short_name = short_name
        self.long_name = long_name
        self.type = type
        self.invertable = invertable
    
    def matches(self, name):
        """Tests if the passed name matches this argument"""
        return bool(self._parse_name(name))
    
    def _parse_name(self, name):
        """Parses the passed argument name and return a tuple(name, invertable)
        containing the name and if it is invertable or not.
        """
        parts = name.split('__')
        if parts[0] != self.short_name and parts[0] != self.long_name:
            return False
        
        inverse = False
        for part in parts[1:]:
            if part != 'not':
                raise ValueError("Only 'not' is supported")
            if not self.invertable:
                raise ValueError('This argument is not invertable')
            inverse = not inverse
        return UnboundArgument.ParseResult(name=parts[0], inverse=inverse)
    
    def bind(self, name, value):
        """Returns a BoundArgument, binding this argument to a value"""
        parse_result = self._parse_name(name)
        if not parse_result:
            raise ValueError('name does not match')
        return BoundArgument(self, value, parse_result.inverse)
    
    def help(self):
        return "%s, %s (type: %s%s)" % (self.short_name,
                                        self.long_name,
                                        self.type.__name__,
                                        ', invertable' if self.invertable else '',
                                        )
        
class Argument(object):
    """Represents a iptables Rule argument/value pair (abstract)"""
    
    def __init__(self, value):
        """Create an Argument with the specified value
        
        Note: arguments may have many names, and these are
        specified by the subclasses of this class
        """
        self.value = self._parse_value(value)
        
    def _parse_value(self, values):
        if not isinstance(values, list):
            values = [values]
        result = []
        for value in values:
            value = value.replace('"', '\\"')
            if ' ' in value:
                value = '"%s"' % value
            result.append(value)
        return " ".join(result)
    
    def get_name(self):
        """Returns the preferred name for this argument"""
        raise NotImplemented('Subclasses must implement') # pragma: no cover 
    
    def has_name(self, name):
        """Returns True if this argument is known by the specified name"""
        raise NotImplemented('Subclasses must implement') # pragma: no cover 
    
    def get_argument(self):
        """Renders the argument name with prefixed "-" or "--", as appropriate""" 
        name = self.get_name().replace('_', '-')
        prefix = "-" if len(name) == 1 else "--"
        return "%s%s" % (prefix, name)
    
    def __repr__(self):
        return "<%s: %s=%s>" % (self.__class__.__name__, self.get_name(), self.value)

class BoundArgument(Argument):
    """Represents an known argument (UnboundArgument) bound to value"""
    
    def __init__(self, argument, value, inverse):
        """Creates a BoundArgument
        
        argument - the UnboundArgument
        value    - the value
        inverse  - the rule should pass for values that don't match
        """
        self.argument = argument
        super(BoundArgument, self).__init__(value)
        self.inverse = inverse
    
    def _parse_value(self, value):
        if not isinstance(value, self.argument.type):
            raise ValueError('Argument must be of type %s' % self.argument.type)
        return super(BoundArgument, self)._parse_value(value)
    
    def get_name(self):
        """Returns the preferred name for this argument"""
        if self.argument.short_name:
            return self.argument.short_name
        return self.argument.long_name
    
    def has_name(self, name):
        """Returns True if this argument is known by the specified name"""
        return name == self.argument.short_name or name == self.argument.long_name
    
    def to_iptables(self):
        """Return argument in iptables format, suitable for use in an iptables format rule""" 
        if self.inverse:
            return "! %s %s" % (self.get_argument(), self.value)
        return "%s %s" % (self.get_argument(), self.value)

class CustomArgument(Argument):
    """Represents an iptables argument that the system has no
    explicit knowledge of.
    """
    
    def __init__(self, name, value):
        """Create a CustomArgument"""
        super(CustomArgument, self).__init__(value)
        parts = name.split('__')
        if len(parts) == 1:
            self.inverse = False
            self.name = name
        elif len(parts) == 2:
            if parts[1] == 'not':
                self.inverse = True
                self.name = parts[0]
            else:
                raise ValueError("Only 'not' is supported")
        else:
            raise ValueError("badly formatted argument name")
    
    def _parse_value(self, value):
        if value is None:
            return None
        return super(CustomArgument, self)._parse_value(value)
    
    def get_name(self):
        """Returns the preferred name for this argument"""
        return self.name
    
    def has_name(self, name):
        """Returns True if this argument is known by the specified name"""
        return name == self.name
    
    def to_iptables(self):
        """Return argument in iptables format, suitable for use in an iptables format rule"""
        if self.value is None:
            result = "%s" % self.get_argument()
        else:
            result = "%s %s" % (self.get_argument(), self.value)
        if self.inverse:
            return "! %s" % result
        return result

class ArgumentList(object):
    """Represents a list of iptables Arguments
    
    Can be interated:
    for arg in arglist:
        pass
    
    Can be indexed by argument name, e.g.:
    p = arglist['proto']
    
    Can be tested for containment, e.g.:
    if 'p' in arglist:
        pass
    """ 
    def __init__(self, known_args=[], args=(), **kwargs):
        """Creates an ArgumentList
        
        known_args - list of UnboundArguments known to this ArgumentList
                     mostly used by subclasses
        kwargs     - any iptables arguments, known or unknown
        args       - other ArgumentList objects to add to this ArgumentList
        """
        super(ArgumentList, self).__init__()
        self.known_args = known_args
        self.args = args
        self.kwargs = kwargs
    
    def __call__(self, args=(), **kwargs):
        """Returns a new ArgumentList based on this ArgumentList
        with the args and kwargs specified added to it
        """
        args, kwargs = self._update_args(args, kwargs)
        return ArgumentList(known_args=self.known_args, args=args, **kwargs)
    
    def _update_args(self, args, kwargs):
        args, kwargs = list(args), dict(kwargs) # don't modify passed data
        for arglist in args:
            arglist.known_args.extend(self.known_args)
        args.extend(self.args)
        kwargs.update(self.kwargs)
        return args, kwargs
    
    def __iter__(self):
        kwargs = dict(self.kwargs) # duplicate dictionary, as it is modified below
        for argument in self.known_args:
            for key in kwargs.keys():
                if argument.matches(key):
                    value = kwargs.pop(key)
                    yield argument.bind(key, value)
                    break
        for name, value in kwargs.items():
            yield CustomArgument(name, value)
        for arglist in self.args:
            for arg in arglist:
                yield arg
    
    def __getitem__(self, key):
        for arg in self:
            if arg.has_name(key):
                return arg
        raise KeyError('argument "%s" not in list' % key)
    
    def __contains__(self, key):
        try:
            self[key]
        except KeyError:
            return False
        else:
            return True
    
    def to_iptables(self):
        """Return arguments in iptables format, suitable for use in an iptables format rule""" 
        return " ".join([arg.to_iptables() for arg in self])
    
    def __str__(self):
        return str(self.to_iptables())
    
    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.to_iptables())
