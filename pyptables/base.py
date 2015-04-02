import inspect

class DebugObject(object):
    """Base class for most iptables classes.
    Allows objects to determine the source line they were created from,
    which is used to insert debugging infomation into the generated output
    """
    def __init__(self, *args, **kwargs):
        super(DebugObject, self).__init__(*args, **kwargs)
        frame = inspect.currentframe().f_back
        while frame:
            info = inspect.getframeinfo(frame)
            if not info[2].startswith('__'):
                break
            frame = frame.f_back
        self.filename, self.lineno, self.function, __, __ = info
    
    def debug_info(self):
        """Returns a string of debug info about the creation of this object"""
        return "%s:%s %s" % (self.filename, self.lineno, self.function)
