from collections import OrderedDict

from base import DebugObject

class Tables(DebugObject, OrderedDict):
    """Dictionary like top-level container of iptables, holds a number of Table objects."""
    def __init__(self, *tables):
        super(Tables, self).__init__()
        for table in tables:
            self.append(table)
    
    def to_iptables(self):
        """Returns this list of tables in a format compatible with iptables-restore"""
        try:
            header = '# Tables generated by PyPTables (%(debug)s)' % {'debug': self.debug_info()}
            table_output = [table.to_iptables() for table in self.values()]
            table_output = "\n\n".join(table_output)
            return "%(header)s\n\n%(tables)s\n" % {
                'header': header,
                'tables': table_output,
                }
        except Exception, e: #pragma: no cover
            e.iptables_path = getattr(e, 'iptables_path', [])
            e.iptables_path.insert(0, "Tables")
            e.message = "Iptables error at:\n    %s\n\nError message: %s" % ("\n".join(e.iptables_path).replace('\n', '\n    '), e.message)
            raise
    
    def __setitem__(self, *args, **kwargs):
        raise TypeError("Tables object does not support item assignment, use append(table)")
    
    def append(self, table):
        """Append a table to this list of tables"""
        super(Tables, self).__setitem__(table.name, table)
        return table
    
    def __repr__(self):
        return "<Tables: [%s]>" % ", ".join(['<Table: %s ...>' % t.name for t in self.values()])

class Table(DebugObject, OrderedDict):
    """Represents an iptables table, holds a number of Chain objects in a dictionary-like fashion"""  
    def __init__(self, name, *chains):
        super(Table, self).__init__()
        self.name = name
        for chain in chains:
            self.append(chain)
    
    def to_iptables(self):
        """Returns this table in a format compatible with iptables-restore"""
        try:
            header_content = "# %(name)s table (%(debug)s) #" % {
                'name': self.name,
                'debug': self.debug_info(),
                }
            header = "%(marquee)s\n%(content)s\n%(marquee)s\n*%(name)s" % {
                'content': header_content,
                'marquee': "#"*len(header_content),
                'name': self.name, 
                }
            chain_results = [chain.to_iptables() for chain in self.values()]
        
            return "%(header)s\n%(chains)s\n\n%(rules)s\n\n%(footer)s" % {
                'header': header,
                'chains': "\n".join([result.header_content for result in chain_results]),
                'rules': "\n\n".join([result.rules for result in chain_results]),
                'footer': 'COMMIT'
                }
        except Exception, e: #pragma: no cover
            e.iptables_path = getattr(e, 'iptables_path', [])
            e.iptables_path.insert(0, self.name)
            raise
    
    def __setitem__(self, *args, **kwargs):
        raise TypeError("Table object does not support item assignment, use append(chain)")
    
    def append(self, chain):
        """Append a chain to this table"""
        super(Table, self).__setitem__(chain.name, chain)
        return chain
    
    def __repr__(self):
        return "<Table: %s - %s>" % (self.name, self.values())