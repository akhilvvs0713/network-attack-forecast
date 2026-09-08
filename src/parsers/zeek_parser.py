import logging

logger = logging.getLogger(__name__)

class ZeekParser:
    """Parses Zeek TSV (Tab-Separated Values) format."""
    
    def __init__(self):
        self.separator = '\t'
        self.set_separator = ','
        self.empty_field = '(empty)'
        self.unset_field = '-'
        self.fields = []
        self.types = []
        self.path = 'unknown'

    def parse_line(self, line: str):
        """
        Parses a single line from a Zeek log.
        Returns a dictionary of fields if it's a data row.
        Returns None if it's a header/metadata row or empty.
        """
        line = line.rstrip('\n\r')
        if not line:
            return None
            
        if line.startswith('#'):
            self._parse_header(line)
            return None
            
        if not self.fields:
            # We haven't seen the #fields header yet, can't parse data safely
            return None
            
        parts = line.split(self.separator)
        
        # In case the line is malformed
        if len(parts) != len(self.fields):
            logger.debug(f"Malformed line in {self.path} log (expected {len(self.fields)} fields, got {len(parts)})")
            return None
            
        record = {}
        for field, value in zip(self.fields, parts):
            if value == self.unset_field or value == self.empty_field:
                record[field] = None
            else:
                record[field] = value
                
        # Inject the log type so the normalizer knows what it is
        record['_path'] = self.path
        return record

    def _parse_header(self, line: str):
        """Parses Zeek header lines to configure the parser state."""
        parts = line.split()
        if len(parts) < 2:
            return
            
        directive = parts[0]
        
        if directive == '#separator':
            # Format is usually #separator \x09
            sep_val = line[len('#separator '):]
            if sep_val.startswith('\\x'):
                self.separator = chr(int(sep_val[2:], 16))
            else:
                self.separator = sep_val
        elif directive == '#set_separator':
            self.set_separator = parts[1]
        elif directive == '#empty_field':
            self.empty_field = parts[1]
        elif directive == '#unset_field':
            self.unset_field = parts[1]
        elif directive == '#path':
            self.path = parts[1]
        elif directive == '#fields':
            self.fields = line.split(self.separator)[1:]
        elif directive == '#types':
            self.types = line.split(self.separator)[1:]
