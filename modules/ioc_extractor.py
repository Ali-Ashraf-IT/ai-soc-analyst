import re

class IOCExtractor:
    """
    Extracts Indicators of Compromise from normalized events.
    """
    # Common Regex Patterns
    PATTERNS = {
        "ipv4": r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "md5": r'\b[a-fA-F0-9]{32}\b',
        "sha1": r'\b[a-fA-F0-9]{40}\b',
        "sha256": r'\b[a-fA-F0-9]{64}\b',
        "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})\b',
    }
    
    @staticmethod
    def extract(events: list[dict]) -> dict:
        iocs = {
            "ipv4": set(),
            "email": set(),
            "md5": set(),
            "sha1": set(),
            "sha256": set(),
            "domain": set(),
            "users": set(),
            "processes": set(),
        }
        
        for event in events:
            raw = event.get("raw_event", "")
            
            # Regex extraction
            for ioc_type, pattern in IOCExtractor.PATTERNS.items():
                matches = re.findall(pattern, raw)
                for match in matches:
                    # Basic filter for domains to avoid matching common words / extensions wrongly in this simple regex
                    if ioc_type == "domain" and len(match) < 4: continue
                    iocs[ioc_type].add(match)
                    
            # Extracted keys from log parser
            if "user" in event: iocs["users"].add(event["user"])
            if "username" in event: iocs["users"].add(event["username"])
            if "process" in event: iocs["processes"].add(event["process"])
            if "process_name" in event: iocs["processes"].add(event["process_name"])
            
            # Special case for src_ip / dst_ip found from kv pairs
            if "src_ip" in event: iocs["ipv4"].add(event["src_ip"])
            if "dst_ip" in event: iocs["ipv4"].add(event["dst_ip"])
            
        # Convert sets to lists
        return {k: list(v) for k, v in iocs.items() if v}
