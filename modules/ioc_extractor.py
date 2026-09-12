import re

class IOCExtractor:
    """
    Extracts Indicators of Compromise (IOCs) from normalized events with strict type validation.
    """
    # Common Regex Patterns
    PATTERNS = {
        "ipv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        "email": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        "md5": r'\b[a-fA-F0-9]{32}\b',
        "sha1": r'\b[a-fA-F0-9]{40}\b',
        "sha256": r'\b[a-fA-F0-9]{64}\b',
        "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    }

    # File extensions that must NOT be misclassified as domain names
    NON_DOMAIN_EXTENSIONS = {
        'php', 'sh', 'exe', 'py', 'dll', 'service', 'bat', 'js', 'txt', 'log',
        'csv', 'json', 'html', 'css', 'bin', 'zip', 'tar', 'gz', 'ps1', 'conf',
        'ini', 'so', 'sys', 'dat', 'xml', 'yml', 'yaml', 'pl', 'rb', 'c', 'cpp', 'h'
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
            "files": set(),
            "users": set(),
            "processes": set(),
        }

        for event in events:
            raw = event.get("raw_event", "")

            # Regex extraction
            for ioc_type, pattern in IOCExtractor.PATTERNS.items():
                matches = re.findall(pattern, raw)
                for match in matches:
                    if ioc_type == "domain":
                        ext = match.split('.')[-1].lower()
                        # If extension is a file extension (e.g., .php, .sh, .service), treat as file/script, not domain!
                        if ext in IOCExtractor.NON_DOMAIN_EXTENSIONS:
                            iocs["files"].add(match)
                            continue
                        if len(match) < 4:
                            continue
                    iocs[ioc_type].add(match)

            # Extracted keys from log parser
            for u_key in ("user", "username", "account", "src_user", "dst_user"):
                if u_key in event and event[u_key]:
                    iocs["users"].add(str(event[u_key]))

            for p_key in ("process", "process_name", "proc", "cmd", "command"):
                if p_key in event and event[p_key]:
                    iocs["processes"].add(str(event[p_key]))

            for f_key in ("file", "filename", "filepath", "script"):
                if f_key in event and event[f_key]:
                    iocs["files"].add(str(event[f_key]))

            # Key-value pairs for IPs
            if "src_ip" in event: iocs["ipv4"].add(event["src_ip"])
            if "dst_ip" in event: iocs["ipv4"].add(event["dst_ip"])

        # Convert sets to sorted lists
        return {k: sorted(list(v)) for k, v in iocs.items() if v}
