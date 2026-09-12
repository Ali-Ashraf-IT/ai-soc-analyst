import re
import json

class LogParser:
    """
    Parses various raw log formats into a normalized internal structure,
    automatically detecting and tagging the log source per event and per batch.
    """

    @staticmethod
    def detect_log_source(line: str) -> str:
        """
        Detects log source environment based on signature patterns.
        """
        l_lower = line.lower()

        # Windows Event Log / Sysmon / Defender
        if any(k in l_lower for k in ["eventid=", "eventid ", "sysmon", "logontype=", "microsoft-windows", "winevent", "privilegeescalation"]):
            return "Windows Event Log"

        # Linux Syslog / SSH / Auth
        if any(k in l_lower for k in ["sshd[", "sudo:", "systemd[", "cron[", "/var/log/", "pam_unix", "session opened for user", "accepted password", "failed password"]):
            return "Linux Auth / Syslog"

        # Network Firewall / IDS / Router
        if any(k in l_lower for k in ["action=block", "action=allow", "proto=tcp", "proto=udp", "paloalto", "fortigate", "pfsense", "iptables", "ufw", "snort", "suricata"]):
            return "Network Firewall / IDS"

        # Web Server (Nginx / Apache / IIS)
        if any(k in l_lower for k in ["get /", "post /", "http/1.1", "http/2.0", " status=200 ", " status=404 ", " status=500 ", "nginx", "apache", "iis"]):
            return "Web Server Log"

        # EDR / Endpoint Detection Trace
        if any(k in l_lower for k in ["process_command_line", "parent_process_name", "crowdstrike", "sentinelone", "defender_atp"]):
            return "EDR Trace"

        return "Generic Security Log"

    @staticmethod
    def parse_logs(raw_text: str) -> dict:
        """
        Parses raw log text and returns normalized events along with detected sources.
        """
        normalized_events = []
        lines = raw_text.strip().split('\n')
        detected_sources = set()

        for idx, line in enumerate(lines):
            line_str = line.strip()
            if not line_str:
                continue

            log_src = LogParser.detect_log_source(line_str)
            detected_sources.add(log_src)

            event = {
                "event_id": f"EVT-{idx+1}",
                "timestamp": "Unknown",
                "log_source": log_src,
                "raw_event": line_str
            }

            # JSON log format parsing
            try:
                parsed = json.loads(line_str)
                if isinstance(parsed, dict):
                    event.update(parsed)
                    event["log_source"] = log_src
                    normalized_events.append(event)
                    continue
            except json.JSONDecodeError:
                pass

            # Timestamp extraction (YYYY-MM-DD HH:MM:SS or Syslog standard format)
            timestamp_match = re.search(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}', line_str)
            if not timestamp_match:
                # Syslog format: Month Day HH:MM:SS (e.g. Sep 10 08:12:01)
                timestamp_match = re.search(r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line_str)
            
            if timestamp_match:
                event["timestamp"] = timestamp_match.group(0)

            # Key-value extraction (e.g., user=admin src_ip=10.0.0.1 action=block)
            kv_pattern = re.compile(r'(\w+)=("[^"]*"|\S+)')
            matches = kv_pattern.findall(line_str)
            for k, v in matches:
                v = v.strip('"')
                event[k.lower()] = v

            normalized_events.append(event)

        return {
            "events": normalized_events,
            "detected_sources": sorted(list(detected_sources)) if detected_sources else ["Generic Security Log"]
        }
