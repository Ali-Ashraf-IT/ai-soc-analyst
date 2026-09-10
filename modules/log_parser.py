import re
import json

class LogParser:
    """
    Parses various raw log formats into a normalized internal JSON structure.
    """
    @staticmethod
    def parse_logs(raw_text: str) -> list[dict]:
        normalized_events = []
        lines = raw_text.strip().split('\n')
        
        for idx, line in enumerate(lines):
            if not line.strip():
                continue
                
            event = {
                "event_id": f"EVT-{idx+1}",
                "timestamp": "Unknown",
                "source": "Unknown",
                "raw_event": line.strip()
            }
            
            # Basic JSON parsing
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    event.update(parsed)
                    normalized_events.append(event)
                    continue
            except json.JSONDecodeError:
                pass
            
            # Heuristic Regex Parsing for timestamp (basic YYYY-MM-DD HH:MM:SS)
            timestamp_match = re.search(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}', line)
            if timestamp_match:
                event["timestamp"] = timestamp_match.group(0)
            
            # Extract common key-value pairs (e.g., user=admin src_ip=10.0.0.1)
            kv_pattern = re.compile(r'(\w+)=("[^"]*"|\S+)')
            matches = kv_pattern.findall(line)
            for k, v in matches:
                v = v.strip('"')
                event[k.lower()] = v
                
            # If no key-value pairs, we rely on the raw_event and AI analysis
            normalized_events.append(event)
            
        return normalized_events
