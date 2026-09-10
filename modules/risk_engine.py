class RiskEngine:
    """
    Calculates incident severity and risk score.
    """
    @staticmethod
    def calculate_risk(investigation_result: dict, iocs: dict) -> dict:
        score = 0
        factors = []
        
        # Base score from confidence
        confidence = float(investigation_result.get("confidence", 0.0))
        
        decision = investigation_result.get("decision", "UNKNOWN")
        if "FALSE POSITIVE" in decision or "BENIGN" in decision:
            return {"severity": "Low", "score": 5, "factors": ["Determined as False Positive or Benign"]}
            
        score += confidence * 40
        factors.append(f"AI Confidence {confidence*100}% (+{int(confidence*40)})")
        
        # Add points for IOCs
        if len(iocs.get("ipv4", [])) > 1:
            score += 10
            factors.append("Multiple IP addresses involved (+10)")
        if len(iocs.get("sha256", [])) > 0 or len(iocs.get("md5", [])) > 0:
            score += 20
            factors.append("File hashes detected (+20)")
        if len(iocs.get("processes", [])) > 0:
            score += 15
            factors.append("Process execution detected (+15)")
            
        classification = investigation_result.get("classification", "").lower()
        if "malware" in classification or "ransomware" in classification:
            score += 30
            factors.append("Malware/Ransomware classification (+30)")
        if "credential" in classification:
            score += 20
            factors.append("Credential attack (+20)")
            
        # Cap score at 100
        score = min(int(score), 100)
        
        if score <= 20:
            severity = "Low"
        elif score <= 50:
            severity = "Medium"
        elif score <= 80:
            severity = "High"
        else:
            severity = "Critical"
            
        return {
            "score": score,
            "severity": severity,
            "factors": factors
        }
