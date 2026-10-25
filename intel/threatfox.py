import requests

def query_threatfox(indicator: str) -> dict:
    """
    Queries the abuse.ch ThreatFox open API for known C2 indicators (IP or domain).
    No API key required.
    """
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {
        "query": "search_ioc",
        "search_term": indicator.strip()
    }
    
    try:
        response = requests.post(url, json=payload, timeout=5)
        data = response.json()
        
        if data.get("query_status") == "ok" and data.get("data"):
            hit = data["data"][0]
            return {
                "match": True,
                "malware_name": hit.get("malware_printable", "Unknown Malware"),
                "confidence": hit.get("confidence_level", 0),
                "threat_type": hit.get("threat_type_desc", "Botnet / C2"),
                "reporter": hit.get("reporter", "Unknown")
            }
    except Exception:
        pass
        
    return {"match": False}
