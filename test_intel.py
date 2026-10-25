from intel.threatfox import query_threatfox

target_ip = "45.131.214.85"
print(f"[*] Querying ThreatFox API for: {target_ip}...")
result = query_threatfox(target_ip)

if result["match"]:
    print("[+] MATCH FOUND IN THREAT INTEL DATABASE")
    print(f"    Malware Family : {result['malware_name']}")
    print(f"    Threat Type    : {result['threat_type']}")
    print(f"    Confidence     : {result['confidence']}%")
else:
    print("[-] Indicator not listed in active ThreatFox database (unlisted or ephemeral C2).")
