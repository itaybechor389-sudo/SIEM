"""
🛡️ SIEM Detection Rules — 13 Rules mapped to MITRE ATT&CK
Each rule receives a log dict and returns an alert dict or None
"""

RULES = []

def rule(rule_id, name, severity, mitre):
    def decorator(func):
        func.rule_id = rule_id
        func.name = name
        func.severity = severity
        func.mitre = mitre
        RULES.append(func)
        return func
    return decorator


@rule("R01", "Suspicious PowerShell", "HIGH", "T1059.001")
def detect_powershell(log):
    image = log.get("process", {}).get("executable", "").lower()
    cmdline = log.get("process", {}).get("command_line", "").lower()
    flags = ["-enc", "-encodedcommand", "bypass", "hidden", "downloadstring", "invoke-expression", "iex"]
    if "powershell" in image:
        for f in flags:
            if f in cmdline:
                return {"description": f"PowerShell with suspicious flag: {f}", "raw": cmdline[:200]}


@rule("R02", "Hacking Tool Detected", "CRITICAL", "T1588.002")
def detect_hacking_tools(log):
    image = log.get("process", {}).get("executable", "").lower()
    tools = ["mimikatz", "rubeus", "sharphound", "bloodhound", "lazagne", "crackmapexec", "psexec"]
    for t in tools:
        if t in image:
            return {"description": f"Hacking tool: {t}", "raw": image}


@rule("R03", "Network Scan Detected", "MEDIUM", "T1046")
def detect_network_scan(log):
    image = log.get("process", {}).get("executable", "").lower()
    scanners = ["nmap", "masscan", "zenmap", "angry_ip"]
    for s in scanners:
        if s in image:
            return {"description": f"Scanner: {s}", "raw": image}


@rule("R04", "New User Created", "HIGH", "T1136.001")
def detect_new_user(log):
    if str(log.get("event", {}).get("code")) == "4720":
        user = log.get("winlog", {}).get("event_data", {}).get("TargetUserName", "?")
        return {"description": f"New local user: {user}", "raw": user}


@rule("R05", "Registry Run Key Modified", "HIGH", "T1547.001")
def detect_registry_persistence(log):
    if str(log.get("event", {}).get("code")) == "13":
        target = log.get("winlog", {}).get("event_data", {}).get("TargetObject", "")
        if "currentversion\\run" in target.lower():
            return {"description": "Registry Run key modified", "raw": target[:200]}


@rule("R06", "Suspicious Outbound Connection", "HIGH", "T1571")
def detect_suspicious_connection(log):
    if str(log.get("event", {}).get("code")) == "3":
        port = log.get("winlog", {}).get("event_data", {}).get("DestinationPort", "")
        ip = log.get("winlog", {}).get("event_data", {}).get("DestinationIp", "")
        if port in ["4444", "5555", "8888", "1337", "6666", "9999"]:
            return {"description": f"Suspicious port {port} -> {ip}", "raw": f"{ip}:{port}"}


@rule("R07", "Brute Force Attempt", "HIGH", "T1110")
def detect_brute_force(log):
    if str(log.get("event", {}).get("code")) == "4625":
        user = log.get("winlog", {}).get("event_data", {}).get("TargetUserName", "?")
        src = log.get("winlog", {}).get("event_data", {}).get("IpAddress", "?")
        return {"description": f"Failed login: {user} from {src}", "raw": f"User: {user} | Source: {src}"}


@rule("R08", "Suspicious CMD from Office", "HIGH", "T1204.002")
def detect_suspicious_cmd(log):
    image = log.get("process", {}).get("executable", "").lower()
    parent = log.get("process", {}).get("parent", {}).get("executable", "").lower()
    if "cmd.exe" in image:
        for p in ["winword", "excel", "outlook", "powerpnt", "wscript"]:
            if p in parent:
                return {"description": f"CMD from {parent}", "raw": f"{parent} -> cmd.exe"}


@rule("R09", "Lateral Movement", "CRITICAL", "T1021")
def detect_lateral_movement(log):
    if str(log.get("event", {}).get("code")) == "4624":
        if str(log.get("winlog", {}).get("event_data", {}).get("LogonType")) == "3":
            src = log.get("winlog", {}).get("event_data", {}).get("IpAddress", "?")
            user = log.get("winlog", {}).get("event_data", {}).get("TargetUserName", "?")
            return {"description": f"Network logon: {user} from {src}", "raw": f"{user}@{src} Type:3"}


@rule("R10", "Scheduled Task Created", "MEDIUM", "T1053.005")
def detect_scheduled_task(log):
    image = log.get("process", {}).get("executable", "").lower()
    cmdline = log.get("process", {}).get("command_line", "").lower()
    if "schtasks" in image and "/create" in cmdline:
        return {"description": "New scheduled task", "raw": cmdline[:200]}


@rule("R11", "New Service Installed", "HIGH", "T1543.003")
def detect_service_install(log):
    if str(log.get("event", {}).get("code")) == "7045":
        svc = log.get("winlog", {}).get("event_data", {}).get("ServiceName", "?")
        return {"description": f"New service: {svc}", "raw": svc}


@rule("R12", "Suspicious DNS (C2)", "MEDIUM", "T1071.004")
def detect_suspicious_dns(log):
    if str(log.get("event", {}).get("code")) == "22":
        query = log.get("winlog", {}).get("event_data", {}).get("QueryName", "")
        if len(query) > 50 or query.count(".") > 4:
            return {"description": f"Suspicious DNS: {query}", "raw": query}


@rule("R13", "Executable Dropped in Temp", "MEDIUM", "T1105")
def detect_temp_file(log):
    if str(log.get("event", {}).get("code")) == "11":
        target = log.get("winlog", {}).get("event_data", {}).get("TargetFilename", "")
        if "\\temp\\" in target.lower() or "\\tmp\\" in target.lower():
            for ext in [".exe", ".dll", ".bat", ".ps1", ".vbs", ".hta"]:
                if target.lower().endswith(ext):
                    return {"description": f"Dropped in Temp: {target}", "raw": target[:200]}
