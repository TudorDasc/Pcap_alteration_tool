from idstools import rule as idsRule
import re

# Mapping the bucket files to mitre tags
TRANSLATION = {
    "2014-6271": "T1210",
    "android_c2": "T1041",
    "apt_c2": "T1071",
    "beacon activity": "T1071",
    "bruteforce": "T1110",
    "C2_activity_http": "T1071",
    "C2_activity_tcp": "T1095",
    "C2_bot app": "T1071",
    "C2_bot tcp": "T1095",
    "C2_dns": "T1071",
    "C2_domain_app": "T1071",
    "C2_domain_tls": "T1573",
    "C2_in_out app": "T1071",
    "C2_in_out other": "T1095",
    "C2_out_in app": "T1071",
    "C2_out_in": "T1095",
    "C2_ransomware app": "T1071",
    "C2_server_app": "T1071",
    "C2_server_noapp": "T1095",
    "C2_traffic_app": "T1071",
    "C2_traffic_nonapp": "T1095",
    "Cobalt Strike Activity": "T1041",
    "Cobalt Strike_c2": "T1071",
    "coinminer_auth": "T1496",
    "coinminer_c2": "T1496",
    "compromised server": "T1584",
    "crawling": "T1593",
    "credit card skimming": "T1041",
    "default-login-attempt": "T0812",
    "default-login": "T0812",
    "dns lookup": "T1071",
    "dns query": "T1071",
    "dos": "T1498",
    "Downloader Activity app layer": "T1105",
    "drive-by exploit": "T1189",
    "dynamic dns query": "T1568",
    "dynamic http request to domain": "T1568",
    "exe download": "T1105",
    "exfil_steal_c2": "T1041",
    "exfil_via_alternative_protocol": "T1048",
    "exfil_via_web_service": "T1567",
    "EXPLOIT_KIT landing": "T1189",
    "external-ip-check": "T1016",
    "firmware exploit": "T1190",
    "flooder_c2 app": "T1071",
    "flooder_c2 noapp": "T1095",
    "flood": "T1498",
    "http request to domain": "T1071",
    "HTTP traffic on port 443": "T1571",
    "Internet Explorer Use-After-Free": "T1189",
    "in_any_backdoor": "T1568",
    "in_out_spy app": "T1071",
    "in_out_spy noapp": "T1095",
    "ja3 hash": "T1573",
    "lateral movement_smb": "T1021",
    "malware download URL": "T1105",
    "malware lookup": "T1590",
    "malware sni": "T1573",
    "memory corruption from_server": "T1190",
    "memory corruption rest": "T1190",
    "Metasploit Meterpreter Reverse": "T1059",
    "mirai login": "T0812",
    "mirai user agent inbound": "T1190",
    "mirai user agent outbound": "T1071",
    "netbios bind attempt": "T1190",
    "network-scan": "T1595",
    "obf string": "T1027",
    "onion proxy domain": "T1090",
    "overflow": "T1190",
    "payload delivery": "T1105",
    "PHISHING_credentials": "T1598",
    "PHISHING_dns": "T1566",
    "PHISHING_domain": "T1566",
    "PHISHING_kit": "T1566",
    "PHISHING_landing": "T1598",
    "PHISHING_redirect": "T1598",
    "PHISHING_remaining": "T1566",
    "PHISHING_request": "T1598",
    "PHISHING_succesful": "T1598",
    "Phone Scam Landing": "T1566",
    "port scan": "T1595",
    "powershell exe string": "T1059",
    "pup-activity": "T1204",
    "ransomware domain payment": "T1486",
    "RAT_c2": "T1219",
    "RAT_checkin": "T1219",
    "RAT_malware": "T1219",
    "remote code execution": "T1190",
    "remote file inclusion": "T1190",
    "Retrieving Payload": "T1105",
    "RPC portmap": "T1595",
    "Screenshot_cnc": "T1113",
    "Screenshot": "T1113",
    "Set-Cookie": "T1189",
    "silverfish activity c&c": "T1095",
    "silverfish activity scripts": "T1104",
    "silverfish activity javascript": "T1104",
    "silverfish activity server": "T1071",
    "SOCKS request": "T1133",
    "spam_mail": "T1491",
    "sql injection attempt": "T1190",
    "sql injection": "T1190",
    "ssl_tls cert phish": "T1566",
    "ssl_tls cert": "T1573",
    "sundown_exploit": "T1189",
    "suspicious file": "T1204",
    "suspicious ua": "T1071",
    "system_enumeration": "T1082",
    "Tech Support Scam": "T1566",
    "user execution": "T1204",
    "webshell backdoor": "T1505",
    "webshell": "T1505",
    "web_plugin": "T1190",
    "WEB_SPECIFIC_APPS File Inclusion local": "T1190",
    "WEB_SPECIFIC_APPS File Inclusion remote": "T1190",
    "win32_c2": "T1071",
    "xss": "T1189",
    "ysoserial_java": "T1190",
    "ysoserial_post": "T1190",
    "ysoserial_uri": "T1190",
    "C2_ransomware": "T1071",
    "memory corruption": "T1190",
    "Downloader Activity": "T1105",
    "T1140": "T1140",
    "T1595": "T1595",
    "T1190": "T1190",
    "T1595": "T1595",
    "T1055": "T1055",
    "T595": "T595",
    "T1071": "T1071",
    "T1078": "T1078",
    "T1568": "T1568",
    "T1129": "T1129",
    "T1210": "T1210",
    "T1568": "T1568",
    "T1595": "T1595",
    "T1048": "T1048",
    "T1090": "T1090",
    "T1110": "T1110",
}

HARD_CODED = {
    2022858: "suspicious ua",
    2008738: "suspicious ua",
    2021076: "exfil_steal_c2",
    2837960: "exfil_steal_c2",
    2835300: "pup-activity",
}


def getIndex(l, key):
    for i in range(len(l)):
        if l[i]["name"] == key:
            return i
    return -1


def reParse(r):
    new_rule_string = "%s%s (%s)" % (
        "" if r.enabled else "# ",
        r["header"].strip(),
        r.rebuild_options(),
    )
    # print(r)
    # print(new_rule_string)
    return idsRule.parse(new_rule_string)


def translate(text):
    if text in TRANSLATION:
        return TRANSLATION[text]
    else:
        print("Missing translation: " + text)
        return ""


class RuleTransformer:
    def __init__(self, option_name):
        self.option_name = option_name

    def ruleTransform(self, rule, text):
        # if(not rule.metadata):
        #     rule = idsRule.add_option(rule, 'metadata', [])
        # r = idsRule.add_option(idsRule.remove_option(rule, "metadata"), 'metadata', " "+" ".join([option_name + " " + translate(text)] + rule.metadata))
        index = getIndex(rule.options, "metadata")

        if index == -1:
            rule.options.append({"name": "metadata", "value": ""})
            metadata_array = []
            index = getIndex(rule.options, "metadata")
        else:
            metadata_array = rule.options[index]["value"].split(", ")

        metadata_array.append(self.option_name + " " + translate(text))
        rule.options[index]["value"] = ", ".join(metadata_array)

        return reParse(rule)

    def passRegex(self, rule):
        message = rule.msg.lower()

        if rule.sid in HARD_CODED:
            r = self.ruleTransform(rule, HARD_CODED[rule.sid])

        elif re.search("(?=.*mirai) (?=.*login)", message):
            r = self.ruleTransform(rule, "mirai login")

        elif re.search("ADWARE_PUP|MALWARE PUP", rule.msg):
            r = self.ruleTransform(rule, "pup-activity")

        elif re.search("(?=.*(ssl/tls cert|malicious ssl cert))(?=.*phish)", message):
            r = self.ruleTransform(rule, "ssl_tls cert phish")

        elif re.search("(?=.*(ssl/tls cert|malicious ssl cert))(?=.*coin)", message):
            r = self.ruleTransform(rule, "coinminer_c2")

        elif re.search("(ssl/tls cert|malicious ssl cert)", message) and not re.search(
            "phish|coin", message
        ):
            r = self.ruleTransform(rule, "ssl_tls cert")

        elif re.search("http", message) and re.search("443", message):
            r = self.ruleTransform(rule, "HTTP traffic on port 443")

        elif re.search("system|network|file|dir|host|os", message) and re.search(
            "enumerat", message
        ):
            r = self.ruleTransform(rule, "system_enumeration")

        elif re.search("exploit", message) and re.search("sundown", message):
            r = self.ruleTransform(rule, "sundown_exploit")

        elif re.search("phish", message) and re.search("landing|page", message):
            r = self.ruleTransform(rule, "PHISHING_landing")

        elif re.search("credential phish |password phish |credential theft", message):
            r = self.ruleTransform(rule, "PHISHING_credentials")

        elif re.search("phish", message) and re.search("kit ", message):
            r = self.ruleTransform(rule, "PHISHING_kit")

        elif re.search("phish", message) and re.search("redirect", message):
            r = self.ruleTransform(rule, "PHISHING_redirect")

        elif re.search("phish", message) and re.search("dns", message):
            r = self.ruleTransform(rule, "PHISHING_dns")

        elif re.search("phish", message) and re.search("request", message):
            r = self.ruleTransform(rule, "PHISHING_request")

        elif re.search("phish", message) and re.search("domain", message):
            r = self.ruleTransform(rule, "PHISHING_domain")

        elif re.search("phish", message) and re.search("succesful|successful", message):
            r = self.ruleTransform(rule, "PHISHING_succesful")

        elif re.search("phish", message):
            r = self.ruleTransform(rule, "PHISHING_remaining")

        elif re.search("(?=.*fireeye)(?=.*backdoor)", message) and re.search(
            "http|https|dns", rule.header
        ):
            r = self.ruleTransform(rule, "C2_traffic_app")

        elif re.search("(?=.*fireeye)(?=.*backdoor)", message) and re.search(
            "tls", rule.header
        ):
            r = self.ruleTransform(rule, "C2_domain_tls")

        elif re.search("(?=.*netbios) (?=.*bind attempt)", message):
            r = self.ruleTransform(rule, "netbios bind attempt")

        elif re.search("phone scam landing", message):
            r = self.ruleTransform(rule, "Phone Scam Landing")

        elif re.search("retrieving payload", message):
            r = self.ruleTransform(rule, "Retrieving Payload")

        elif re.search("downloader activity", message) and re.search(
            "http\.method|GET|POST", str(rule)
        ):
            r = self.ruleTransform(rule, "Downloader Activity app layer")

        elif re.search("downloader activity", message):
            r = self.ruleTransform(rule, "Downloader Activity")
            # r = rule

        elif re.search("set-cookie", message):
            r = self.ruleTransform(rule, "Set-Cookie")

        elif re.search(
            "(?=.*WEB_SPECIFIC_APPS) (?=.*File Inclusion)", rule.msg
        ) and re.search("local", message):
            r = self.ruleTransform(rule, "WEB_SPECIFIC_APPS File Inclusion local")

        elif re.search("(?=.*WEB_SPECIFIC_APPS) (?=.*File Inclusion)", rule.msg):
            r = self.ruleTransform(rule, "WEB_SPECIFIC_APPS File Inclusion remote")

        elif re.search("Internet Explorer Use-After-Free", rule.msg):
            r = self.ruleTransform(rule, "Internet Explorer Use-After-Free")

        elif re.search("(?=.*exploit) (?=.*firmware)", message):
            r = self.ruleTransform(rule, "firmware exploit")

        elif re.search("remote code execution", message):
            r = self.ruleTransform(rule, "remote code execution")

        elif re.search("remote file inclu", message):
            r = self.ruleTransform(rule, "remote file inclusion")

        elif re.search("(?=.*exploit) (?=.*driveby|drive by|drive-by)", message):
            r = self.ruleTransform(rule, "drive-by exploit")

        elif re.search("2014-6271", str(rule)):
            r = self.ruleTransform(rule, "2014-6271")

        elif re.search("(?=.*obfusc) (?=.*string)", message):
            r = self.ruleTransform(rule, "obf string")

        elif re.search("(?=.*socks)(?=.*request)(?=.*inbound)", message):
            r = self.ruleTransform(rule, "SOCKS request")

        elif re.search("lateral movement", message) and re.search(
            "smb|ssh|vnc|winrm", message
        ):
            r = self.ruleTransform(rule, "lateral movement_smb")

        elif re.search("lateral movement", message) and re.search(
            "smb|ssh|vnc", rule.header
        ):
            r = self.ruleTransform(rule, "lateral movement_smb")

        elif re.search("(?=.*exe) (?=.*download)", message):
            r = self.ruleTransform(rule, "exe download")

        elif re.search("(?=.*mail) (?=.*spam)", message):
            r = self.ruleTransform(rule, "spam_mail")

        elif re.search(
            "spambot| spam bot| spam campaign|spammer", message
        ) and re.search("http|https|dns|smtp", str(rule).lower()):
            r = self.ruleTransform(rule, "C2_traffic_app")

        elif re.search(
            "spambot| spam bot| spam campaign|spammer", message
        ) and re.search("tcp|udp", str(rule).lower()):
            r = self.ruleTransform(rule, "C2_traffic_nonapp")

        elif (
            re.search("flood", message)
            and re.search("cnc|c&c|cc|c2|checkin|command and control", message)
            and re.search("http|https|dns", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "flooder_c2 app")

        elif (
            re.search("flood", message)
            and re.search("cnc|c&c|cc|c2|checkin", message)
            and re.search("tcp|udp", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "flooder_c2 noapp")

        elif re.search("flood", message):
            r = self.ruleTransform(rule, "flood")

        elif re.search("screenshot", message) and re.search("cnc", message):
            r = self.ruleTransform(rule, "Screenshot_cnc")

        elif re.search("screenshot", message):
            r = self.ruleTransform(rule, "Screenshot")

        elif re.search("beacon", message):
            r = self.ruleTransform(rule, "beacon activity")

        elif re.search("cobalt strike activity", message):
            r = self.ruleTransform(rule, "Cobalt Strike Activity")

        elif re.search("(?=.*web|link|page)(?=.*crawl)", message):
            r = self.ruleTransform(rule, "crawling")

        elif re.search("tech support scam", message):
            r = self.ruleTransform(rule, "Tech Support Scam")

        elif re.search("(?=.*default)(?=.*login)", message):
            r = self.ruleTransform(rule, "default-login-attempt")

        elif re.search("(?=.*default)(?=.*password)", message):
            r = self.ruleTransform(rule, "default-login-attempt")

        elif re.search(
            r"(?=.*suspicious)(?=.*(\bua\b|user agent|user-agent))", message
        ):
            r = self.ruleTransform(rule, "suspicious ua")

        elif re.search("fake browser", message):
            r = self.ruleTransform(rule, "suspicious ua")

        elif rule.classtype != None and re.search("network-scan", rule.classtype) and re.search("scan", message):
            r = self.ruleTransform(rule, "network-scan")

        elif re.search("rpc portmap", message):
            r = self.ruleTransform(rule, "RPC portmap")

        elif re.search("(?=.*silverfish)(?=.*activity)", message) and re.search(
            "server", message
        ):
            r = self.ruleTransform(rule, "silverfish activity server")

        elif re.search("(?=.*silverfish) (?=.*activity)", message) and re.search(
            "scripts", message
        ):
            r = self.ruleTransform(rule, "silverfish activity scripts")

        elif re.search("(?=.*silverfish) (?=.*activity)", message) and re.search(
            "javascript", message
        ):
            r = self.ruleTransform(rule, "silverfish activity javascript")

        elif re.search("credit card skimming", message):
            r = self.ruleTransform(rule, "credit card skimming")

        elif re.search("AbaddonPOS", rule.msg):
            r = self.ruleTransform(rule, "credit card skimming")

        elif re.search(
            '^(?=.*msg:"((?=(((.* backdoor)(.* web)|(.* web)(.* backdoor))).*?("\;)+?))).*$',
            str(rule).lower(),
        ):
            r = self.ruleTransform(rule, "webshell backdoor")

        elif re.search("(?=.*ransomware)(?=.*domain)(?=.*payment)", message):
            r = self.ruleTransform(rule, "ransomware domain payment")

        elif re.search(
            "(?=.*ransomware)(?=.*domain)^((?!payment).)*$", message
        ) and re.search("http|dns", str(rule)):
            r = self.ruleTransform(rule, "C2_traffic_app")

        elif re.search(
            "(?=.*ransomware)(?=.*domain)^((?!payment).)*$", message
        ) and re.search("tls|ssl", str(rule)):
            r = self.ruleTransform(rule, "C2_domain_tls")

        elif re.search("onion proxy domain", message):
            r = self.ruleTransform(rule, "onion proxy domain")

        elif re.search("metasploit meterpreter reverse", message):
            r = self.ruleTransform(rule, "Metasploit Meterpreter Reverse")

        elif re.search("powershell execution string", message):
            r = self.ruleTransform(rule, "powershell exe string")

        elif re.search("(sql injection|sqli)", message) and re.search(
            "(attempt)", message
        ):
            r = self.ruleTransform(rule, "sql injection attempt")

        elif re.search("sql", message) and re.search("(injection)", message):
            r = self.ruleTransform(rule, "sql injection")

        elif (
            re.search("exfil|report", message)
            and re.search("via", message)
            and re.search("telegram|webhook|discord", message)
        ):
            r = self.ruleTransform(rule, "exfil_via_web_service")

        elif re.search("exfil|report", message) and re.search(
            "smtp|ftp|http|https|dns|smb|udp|mail", message
        ):
            r = self.ruleTransform(rule, "exfil_via_alternative_protocol")

        elif re.search("exfil|report", message) and re.search(
            "smtp|ftp|http|https|dns|smb|mail|ssl|tls", rule.header
        ):
            r = self.ruleTransform(rule, "exfil_via_alternative_protocol")

        elif re.search("(?=.*suspicious) (?=.*filename)", message):
            r = self.ruleTransform(rule, "suspicious file")

        elif rule.classtype != None and re.search("external-ip-check", rule.classtype):
            r = self.ruleTransform(rule, "external-ip-check")

        elif re.search("GeoIP Lookup|Geolocation Lookup|external ip lookup", rule.msg):
            r = self.ruleTransform(rule, "external-ip-check")

        elif re.search("ip lookup", message) and re.search(
            "\$HOME_NET any ->", rule.header
        ):
            r = self.ruleTransform(rule, "external-ip-check")

        elif (
            re.search("miner", message)
            and re.search("coin", message)
            and re.search("auth", message)
        ):
            r = self.ruleTransform(rule, "coinminer_auth")

        elif re.search("coin", message) and re.search("cnc|c2|c&c|checkin", message):
            r = self.ruleTransform(rule, "coinminer_c2")

        elif re.search(" dos | ddos |denial of service|denial-of-service", message):
            r = self.ruleTransform(rule, "dos")

        elif re.search("(?=.*mirai)(.*(ua|user agent|user-agent))(.*inbound)", message):
            r = self.ruleTransform(rule, "mirai user agent inbound")

        elif re.search(
            "(?=.*mirai)(.*(ua|user agent|user-agent))(.*outbound)", message
        ):
            r = self.ruleTransform(rule, "mirai user agent outbound")

        elif re.search("(?=.*port) (?=.*scan)", message):
            r = self.ruleTransform(rule, "port scan")

        elif re.search("bruteforce|brute force|brute-force", message):
            r = self.ruleTransform(rule, "bruteforce")

        elif re.search("cross-site| xss |cross site", message):
            r = self.ruleTransform(rule, "xss")

        elif re.search("web", message) and re.search("plugin|extension", message):
            r = self.ruleTransform(rule, "web_plugin")

        elif re.search("ysoserial", message) and re.search("java", message):
            r = self.ruleTransform(rule, "ysoserial_java")

        elif re.search("ysoserial", message) and re.search("post", message):
            r = self.ruleTransform(rule, "ysoserial_post")

        elif re.search("ysoserial", message) and re.search("uri|header", message):
            r = self.ruleTransform(rule, "ysoserial_uri")

        elif re.search(
            "via doc|via xls|via rtf|via document|via txt|via pdf|via png|via jpeg|via image|via xlt",
            message,
        ):
            r = self.ruleTransform(rule, "user execution")

        elif re.search("memory corruption", message):
            r = self.ruleTransform(rule, "memory corruption")
            # r = rule

        elif re.search("(?=.*payload)(?=.*delivery)", message):
            r = self.ruleTransform(rule, "payload delivery")

        elif re.search("^urlhaus .* malware download url detected", message):
            r = self.ruleTransform(rule, "malware download URL")

        elif re.search(" overflow", message):
            r = self.ruleTransform(rule, "overflow")

        elif re.search("dns lookup|domain lookup", message):
            r = self.ruleTransform(rule, "dns lookup")

        elif re.search("ja3 hash", message):
            r = self.ruleTransform(rule, "ja3 hash")

        elif re.search("related domain", message) and re.search(
            "http|dns", str(rule).lower()
        ):
            r = self.ruleTransform(rule, "C2_traffic_app")

        elif re.search("related domain", message) and re.search(
            "tls", str(rule).lower()
        ):
            r = self.ruleTransform(rule, "C2_domain_tls")

        elif re.search("EXPLOIT_KIT", rule.msg) and re.search("landing", message):
            r = self.ruleTransform(rule, "EXPLOIT_KIT landing")

        elif re.search("http request to", message) and re.search("dynamic", message):
            r = self.ruleTransform(rule, "dynamic http request to domain")

        elif re.search("lookup", message) and re.search("dynamic", message):
            r = self.ruleTransform(rule, "dynamic http request to domain")

        elif re.search("domain generation algorithm", message):
            r = self.ruleTransform(rule, "dynamic http request to domain")

        elif re.search("http request to", message):
            r = self.ruleTransform(rule, "http request to domain")

        elif re.search("dns", message) and re.search("dynamic", message):
            r = self.ruleTransform(rule, "dynamic dns query")

        elif re.search("dyndns", message):
            r = self.ruleTransform(rule, "dynamic dns query")

        elif re.search("dns query", message):
            r = self.ruleTransform(rule, "dns query")

        elif (
            re.search("suspicious|observed", message)
            and re.search("domain", message)
            and re.search("dynamic", message)
        ):
            r = self.ruleTransform(rule, "dynamic dns query")

        elif (
            re.search("suspicious|observed", message)
            and re.search("domain", message)
            and re.search("tls", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "C2_domain_tls")

        elif (
            re.search("suspicious|observed", message)
            and re.search("domain", message)
            and re.search("http|dns", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "C2_traffic_app")

        elif re.search("compromised", message) and re.search("server", message):
            r = self.ruleTransform(rule, "compromised server")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("ransomware", message)
            and re.search("http|https|dns|smtp", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "C2_ransomware app")

        elif re.search("c2|cnc|command-and-control|c&c", message) and re.search(
            "ransomware", message
        ):
            r = self.ruleTransform(rule, "C2_ransomware")
            # r = rule

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("bot", message)
            and re.search("http|dns", str(rule))
        ):
            r = self.ruleTransform(rule, "C2_bot app")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("bot", message)
            and re.search("tcp", rule.header)
        ):
            r = self.ruleTransform(rule, "C2_bot tcp")

        elif re.search("c2|cnc|command-and-control|c&c", message) and re.search(
            "tls", rule.header
        ):
            r = self.ruleTransform(rule, "C2_domain_tls")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("domain", message)
            and re.search(" sni", message)
        ):
            r = self.ruleTransform(rule, "C2_domain_tls")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("domain", message)
            and re.search("dns|http", rule.header)
        ):
            r = self.ruleTransform(rule, "C2_domain_app")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("inbound|outbound", message)
            and re.search("http|dns", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "C2_traffic_app")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("inbound|outbound", message)
            and re.search("tcp|udp", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "C2_traffic_nonapp")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("traffic", message)
            and re.search("tcp|udp", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "C2_traffic_nonapp")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("traffic", message)
            and re.search("http", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "C2_traffic_app")

        elif re.search("c2|cnc|command-and-control|c&c", message) and re.search(
            "dns", message
        ):
            r = self.ruleTransform(rule, "C2_dns")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("server", message)
            and re.search("ip|tcp", rule.header)
        ):
            r = self.ruleTransform(rule, "C2_server_noapp")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("server", message)
            and re.search("http|dns", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "C2_server_app")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("activity", message)
            and re.search("http", str(rule))
        ):
            r = self.ruleTransform(rule, "C2_activity_http")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("checkin", message)
            and re.search("http|smtp|dns|smb", str(rule))
        ):
            r = self.ruleTransform(rule, "C2_traffic_app")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("checkin", message)
            and re.search("udp|tcp", str(rule))
        ):
            r = self.ruleTransform(rule, "C2_traffic_nonapp")

        elif re.search("c2|cnc|command-and-control|c&c", message) and re.search(
            "apt", message
        ):
            r = self.ruleTransform(rule, "apt_c2")

        elif re.search("c2|cnc|command-and-control|c&c", message) and re.search(
            "exfil|steal", message
        ):
            r = self.ruleTransform(rule, "exfil_steal_c2")

        elif re.search("c2|cnc|command-and-control|c&c", message) and re.search(
            "cobalt strike", message
        ):
            r = self.ruleTransform(rule, "Cobalt Strike_c2")

        elif re.search("c2|cnc|command-and-control|c&c", message) and re.search(
            "rat", message
        ):
            r = self.ruleTransform(rule, "RAT_c2")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("activity", message)
            and re.search("tcp", rule.header)
        ):
            r = self.ruleTransform(rule, "C2_activity_tcp")

        elif re.search("c2|cnc|command-and-control|c&c", message) and re.search(
            "sni", message
        ):
            r = self.ruleTransform(rule, "malware sni")

        elif re.search("c2|cnc|command-and-control|c&c", message) and re.search(
            "android", message
        ):
            r = self.ruleTransform(rule, "android_c2")

        elif re.search("c2|cnc|command-and-control|c&c", message) and re.search(
            "win32", message
        ):
            r = self.ruleTransform(rule, "win32_c2")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("\$HOME_NET any -> \$EXTERNAL_NET", rule.header)
            and re.search("http", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "C2_in_out app")

        elif (
            re.search("c2|cnc|command-and-control|c&c", message)
            and re.search("\$HOME_NET any -> \$EXTERNAL_NET", rule.header)
            and re.search("tcp|udp|ftp", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "C2_in_out other")

        elif re.search(" c2 | cnc |command-and-control|c&c", message) and re.search(
            "http|https|dns", str(rule).lower()
        ):
            r = self.ruleTransform(rule, "C2_out_in app")

        elif re.search(" c2 | cnc |command-and-control|c&c", message):
            r = self.ruleTransform(rule, "C2_out_in")

        elif re.search("(?=.*web_server) (?=.*webshell)", message):
            r = self.ruleTransform(rule, "webshell")

        elif (
            re.search("HOME_NET any -> \\$EXTERNAL_NET", rule.header)
            and re.search("spy", message)
            and re.search("http|https|smtp|dns", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "in_out_spy app")

        elif (
            re.search("HOME_NET any -> \\$EXTERNAL_NET", rule.header)
            and re.search("spy", message)
            and re.search("tls", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "C2_domain_tls")

        elif (
            re.search("HOME_NET any -> \\$EXTERNAL_NET", rule.header)
            and re.search("spy", message)
            and re.search("udp|tcp", str(rule).lower())
        ):
            r = self.ruleTransform(rule, "in_out_spy noapp")

        elif re.search("HOME_NET any -> \\$EXTERNAL_NET", rule.header) and re.search(
            "rat checkin", message
        ):
            r = self.ruleTransform(rule, "RAT_checkin")

        elif (
            re.search("HOME_NET any -> any", rule.header)
            and re.search("backdoor", message)
            and re.search("ccleaner", message)
        ):
            r = self.ruleTransform(rule, "in_any_backdoor")

        elif re.search("(?=.*malware)(?=.* sni)", message):
            r = self.ruleTransform(rule, "malware sni")

        elif re.search("(?=.*rat)(?=.* sni)", message):
            r = self.ruleTransform(rule, "malware sni")

        elif re.search("(?=.*malware) (?=.*checkin)", message) and re.search(
            "http|icmp|ftp|smtp|dns|ssh", str(rule).lower()
        ):
            r = self.ruleTransform(rule, "C2_traffic_app")

        elif re.search("(?=.*malware) (?=.*checkin)", message) and re.search(
            "tcp|udp", str(rule).lower()
        ):
            r = self.ruleTransform(rule, "C2_traffic_nonapp")

        elif re.search("(?=.*malware) (?=.*report)", message) and re.search(
            "http|icmp|ftp|smtp|dns|ssh", str(rule).lower()
        ):
            r = self.ruleTransform(rule, "C2_traffic_app")

        elif re.search("(?=.*malware) (?=.*report)", message) and re.search(
            "tcp|udp", str(rule).lower()
        ):
            r = self.ruleTransform(rule, "C2_traffic_nonapp")

        elif re.search(
            '^(?=.*msg:"((?=((.*prox)(.*(cnc|c&c| cc | c2 |checkin|command and control))|(.*(cnc|c&c| cc | c2 |checkin|command and control)(.*prox))).*?("\;)+?))).*$',
            str(rule).lower(),
        ):
            r = self.ruleTransform(rule, "silverfish activity c&c")

        elif re.search("RAT", rule.msg) and re.search("checkin", message):
            r = self.ruleTransform(rule, "RAT_checkin")

        elif re.search("RAT", rule.msg) and re.search("c2|cnc", message):
            r = self.ruleTransform(rule, "RAT_c2")

        elif re.search("rat", message) and re.search("malware", message):
            r = self.ruleTransform(rule, "RAT_malware")

        # Toms regex for common alerts
        elif re.search("Generic eval of base64_decode", rule.msg):
            r = self.ruleTransform(rule, "T1140")
        elif re.search("Fuzz Faster U Fool", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Path Traversal Attempt", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("Empty If-Modified-Since Header", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Empty Referer Header", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Empty Accept-Language Header", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("log4j", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("ScannerBot", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("log4j", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("ICMP_INFO PING", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Suspicious Empty Host Header", rule.msg):
            r = self.ruleTransform(rule, "T595")
        elif re.search("PHP Easteregg Information-Disclosure", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("File Inclusion Attempt", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("Information Leak Attempt Inbound", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Password Exposure via sftp-config.json", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Suspicious X25 DNS Request Outbound", rule.msg):
            r = self.ruleTransform(rule, "T1071")
        elif re.search("Request for config.json", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Unauthenticated Credential Disclosure", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("PowerShell String Base64 Encoded", rule.msg):
            r = self.ruleTransform(rule, "T1140")
        elif re.search("SOAP Netgear WNDR Auth Bypass", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("log4j", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search(
            "Unusually fast Terminal Server Traffic Potential Scan", rule.msg
        ):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Default Credentials", rule.msg):
            r = self.ruleTransform(rule, "T1078")
        elif re.search("Muieblackcat scanner", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Suspicious Registrar Nameservers in DNS Response", rule.msg):
            r = self.ruleTransform(rule, "T1071")
        elif re.search("HTTP Server Exec Command Execution Attempt", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("Command Injection Attempt Inbound", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("Nmap User-Agent", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Host Tried to Connect to MySQL Server", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("door controllers discover", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("HackingTrio UA", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("Sipvicious Scan", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Arbitrary Code Execution", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("Tomcat admin-admin login credentials", rule.msg):
            r = self.ruleTransform(rule, "T1078")
        elif re.search("TheMoon.linksys.router", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("External Host Probing", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("EnShare IoT Gigabit Cloud Service RCE", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("Vulnerable Magento Adminhtml Access", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("source disclosure vulnerability", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("Command Injection Inbound", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("RCE Attempt", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("Virut DGA NXDOMAIN", rule.msg):
            r = self.ruleTransform(rule, "T1568")
        elif re.search("log4j", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("RCE Attempt", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("WEB_SERVER DELETE attempt", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("PowerShell String Base64 Encoded Invoke-RestMethod", rule.msg):
            r = self.ruleTransform(rule, "T1140")
        elif re.search("RCE Inbound", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("log4j", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("SSH Scan OUTBOUND", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Suspicious Pulse Secure HTTP Request", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search(
            "VMware vCenter Chargeback Manager Information Disclosure", rule.msg
        ):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("ET WEB_SERVER Inbound PHP User-Agent", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("CVE-2016-0042", rule.msg):
            r = self.ruleTransform(rule, "T1129")
        elif re.search("Last-Modified Header", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("MS17-010", rule.msg):
            r = self.ruleTransform(rule, "T1210")
        elif re.search("Tinba DGA", rule.msg):
            r = self.ruleTransform(rule, "T1568")
        elif re.search("Empty Age Header", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("MS17-010", rule.msg):
            r = self.ruleTransform(rule, "T1210")
        elif re.search("CVE-2019-12725", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("VNC Scan 5800-5820", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("OpenSSL HeartBleed", rule.msg):
            r = self.ruleTransform(rule, "T1048")
        elif re.search("log4j", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("Empty If-None-Match Header", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("PowerShell String Base64 Encoded Text.Encoding", rule.msg):
            r = self.ruleTransform(rule, "T1140")
        elif re.search("NMAP SIP Version Detect", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Dir Traversal Attempt", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("Go HTTP Client User-Agent", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Unauthorized SIP Responses", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("NMAP OS Detection Probe", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Nmap Scripting Engine User-Agent Detected", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("log4j", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("Sleuth Scanner", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Sipvicious Asterisk PBX User-Agent", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Sipvicious User-Agent Detected", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Tomcat admin-blank login credentials", rule.msg):
            r = self.ruleTransform(rule, "T1078")
        elif re.search("Zeus GameOver/FluBot Related DGA NXDOMAIN", rule.msg):
            r = self.ruleTransform(rule, "T1568")
        elif re.search("apache ?M=D directory list attempt", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("IP Camera 5.4.0 Information Disclosure", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("Settings Disclosure Attempt", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("P2P Edonkey", rule.msg):
            r = self.ruleTransform(rule, "T1090")
        elif re.search("PHP Injection Attack", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("ColdFusion administrator access", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("xdmcp info query", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("phpinfo access", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("PHP tags in HTTP POST", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("ColdFusion adminapi access", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("named version attempt", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Remote Command Execution", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("CVE-2017-7577", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("OpenSSL HeartBleed", rule.msg):
            r = self.ruleTransform(rule, "T1048")
        elif re.search("IKEv1 Aggressive mode", rule.msg):
            r = self.ruleTransform(rule, "T1110")
        elif re.search("P2P Edonkey", rule.msg):
            r = self.ruleTransform(rule, "T1090")
        elif re.search("Command Injection", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("WP Theme LFI Attempt", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("Double HTTP/1.1 Header Inbound", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("log4j", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("VNC Scan 5900-5920", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("URI Directory Traversal", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("log4j", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("Bluekeep Inbound RDP Exploitation Attempt", rule.msg):
            r = self.ruleTransform(rule, "T1190")
        elif re.search("Get SQL Server Version", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("CONNECT method to Mail", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("Command Execution Attempt", rule.msg):
            r = self.ruleTransform(rule, "T1055")
        elif re.search("printenv access", rule.msg):
            r = self.ruleTransform(rule, "T1595")
        elif re.search("log4j", rule.msg):
            r = self.ruleTransform(rule, "T1055")

        else:
            r = rule
        return r
