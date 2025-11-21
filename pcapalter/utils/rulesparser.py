from suricataparser import parse_file
from idstools import rule as idsRule
import re
from collections import defaultdict
import os

from .mitre_rule_tagger import main

def grouped_by_mitre_tactic(file_path):
    grouped_mitres = defaultdict(list)
    for rule in parse_file(file_path):
        ruleStr = str(rule)
        matchMitreTactic = re.search(r'mitre_tactic_id\s+(\w+)', ruleStr)
        if matchMitreTactic:
            mitre_tactic = matchMitreTactic.group(1)
            grouped_mitres[mitre_tactic].append(rule.sid)
        else:
            matchClassType = re.search(r'classtype:([^;]+)', ruleStr)
            if matchClassType:
                class_type = matchClassType.group(1)
                grouped_mitres[class_type].append(rule.sid)
            else:
                grouped_mitres['unclassified'].append(rule.sid)
    return grouped_mitres

def grouped_by_mitre_technique(file_path):
    grouped_techniques = defaultdict(list)
    for rule in parse_file(file_path):
        ruleStr = str(rule)
        matchMitreTactic = re.search(r'mitre_technique_id\s+(\w+)', ruleStr)
        if matchMitreTactic:
            mitre_technique = matchMitreTactic.group(1)
            grouped_techniques[mitre_technique].append(rule.sid)
        else:
            grouped_techniques['unclassified'].append(rule.sid)

    return grouped_techniques
