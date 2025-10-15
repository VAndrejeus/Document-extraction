'''
Creates a worker that strictly follows STIX 2.1 triple combinations
Evaluates triples_merged,json against the triple rules and creates two new triple JSON files: one with valid triples, another with invalid
Prints a validation report to console.


Uses entities and relationships described here: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html


This is the prompt based on the original Gemma worker prompt: The worker is using a set of rules similar to this.

def prompt(rules: str) -> str:
    return f"""You are a cybersecurity analyst. Extract subject-predicate-object triples.

Rules:
- Use only these entity types:
[attack-pattern, campaign, course-of-action, grouping, identity, indicator, infrastructure, intrusion-set,
location, malware, malware-analysis, note, observed-data, opinion, report, sighting, threat-actor, tool,
vulnerability, attack-vector, ipv4-addr, ipv6-addr, domain-name, url, file, email-addr, network-traffic,
software, process, windows-registry-key, user-account, autonomous-system, directory, artifact, relationship, marking-definition, statement, x-mitre-data-source, x-mitre-data-component]

- Use only these predicates and type rules:
uses(threat-actor|intrusion-set|campaign -> malware|tool|infrastructure|attack-pattern)
targets(threat-actor|intrusion-set|campaign|malware|attack-pattern -> identity|organization|sector|location|country)
attributed_to(campaign|intrusion-set -> threat-actor)
exploits(threat-actor|malware|tool -> vulnerability)
affects(software|tool|malware -> vulnerability)
mitigates(course-of-action|software|organization -> vulnerability|malware|attack-pattern)
indicates(indicator -> malware|campaign|intrusion-set|tool|infrastructure|attack-pattern|vulnerability|organization|sector|location)
detects(indicator|tool|x-mitre-data-source -> malware|attack-pattern|campaign|intrusion-set|infrastructure|tool|vulnerability)
based_on(indicator -> file|url|domain-name|ipv4-addr|ipv6-addr|email-addr|artifact|observable)
derived_from(indicator -> report|observed-data|log|artifact)
observed_in(indicator -> infrastructure|malware|tool|campaign|threat-actor|attack-pattern)
communicates_with(infrastructure|malware|tool -> ipv4-addr|ipv6-addr|domain-name|url)
hosts(infrastructure -> domain-name|ipv4-addr|ipv6-addr|url|file)
delivers(infrastructure|malware|tool -> malware|tool|file|url)
drops(malware|tool -> malware|tool|file)
located_at(infrastructure -> location|country|city)
uses_technique(threat-actor|malware|tool|campaign -> attack-pattern)
subtechnique_of(attack-pattern -> attack-pattern)
revoked_by(attack-pattern|malware|tool -> attack-pattern|malware|tool)
duplicate_of(attack-pattern|malware|tool|indicator -> attack-pattern|malware|tool|indicator)
originates_from(threat-actor|intrusion-set -> location|country)
impacts(threat-actor|malware|attack-pattern -> identity|organization|sector)
resolves_to(domain-name -> ipv4-addr|ipv6-addr)
downloads_from(malware|tool -> url|domain-name)
writes_to(malware|tool -> file)
reads_from(malware|tool -> file)
emails_to(email-addr -> email-addr)
observed_on(threat-actor|malware|tool|infrastructure|indicator|attack-pattern -> date)
analysis_of(malware-analysis -> malware|tool|attack-pattern)
characterizes(malware-analysis -> malware|tool|attack-pattern)
sighting_of(sighting -> indicator|malware|tool|campaign|intrusion-set|attack-pattern)
sighted_at(indicator|malware|tool|campaign|intrusion-set|attack-pattern -> infrastructure|identity|organization|sector|location)
sighted_by(indicator|malware|tool|campaign|intrusion-set|attack-pattern -> identity|organization|x-mitre-data-source)
variant_of(malware|tool|indicator|attack-pattern -> malware|tool|indicator|attack-pattern)
related_to(any -> any)

Return ONLY valid JSON:
[
  {{
    "subject": {{"name": "...", "type": "..." }},
    "predicate": "...",
    "object": {{"name": "...", "type": "..." }},
    "confidence": 0.0
  }}
]

If none, return the JSON string "No related entities and relations."

Work strictly following the rules below:
{rules}"""

'''
import json, os, sys, re
from typing import Any, Dict, List, Tuple, Set

IN_PATH  = os.environ.get("IN_PATH", "triples_merged.json")
OUT_OK   = os.environ.get("OUT_OK", "triples_valid.json")
OUT_BAD  = os.environ.get("OUT_BAD", "triples_invalid.json")
MAX_STR_LEN = int(os.environ.get("MAX_STR_LEN", "500"))

#Allowed Stix 2.1 entities
ALLOWED_TYPES: Set[str] = {
  "threat-actor","intrusion-set","campaign","malware","tool","infrastructure","attack-pattern",
  "course-of-action","indicator","vulnerability","software","product","organization","identity",
  "sector","country","location","city","ipv4-addr","ipv6-addr","domain-name","url","file",
  "email-addr","observed-data","report","sighting","x-mitre-data-source","x-mitre-data-component",
  "observable","user-account","directory","autonomous-system","date","malware-analysis"
}

ALLOWED_PREDICATES: Set[str] = {
  "uses","targets","attributed_to","exploits","affects","mitigates","indicates","detects","based_on",
  "derived_from","observed_in","communicates_with","hosts","delivers","drops","located_at",
  "uses_technique","subtechnique_of","revoked_by","duplicate_of","originates_from","impacts",
  "resolves_to","downloads_from","writes_to","reads_from","emails_to","observed_on",
  "analysis_of","characterizes","sighting_of","sighted_at","sighted_by","variant_of"
}

#Possile relationships
PREDICATE_SCHEMA: Dict[str, Tuple[Set[str], Set[str]]] = {
  "uses": ({"threat-actor","intrusion-set","campaign"}, {"malware","tool","infrastructure","attack-pattern"}),
  "targets": ({"threat-actor","intrusion-set","campaign","malware","attack-pattern"}, {"identity","organization","sector","location","country"}),
  "attributed_to": ({"campaign","intrusion-set"}, {"threat-actor"}),
  "exploits": ({"threat-actor","malware","tool"}, {"vulnerability"}),
  "uses_technique": ({"threat-actor","malware","tool","campaign"}, {"attack-pattern"}),
  "originates_from": ({"threat-actor","intrusion-set"}, {"location","country"}),
  "based_on": ({"indicator"}, {"file","url","domain-name","ipv4-addr","ipv6-addr","email-addr","observable","artifact"}),
  "derived_from": ({"indicator"}, {"report","observed-data","artifact","log"}),
  "detects": ({"indicator","tool","x-mitre-data-source"}, {"malware","attack-pattern","campaign","intrusion-set","infrastructure","tool","vulnerability"}),
  "indicates": ({"indicator"}, {"malware","campaign","intrusion-set","tool","infrastructure","attack-pattern","vulnerability","organization","sector","location"}),
  "resolves_to": ({"domain-name"}, {"ipv4-addr","ipv6-addr"}),
  "hosts": ({"infrastructure"}, {"domain-name","ipv4-addr","ipv6-addr","url","file"}),
  "delivers": ({"infrastructure","malware","tool"}, {"malware","tool","file","url"}),
  "drops": ({"malware","tool"}, {"malware","tool","file"}),
  "located_at": ({"infrastructure","organization","identity"}, {"location","country","city"}),
  "observed_on": ({"threat-actor","malware","tool","infrastructure","indicator","attack-pattern"}, {"date"}),
  "impacts": ({"threat-actor","malware","attack-pattern"}, {"identity","organization","sector"}),
}

def is_str(x): 
    return isinstance(x, str)

def nonempty_str(x): 
    return is_str(x) and 0 < len(x.strip()) <= MAX_STR_LEN

def numlike(x): 
    return isinstance(x, (int, float))

def validate_domain_range(pred: str, st: str, ot: str) -> List[str]:
    errs = []
    if pred in PREDICATE_SCHEMA:
        subj_ok, obj_ok = PREDICATE_SCHEMA[pred]
        if st not in subj_ok:
            errs.append(f"subject.type_invalid_for_{pred}")
        if ot not in obj_ok:
            errs.append(f"object.type_invalid_for_{pred}")
    return errs

def validate_triple(t: Dict[str, Any]):
    reasons: List[str] = []
    if not isinstance(t, dict): return False, ["not_an_object"]

    subj = t.get("subject"); obj = t.get("object"); pred = t.get("predicate")

    #Check that triple core fields exist and have the right data tytpes
    if not isinstance(subj, dict): reasons.append("subject_not_object")
    if not isinstance(obj, dict):  reasons.append("object_not_object")
    if not nonempty_str(pred):     reasons.append("predicate_missing_or_empty")

    #predicates
    if is_str(pred):
        if not re.fullmatch(r"[a-z][a-z_\-]*", pred.strip()):
            reasons.append("predicate_not_tokenlike")
        if pred not in ALLOWED_PREDICATES:
            reasons.append("predicate_not_allowed")

    #subject/object names & types
    sname = subj.get("name") if isinstance(subj, dict) else ""
    stype = subj.get("type") if isinstance(subj, dict) else ""
    oname = obj.get("name")  if isinstance(obj, dict)  else ""
    otype = obj.get("type")  if isinstance(obj, dict)  else ""

    if not nonempty_str(sname): reasons.append("subject.name_missing_or_empty")
    if not nonempty_str(oname): reasons.append("object.name_missing_or_empty")
    if not nonempty_str(stype): reasons.append("subject.type_missing_or_empty")
    if not nonempty_str(otype): reasons.append("object.type_missing_or_empty")

    if is_str(stype) and stype not in ALLOWED_TYPES: reasons.append("subject.type_not_allowed")
    if is_str(otype) and otype not in ALLOWED_TYPES: reasons.append("object.type_not_allowed")

    #domain/range (only if there is pred asnd type)
    if is_str(pred) and is_str(stype) and is_str(otype):
        reasons += validate_domain_range(pred, stype, otype)

    #confidence 0..1 if present
    if "confidence" in t:
        c = t["confidence"]
        if not numlike(c): reasons.append("confidence_not_numeric")
        elif not (0.0 <= float(c) <= 1.0): reasons.append("confidence_out_of_range")

    #length sanity on predicate
    if is_str(pred) and len(pred) > MAX_STR_LEN: reasons.append("predicate_too_long")

    return (len(reasons) == 0), reasons

def main():
    try:
        with open(IN_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[strict-validator] Failed to read {IN_PATH}: {e}")
        sys.exit(1)

    triples = data.get("triples") if isinstance(data, dict) else data
    if not isinstance(triples, list):
        print("[strict-validator] Input is neither {'triples': [...]} nor a list.")
        sys.exit(1)

    valid, invalid = [], []
    for t in triples:
        ok, reasons = validate_triple(t)
        (valid if ok else invalid).append(t if ok else {"triple": t, "reasons": reasons})

    with open(OUT_OK, "w", encoding="utf-8") as f:
        json.dump({"triples": valid}, f, ensure_ascii=False, indent=2)
    with open(OUT_BAD, "w", encoding="utf-8") as f:
        json.dump({"triples": invalid}, f, ensure_ascii=False, indent=2)

    total = len(triples)
    print("Validation report")
    print(f"Total: {total}")
    print(f"Valid: {len(valid)}")
    print(f"Invalid: {len(invalid)}")
    if total:
        print(f"Valid rate: {len(valid)/total:.3f} | Invalid rate: {len(invalid)/total:.3f}")
    print(f"Gemma worker B wrote: {OUT_OK}, {OUT_BAD}")

if __name__ == "__main__":
    main()
