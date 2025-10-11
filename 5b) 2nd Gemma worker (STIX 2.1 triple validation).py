'''Choice 2
•	Create a worker that strictly follows found triple combinations
•	Generate a new triple JSON file with triple combinations
•	Compare the new triple JSON and the old one, generate new JSON with similar triples and another one with differentials

Uses entities and relationships described here: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
'''

def prompt(rules: str) -> str:
    return f"""You are a cybersecurity analyst. Extract subject-predicate-object triples.

Rules:
- Use only these STIX 2.1 entity types:
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

