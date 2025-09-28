

import json
import re
import os
from typing import List, Dict, Tuple

import spacy
from spacy.pipeline import EntityRuler

#Setup
INPUT = os.environ.get("PARAGRAPHS_JSON", "page_paragraphs.json")
FILTERED_JSON = os.environ.get("FILTERED_JSON", "filtered_sentences.json")
INPUTS = os.environ.get("INPUTS", "inputs.jsonl")

MIN_SENT_LEN_CHARS = 20
REQUIRE_VERB = False         #set True if you want to require a verb in the sentence
USE_CONTEXT = False          #keep off; worker expects sentence-only prompts (no context window)

# Keep spaCy's general entity labels
ONTOLOGY_ENTITY_LABELS = {"ORG","PRODUCT","GPE","DATE","FAC","LOC"}

#Declare common domain names
COMMON_DOMAINS = (
    "com|net|org|gov|edu|mil|"
    "io|co|info|biz|"
    "us|uk|de|fr|ru|cn|jp"
)
#Domain regex that ends in one of the above domain suffixes.
DOMAIN_RE = re.compile(
    rf"""\b
        (?:[a-z0-9]            # label start
           (?:[a-z0-9-]{{0,61}}[a-z0-9])?
           \.
        )+                      # one or more labels + dot
        (?:{COMMON_DOMAINS})    # common domain suffix
        \b
    """,
    re.IGNORECASE | re.VERBOSE
)

#Common file extensions (for some reason LNK doesm't work properly, need to look into it)
FILE_EXT_GROUP = (
    "exe|dll|sys|lnk|bat|cmd|ps1|psm1|vbs|js|jse|hta|jar|apk|"
    "iso|img|msi|msp|scr|sh|py|pl|php|"
    "zip|rar|7z|gz|bz2|xz|tar|"
    "pdf|rtf|doc|docx|xls|xlsx|ppt|pptx|csv|txt|log|dat|tmp"
)

#Windows path (drive or UNC) + file
FILEPATH_WINDOWS = re.compile(
    rf"""(?:
            (?:[A-Za-z]:\\|\\\\)       # C:\ or \\server\share\
            [^\s"<>|]+?                # path segments
            \.(?:{FILE_EXT_GROUP})\b
        )""",
    re.IGNORECASE | re.VERBOSE
)

#Bare filename (no path). Avoid spaces and invalid Windows characters.
FILE_BARE = re.compile(
    rf"""\b
        [^\s\\/:"<>|]+                 # filename stem
        \.(?:{FILE_EXT_GROUP})\b
    """,
    re.IGNORECASE | re.VERBOSE
)

#CTI pattern rules
PATTERNS = {
    "IPv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?!$)|$)){4}\b"),
    "DOMAIN": DOMAIN_RE,              
    "URL": re.compile(r"\bhttps?://[^\s)]+", re.I),
    "EMAIL": re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I),
    "FILEPATH_WINDOWS": FILEPATH_WINDOWS,
    "FILE": FILE_BARE,             
}

VULN_CVE   = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
ATTACK_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

def rule_entities(text: str) -> List[Dict[str,str]]:
    ents: List[Dict[str,str]] = []
    t = text or ""

    #Domains
    for m in PATTERNS["DOMAIN"].finditer(t):
        ents.append({"text": m.group(0), "label": "DOMAIN"})

    #IPs / URLs / Emails
    for m in PATTERNS["IPv4"].finditer(t):
        ents.append({"text": m.group(0), "label": "IPv4"})
    for m in PATTERNS["URL"].finditer(t):
        ents.append({"text": m.group(0), "label": "URL"})
    for m in PATTERNS["EMAIL"].finditer(t):
        ents.append({"text": m.group(0), "label": "EMAIL"})

    #File paths / filenames (Windows + bare)
    for m in PATTERNS["FILEPATH_WINDOWS"].finditer(t):
        ents.append({"text": m.group(0), "label": "FILE"})
    for m in PATTERNS["FILE"].finditer(t):
        ents.append({"text": m.group(0), "label": "FILE"})

    #CVE / ATT&CK
    for m in VULN_CVE.finditer(t):
        ents.append({"text": m.group(0), "label": "VULN_CVE"})
    for m in ATTACK_TID.finditer(t):
        ents.append({"text": m.group(0), "label": "ATTACK_TID"})

    return ents

def sentence_has_desired_entities(sent_doc, sent_text) -> bool:
    #Pass if spaCy finds any ontology entity OR rule-based CTI entities are present
    if any(ent.label_ in ONTOLOGY_ENTITY_LABELS for ent in sent_doc.ents):
        return True
    return len(rule_entities(sent_text)) > 0

def sentence_has_verb(sent_doc) -> bool:
    return any(tok.pos_ == "VERB" for tok in sent_doc)

#Prompt
def build_prompt(rules: str) -> str:
    return f"""You are a cybersecurity analyst. Extract subject–predicate–object triples.

Rules:
- Use only these entity types: [Threat Actor, Organization, Product, Vulnerability, Malware, Tool, Campaign, Country, City, Date, IP, DOMAIN, URL, FILE, VULN_CVE, ATTACK_TID, SECTOR]
- Use only these predicates and type rules:
targets(Threat Actor|Malware -> Organization|Country|SECTOR)
uses(Threat Actor -> Malware|Tool)
exploits(Threat Actor|Malware -> VULN_CVE|Vulnerability)
drops(Malware -> Malware|Tool)
communicates_with(Malware|Tool -> IP|DOMAIN|URL)
observed_on(Threat Actor|Malware|Tool -> Date)
affects(Product -> VULN_CVE|Vulnerability)
mitigates(Organization|Product -> VULN_CVE|Malware|ATTACK_TID)
attributed_to(Campaign|Intrusion Set -> Threat Actor)

Return ONLY valid JSON:
[
  {{
    "subject": {{"name": "...", "type": "..."}},
    "predicate": "...",
    "object": {{"name": "...", "type": "..."}},
    "confidence": 0.0
  }}
]

If none, return the JSON string "No related entities and relations."

Work strictly following the rules below:
{rules}"""


#spaCY helpers
def add_entity_ruler(nlp):
    """Add fast dictionary patterns for actors/malware/products (extend as needed)."""
    ruler = nlp.add_pipe("entity_ruler", before="ner")
    actor_patterns   = [{"label":"THREAT_ACTOR","pattern":"APT28"},
                        {"label":"THREAT_ACTOR","pattern":"Fancy Bear"},
                        {"label":"THREAT_ACTOR","pattern":"APT29"},
                        {"label":"THREAT_ACTOR","pattern":"Cozy Bear"}]
    malware_patterns = [{"label":"MALWARE","pattern":"Emotet"},
                        {"label":"MALWARE","pattern":"PlugX"},
                        {"label":"MALWARE","pattern":"Cobalt Strike"}]
    prod_patterns    = [{"label":"PRODUCT","pattern":"RouterOS"},
                        {"label":"PRODUCT","pattern":"Microsoft Windows"},
                        {"label":"PRODUCT","pattern":"Exchange Server"}]
    ruler.add_patterns(actor_patterns + malware_patterns + prod_patterns)

def spacy_process_paragraph(nlp, text: str):
    doc = nlp(text)
    return [(sent, sent.text.strip()) for sent in doc.sents]

#Merge spaCy ontology entities with CTI rule entities
def merge_entities(sent_doc, sent_text: str) -> List[Dict[str,str]]:
    merged: List[Dict[str,str]] = []

    # spaCy entities (only keep ontology labels)
    for ent in sent_doc.ents:
        if ent.label_ in ONTOLOGY_ENTITY_LABELS:
            merged.append({"text": ent.text.strip(), "label": ent.label_.upper()})

    # CTI rule entities
    merged.extend(rule_entities(sent_text))

    # Deduplicate (label + casefolded text)
    seen, out = set(), []
    for e in merged:
        key = (e["label"], e["text"].casefold())
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out

#Main
def main():
    #Load paragraphs
    with open(INPUT, "r", encoding="utf-8") as f:
        data = json.load(f)

    #spaCy
    try:
        nlp = spacy.load("en_core_web_sm")
    except OSError:
        raise SystemExit("spaCy model missing. Install with: python -m spacy download en_core_web_sm")
    add_entity_ruler(nlp)

    filtered = []
    prompts = []

    for page in data.get("pages", []):
        page_no = page.get("page")
        for chunk in page.get("chunks", []):
            paragraph_id = chunk.get("id")
            paragraph_text = chunk.get("text") or ""
            if not paragraph_text.strip():
                continue

            sentences = spacy_process_paragraph(nlp, paragraph_text)
            sent_texts = [s for _, s in sentences]

            for sent_idx, (sent_doc, sent_text) in enumerate(sentences):
                if len(sent_text) < MIN_SENT_LEN_CHARS:
                    continue
                if REQUIRE_VERB and not sentence_has_verb(sent_doc):
                    continue
                if not sentence_has_desired_entities(sent_doc, sent_text):
                    continue

                ents_merged = merge_entities(sent_doc, sent_text)

                sentence_id = f"{paragraph_id}-s{sent_idx}"
                filtered.append({
                    "page": page_no,
                    "paragraph_id": paragraph_id,
                    "sentence_id": sentence_id,
                    "text": sent_text,
                    "entities": ents_merged
                })

                #Build sentence-only prompt
                text_for_prompt = sent_text if not USE_CONTEXT else " ".join(sent_texts[max(0, sent_idx-1): sent_idx+2])
                prompts.append({
                    "page": page_no,
                    "paragraph_id": paragraph_id,
                    "sentence_id": sentence_id,
                    "prompt": build_prompt(text_for_prompt),
                    "sentence": sent_text,           # exact sentence used
                    "paragraph": paragraph_text      # paragraph for provenance
                })

    # Write outputs
    with open(FILTERED_JSON, "w", encoding="utf-8") as f:
        json.dump(filtered, f, ensure_ascii=False, indent=2)
    with open(INPUTS, "w", encoding="utf-8") as f:
        for obj in prompts:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"Wrote {FILTERED_JSON} ({len(filtered)} sentences kept)")
    print(f"Wrote {INPUTS} ({len(prompts)} prompts)")

if __name__ == "__main__":
    main()
