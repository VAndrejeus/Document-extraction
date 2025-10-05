
"""
tripples_full_doc_scan.py
Small Gemma worker that:
- chunks the given PDF with Docling
- extracts SPO triples using your prompt template (with confidence)
- validates each triple against its paragraph
- writes a single JSON file: tripples_full_doc_scan.json
"""

import os, re, json, requests, torch
from collections import defaultdict
from typing import Any, Dict, List, Tuple
from docling.document_converter import DocumentConverter
from docling_core.types.doc import DocItemLabel

# ------------------ Config ------------------
OLLAMA_URL  = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL_NAME  = os.environ.get("OLLAMA_MODEL", "gemma2:9b")
PDF_PATH    = os.environ.get("PDF_PATH", "Cyble_OperationShadowCat-Targeting-Indian-Political-Observers(07-24-2024).pdf")
OUT_FILE    = "tripples_full_doc_scan.json"
TIMEOUT_SEC = float(os.environ.get("OLLAMA_TIMEOUT", "120"))
GEN_OPTIONS = {"temperature": 0.1, "top_p": 0.9, "repeat_penalty": 1.1, "num_predict": 512}

print(f"CUDA available: {torch.cuda.is_available()}")

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

#Prompt Validation
VALIDATE_PROMPT = (
    "Given a paragraph and one triple, decide if the triple is explicitly supported (not implied). "
    "Return ONLY JSON: {\"valid\": true|false, \"confidence\": <0..1>}."
)

#Extra guardrails you can tweak 
DEFAULT_RULES = """- Extract only relations explicitly stated in the paragraph (no inference).
- Keep entity names concise as they appear.
- Ensure subject/object types match the allowed type rules.
- If uncertain, skip the triple."""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tripples_full_doc_scan.py
Gemma worker without paragraph chunking:
- Convert PDF with Docling
- Concatenate entire doc into one text string
- Extract SPO triples using your prompt (with confidence)
- Validate each triple against the full document text
- Write a single JSON file: tripples_full_doc_scan.json
"""

import os, re, json, requests, torch
from typing import Any, Dict, List, Tuple
from docling.document_converter import DocumentConverter

# ------------------ Config ------------------
OLLAMA_URL  = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL_NAME  = os.environ.get("OLLAMA_MODEL", "gemma2:9b")
PDF_PATH    = os.environ.get("PDF_PATH", "Cyble_OperationShadowCat-Targeting-Indian-Political-Observers(07-24-2024).pdf")
OUT_FILE    = "tripples_full_doc_scan.json"
TIMEOUT_SEC = float(os.environ.get("OLLAMA_TIMEOUT", "120"))
# Optional safety cap to avoid overlong prompts (0 = no cap)
MAX_DOC_CHARS = int(os.environ.get("MAX_DOC_CHARS", "0"))

GEN_OPTIONS = {"temperature": 0.1, "top_p": 0.9, "repeat_penalty": 1.1, "num_predict": 1024}

print(f"CUDA available: {torch.cuda.is_available()}")

# ------------------ Your prompt template ------------------
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

VALIDATE_PROMPT = (
    "Given a document and one triple, decide if the triple is explicitly supported (not implied). "
    "Return ONLY JSON: {\"valid\": true|false, \"confidence\": <0..1>}."
)

DEFAULT_RULES = """- Extract only relations explicitly stated in the document (no inference).
- Keep entity names concise as they appear.
- Ensure subject/object types match the allowed type rules.
- If uncertain, skip the triple."""

#Docling: load entire document text
def _get_page_no(item):
    if getattr(item, "prov", None) and item.prov and (item.prov[0].page_no is not None):
        return item.prov[0].page_no
    return None

def _dehyphen_join(prev: str, cur: str) -> str:
    prev_r = prev.rstrip()
    if prev_r.endswith("-"):
        return prev_r[:-1] + cur.lstrip()
    if prev and not prev.endswith(" "):
        return prev + " " + cur.lstrip()
    return prev + cur.lstrip()

def load_full_text(pdf_path: str) -> str:
    converter = DocumentConverter()
    doc = converter.convert(pdf_path).document
    full, cur_page = "", None
    for it in doc.texts:
        t = (it.text or "").strip()
        if not t: 
            continue
        pg = _get_page_no(it)
        # Insert a page separator when page changes
        if pg is not None and pg != cur_page and cur_page is not None:
            full += "\n\n"  # soft separator for pages
        cur_page = pg
        full = _dehyphen_join(full, t) if full else t
    return full

#Ollama helpers
def ollama(prompt: str) -> str:
    r = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={"model": MODEL_NAME, "prompt": prompt, "stream": False, "options": GEN_OPTIONS},
        timeout=TIMEOUT_SEC,
    )
    r.raise_for_status()
    return (r.json().get("response") or "").strip()

def parse_json_list(txt: str) -> List[Dict[str, Any]]:
    try:
        obj = json.loads(txt)
    except Exception:
        i, j = txt.find("["), txt.rfind("]")
        try:
            obj = json.loads(txt[i:j+1]) if (i != -1 and j != -1 and i < j) else []
        except Exception:
            obj = []
    if isinstance(obj, list):
        out = []
        for t in obj:
            if isinstance(t, dict) and {"subject","predicate","object"} <= t.keys():
                out.append(t)
        return out
    if isinstance(obj, str) and obj.strip().lower() == "no related entities and relations.":
        return []
    return []

def parse_validation_obj(s: str) -> Tuple[bool, float]:
    try:
        o = json.loads(s)
    except Exception:
        i, j = s.find("{"), s.rfind("}")
        try:
            o = json.loads(s[i:j+1]) if (i != -1 and j != -1 and i < j) else {}
        except Exception:
            o = {}
    v = bool(o.get("valid", False))
    try:
        c = float(o.get("confidence", 0.0))
    except Exception:
        c = 0.0
    return v, max(0.0, min(1.0, c))

#Extraction & Validation
EXTRACT_PREAMBLE = build_prompt(DEFAULT_RULES)

def extract_triples(doc_text: str) -> List[Dict[str, Any]]:
    if MAX_DOC_CHARS > 0 and len(doc_text) > MAX_DOC_CHARS:
        doc_text = doc_text[:MAX_DOC_CHARS]
    prompt = f"{EXTRACT_PREAMBLE}\n\nDocument:\n{doc_text}\n\nReturn JSON only."
    out = ollama(prompt)
    triples = parse_json_list(out)
    if not triples:
        triples = parse_json_list(ollama(prompt + "\nReturn ONLY JSON."))
    return triples

def validate_triple(doc_text: str, t: Dict[str, Any]) -> Tuple[bool, float]:
    if MAX_DOC_CHARS > 0 and len(doc_text) > MAX_DOC_CHARS:
        doc_text = doc_text[:MAX_DOC_CHARS]
    s, o = t.get("subject", {}) or {}, t.get("object", {}) or {}
    line = f'("{s.get("name","")}"[{s.get("type","")}] {t.get("predicate","")} "{o.get("name","")}"[{o.get("type","")}])'
    v_prompt = f"{VALIDATE_PROMPT}\n\nDocument:\n{doc_text}\n\nTriple:\n{line}\n\nJSON only."
    out = ollama(v_prompt)
    ok, conf = parse_validation_obj(out)
    if not isinstance(ok, bool):
        ok, conf = parse_validation_obj(ollama(v_prompt + "\nReturn ONLY JSON."))
    return bool(ok), float(conf)

def tkey(t: Dict[str, Any]) -> Tuple[str, str, str, str, str]:
    return (
        (t.get("subject") or {}).get("name","").strip(),
        (t.get("subject") or {}).get("type","").strip(),
        (t.get("predicate") or "").strip(),
        (t.get("object")  or {}).get("name","").strip(),
        (t.get("object")  or {}).get("type","").strip(),
    )

# ------------------ Run: full-document flow ------------------
doc_text = load_full_text(PDF_PATH)

# 1) Extract once over the full document
raw_triples = extract_triples(doc_text)

# 2) Dedupe by semantic key
seen, deduped = set(), []
for t in raw_triples:
    key = tkey(t)
    if key in seen:
        continue
    seen.add(key)
    deduped.append(t)

# 3) Assign IDs
for i, t in enumerate(deduped, 1):
    t["id"] = f"t{i:03d}"

# 4) Validate each triple against the full document text
validated = []
for t in deduped:
    ok, conf = validate_triple(doc_text, t)
    t["validation"] = {"valid": ok, "confidence": conf}
    if ok:
        validated.append(t)

# 5) Write single output file
with open(OUT_FILE, "w", encoding="utf-8") as f:
    json.dump({
        "pdf": os.path.abspath(PDF_PATH),
        "model": MODEL_NAME,
        "extracted_total": len(deduped),
        "validated_true": len(validated),
        "triples": validated
    }, f, ensure_ascii=False, indent=2)

print(f"[done] extracted={len(deduped)} ; valid={len(validated)} -> {OUT_FILE}")
