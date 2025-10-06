
import os, re, json, requests
from typing import Any, Dict, List, Tuple
from docling.document_converter import DocumentConverter

#Config
OLLAMA_URL  = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL_NAME  = os.environ.get("OLLAMA_MODEL", "gemma2:9b")
PDF_PATH    = os.environ.get("PDF_PATH", "Cyble_OperationShadowCat-Targeting-Indian-Political-Observers(07-24-2024).pdf")
OUT_FILE    = "tripples_full_doc_scan.json"
TIMEOUT_SEC = float(os.environ.get("OLLAMA_TIMEOUT", "120"))

#18k char prompt cap
MAX_DOC_CHARS = int(os.environ.get("MAX_DOC_CHARS", "18000"))

#Fall back params
WIN_SIZE   = int(os.environ.get("WIN_SIZE", "12000"))
WIN_STRIDE = int(os.environ.get("WIN_STRIDE", "8000"))

GEN_OPTIONS = {"temperature": 0.1, "top_p": 0.9, "repeat_penalty": 1.1, "num_predict": 1536}

#Prompt
PROMPT = """You are a cybersecurity analyst. Extract subject–predicate–object triples that are explicitly supported by the text.

Guidelines:
- Prefer entity types when obvious: [Threat Actor, Organization, Product, Vulnerability, Malware, Tool, Campaign, Country, City, Date, IP, DOMAIN, URL, FILE, VULN_CVE, ATTACK_TID, SECTOR]
- If type is unclear, set type to "Unknown".
- Allowed predicates include (not limited to): targets, uses, exploits, drops, communicates_with, observed_on, affects, mitigates, attributed_to, associated_with, delivers, references, discovered_by, produced_by, located_in, mentions.
- Use "associated_with" when no specific predicate fits cleanly.
- Return as many triples as are clearly present (aim for at least 10 if available).

Return ONLY valid JSON (array of objects):
[
  { "subject":{"name":"...","type":"..."}, "predicate":"...", "object":{"name":"...","type":"..."}, "confidence": 0.0 }
]
If none, return the JSON string "No related entities and relations."
"""

VALIDATE_PROMPT = 'Given a document and one triple, decide if the triple is explicitly supported (not implied). Return ONLY JSON: {"valid": true|false, "confidence": <0..1>}.'

#Load full ext with docling
def _get_page_no(item):
    if getattr(item, "prov", None) and item.prov and (item.prov[0].page_no is not None):
        return item.prov[0].page_no
    return None

def _join(prev: str, cur: str) -> str:
    prev_r = prev.rstrip()
    if prev_r.endswith("-"): 
        return prev_r[:-1] + cur.lstrip()
    if prev and not prev.endswith(" "):
        return prev + " " + cur.lstrip()
    return prev + cur.lstrip()

def load_full_text(pdf_path: str) -> str:
    doc = DocumentConverter().convert(pdf_path).document
    full, cur_page = "", None
    for it in doc.texts:
        t = (it.text or "").strip()
        if not t: 
            continue
        pg = _get_page_no(it)
        if pg is not None and pg != cur_page and cur_page is not None:
            full += "\n\n"
        cur_page = pg
        full = _join(full, t) if full else t
    return full

#Ollama
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
        try: obj = json.loads(txt[i:j+1]) if (i!=-1 and j!=-1 and i<j) else []
        except Exception: obj = []
    if isinstance(obj, list):
        out = []
        for t in obj:
            if isinstance(t, dict) and {"subject","predicate","object"} <= set(t.keys()):
                t.setdefault("confidence", 0.0)
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
        try: o = json.loads(s[i:j+1]) if (i!=-1 and j!=-1 and i<j) else {}
        except Exception: o = {}
    v = bool(o.get("valid", False))
    try: c = float(o.get("confidence", 0.0))
    except Exception: c = 0.0
    return v, max(0.0, min(1.0, c))

#Main functions
def extract_prompt(text: str) -> List[Dict[str, Any]]:
    if MAX_DOC_CHARS and len(text) > MAX_DOC_CHARS:
        text = text[:MAX_DOC_CHARS]
    out = ollama(f"{PROMPT}\n\nDocument:\n{text}\n\nJSON only.")
    triples = parse_json_list(out)
    if not triples:
        triples = parse_json_list(ollama(f"{PROMPT}\n\nDocument:\n{text}\n\nReturn ONLY JSON."))  # retry
    return triples

def extract_prompt_windows(text: str) -> List[Dict[str, Any]]:
    n = len(text)
    if n == 0: return []
    size, stride = max(2000, WIN_SIZE), max(1000, WIN_STRIDE)
    all_items: List[Dict[str, Any]] = []
    for start in range(0, n, stride):
        chunk = text[start:start+size]
        if not chunk: break
        all_items.extend(extract_prompt(chunk))
        all_items = dedupe(all_items)
    return all_items

def validate(full_text: str, t: Dict[str, Any]) -> Tuple[bool, float]:
    text = full_text[:MAX_DOC_CHARS] if (MAX_DOC_CHARS and len(full_text) > MAX_DOC_CHARS) else full_text
    s, o = t.get("subject", {}) or {}, t.get("object", {}) or {}
    line = f'("{s.get("name","")}"[{s.get("type","Unknown")}] {t.get("predicate","")} "{o.get("name","")}"[{o.get("type","Unknown")}])'
    out = ollama(f"{VALIDATE_PROMPT}\n\nDocument:\n{text}\n\nTriple:\n{line}\n\nJSON only.")
    ok, conf = parse_validation_obj(out)
    if not isinstance(ok, bool):
        ok, conf = parse_validation_obj(ollama(f"{VALIDATE_PROMPT}\n\nDocument:\n{text}\n\nTriple:\n{line}\n\nReturn ONLY JSON."))
    return ok, conf

def key(t: Dict[str, Any]) -> Tuple[str,str,str,str]:
    return (
        (t.get("subject") or {}).get("name","").strip(),
        (t.get("subject") or {}).get("type","").strip(),
        (t.get("predicate") or "").strip(),
        (t.get("object")  or {}).get("name","").strip()
    )

def dedupe(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen, out = set(), []
    for it in items:
        k = key(it)
        if k in seen: 
            continue
        seen.add(k); out.append(it)
    return out

#Run 
doc_text = load_full_text(PDF_PATH)

#Full-document pass
triples = dedupe(extract_prompt(doc_text))

#If no tripples, relaxed sliding windows
if not triples:
    triples = dedupe(extract_prompt_windows(doc_text))

#Triple IDs + validation, keeping only explicitly supported
for i, t in enumerate(triples, 1): t["id"] = f"t{i:03d}"
validated = []
for t in triples:
    ok, conf = validate(doc_text, t)
    t["validation"] = {"valid": ok, "confidence": conf}
    if ok: validated.append(t)

#Write results
with open(OUT_FILE, "w", encoding="utf-8") as f:
    json.dump({
        "pdf": os.path.abspath(PDF_PATH),
        "model": MODEL_NAME,
        "extracted_total": len(triples),
        "validated_true": len(validated),
        "triples": validated
    }, f, ensure_ascii=False, indent=2)

print(f"[done] extracted={len(triples)} ; valid={len(validated)} -> {OUT_FILE}")
