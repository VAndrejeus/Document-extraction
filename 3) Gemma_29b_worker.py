import os
import json
import time
import requests
from typing import Any, Dict, Iterable, List, Tuple

#Config
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL_NAME = os.environ.get("OLLAMA_MODEL", "gemma2:9b")

INPUT_JSONL  = os.environ.get("INPUTS", "inputs.jsonl")
MERGED_JSON  = os.environ.get("MERGED", "triples_merged.json")

#Optional side inputs to back-fill sentence/paragraph if inputs lack them
FILTERED_SENTENCES = os.environ.get("FILTERED_JSON",  "filtered_sentences.json")
PAGE_PARAGRAPHS    = os.environ.get("PARAGRAPHS_JSON","page_paragraphs.json")

TIMEOUT_SEC = float(os.environ.get("OLLAMA_TIMEOUT", "120"))
GEN_OPTIONS = {
    "temperature": 0.1,
    "top_p": 0.9,
    "repeat_penalty": 1.1,
    "num_predict": 512,
}

#JSON loaders
def read_jsonl(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)

def load_sentences_map(path: str) -> Dict[str, str]:
    #Map sentence_id -> sentence text (from filtered_sentences.json).
    try:
        with open(path, "r", encoding="utf-8") as f:
            arr = json.load(f)
        return {
            it.get("sentence_id"): (it.get("text") or "").strip()
            for it in arr if it.get("sentence_id")
        }
    except Exception:
        return {}

def load_paragraphs_map(path: str) -> Dict[str, str]:
    #Map paragraph_id -> paragraph text (from page_paragraphs.json).
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        mp = {}
        for page in data.get("pages", []):
            for ch in page.get("chunks", []):
                pid = ch.get("id")
                if pid:
                    mp[pid] = (ch.get("text") or "").strip()
        return mp
    except Exception:
        return {}

#Parso JSON
def safe_json_parse(text: str):
    """
    Returns (triples: List[dict], note: str)
    note in: '', 'parse_error', 'no_triples_string', 'unexpected_json_shape'
    """
    try:
        obj = json.loads(text)
    except Exception:
        #salvage array if model wrapped with extra prose
        try:
            s = text.find('['); e = text.rfind(']')
            if s != -1 and e != -1 and s < e:
                obj = json.loads(text[s:e+1])
            else:
                return [], "parse_error"
        except Exception:
            return [], "parse_error"

    if isinstance(obj, list):
        triples = []
        for t in obj:
            if isinstance(t, dict) and "subject" in t and "predicate" in t and "object" in t:
                triples.append(t)
        return triples, ""
    if isinstance(obj, str) and obj.strip().lower() == "no related entities and relations.":
        return [], "no_triples_string"
    return [], "unexpected_json_shape"

#Dedupe
def _norm(v) -> str:
    return (v or "").strip()

def triple_key(t: Dict[str, Any]) -> Tuple[str, str, str, str, str, str, str]:
    """
    Key used for deduplication & ID assignment (ignores any prior 'id').
    Includes semantic parts + provenance from metadata; context text is not part of the key.
    """
    s_name = _norm(t.get("subject", {}).get("name"))
    s_type = _norm(t.get("subject", {}).get("type"))
    pred   = _norm(t.get("predicate"))
    o_name = _norm(t.get("object",  {}).get("name"))
    o_type = _norm(t.get("object",  {}).get("type"))
    md     = t.get("metadata") or {}
    page   = _norm(str(md.get("page")))          
    parid  = _norm(md.get("paragraph_id"))
    sentid = _norm(md.get("sentence_id"))
    return (s_name, s_type, pred, o_name, o_type, page, parid, sentid)

def dedupe_triples(triples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Keep first occurrence for each triple_key.
    IDs are assigned later in presentation order.
    """
    seen, out = set(), []
    for t in triples:
        k = triple_key(t)
        if k not in seen:
            seen.add(k)
            out.append(t)
    return out

#Ollama
def ollama_generate(prompt: str) -> str:
    url = f"{OLLAMA_URL}/api/generate"
    payload = {"model": MODEL_NAME, "prompt": prompt, "stream": False, "options": GEN_OPTIONS}
    r = requests.post(url, json=payload, timeout=TIMEOUT_SEC)
    r.raise_for_status()
    return (r.json().get("response") or "").strip()

#Main 
def main():
    #Optional back-fill maps
    sent_map = load_sentences_map(FILTERED_SENTENCES)
    para_map = load_paragraphs_map(PAGE_PARAGRAPHS)

    #Check OLLAMA model
    try:
        tags = requests.get(f"{OLLAMA_URL}/api/tags", timeout=10).json()
        if MODEL_NAME not in [m.get("name") for m in tags.get("models", [])]:
            print(f"[warn] {MODEL_NAME} not found locally. Run:  ollama pull {MODEL_NAME}")
    except Exception as e:
        print(f"[warn] Ollama not available at {OLLAMA_URL}: {e}")

    inputs = list(read_jsonl(INPUT_JSONL))
    all_triples: List[Dict[str, Any]] = []
    error_count = 0

    for item in inputs:
        prompt = item.get("prompt", "")
        meta = {
            "page": item.get("page"),
            "paragraph_id": item.get("paragraph_id"),
            "sentence_id": item.get("sentence_id"),
        }
        if not prompt:
            error_count += 1
            continue

        #Pull sentence/paragraph from record or back-fill
        sentence_text  = _norm(item.get("sentence"))
        paragraph_text = _norm(item.get("paragraph"))
        if not sentence_text and meta["sentence_id"]:
            sentence_text = _norm(sent_map.get(meta["sentence_id"]))
        if not paragraph_text and meta["paragraph_id"]:
            paragraph_text = _norm(para_map.get(meta["paragraph_id"]))

        try:
            raw = ollama_generate(prompt)
            triples, note = safe_json_parse(raw)

            #One self-repair attempt if needed
            if note in {"parse_error", "unexpected_json_shape"}:
                raw2 = ollama_generate(
                    prompt + "\n\nYour previous output was not valid JSON. Return ONLY valid JSON."
                )
                triples2, note2 = safe_json_parse(raw2)
                if triples2 or note2 == "":
                    raw, triples, note = raw2, triples2, note2

            #Build enriched triple records (no per-row results kept)
            for t in triples:
                all_triples.append({
                    "subject":   t["subject"],
                    "predicate": t["predicate"],
                    "object":    t["object"],
                    "metadata": {
                        "page":         meta["page"],
                        "paragraph_id": meta["paragraph_id"],
                        "sentence_id":  meta["sentence_id"],
                    },
                    "context": {
                        "sentence":  sentence_text,
                        "paragraph": paragraph_text
                    }
                })

        except Exception:
            error_count += 1

        time.sleep(0.01)

    #Dedupe and assign sequential IDs t001, t002
    deduped = dedupe_triples(all_triples)

    id_map: Dict[Tuple[str, ...], str] = {}
    for idx, t in enumerate(deduped, start=1):
        tid = f"t{idx:03d}"
        t["id"] = tid
        id_map[triple_key(t)] = tid

    #Write merged outputs
    with open(MERGED_JSON, "w", encoding="utf-8") as f:
        json.dump({
            "total_inputs": len(inputs),
            "total_triples": len(all_triples),
            "unique_triples": len(deduped),
            "errors": error_count,
            "triples": deduped
        }, f, ensure_ascii=False, indent=2)

    print(f"Wrote {len(deduped)} unique triples -> {MERGED_JSON}")

if __name__ == "__main__":
    main()
