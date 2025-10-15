
''' DONE Creates a worker that critiques the work of previous worker by doing the following:
    DONE Re-runs the original prompt against the identified paragraphs in the originally created JSON file page_paragraphs.JSON.
    DONE Choses the best three triples per paragraph and writes a new JSON with them
    TODO Compare two JSON files (old and new) and drop all similar triples
    TODO write a new file with common triples.
    TODO Add proper paragraph matching. Right now paragraph_id 1 = page 1 chunk 0 paragraph_id 2 = page 1 chuck 2
'''

import os, json, re

PAR_PATH     = os.environ.get("PAR_PATH", "page_paragraphs.json")
TRIPLES_PATH = os.environ.get("TRIPLES_PATH", "triples_merged.json") #will be used to compare with the file generasted by this worker
OUT_PATH     = os.environ.get("OUT_PATH", "triples_per_para.json")
PER_PAR_MAX  = int(os.environ.get("PER_PAR_MAX", "3"))
CTX_MAX_CH   = int(os.environ.get("CTX_MAX_CH", "800"))  #truncate long paragraphs

#Stix 2.1 names
ALLOWED_TYPES = {
  "threat-actor","intrusion-set","campaign","malware","tool","infrastructure","attack-pattern",
  "course-of-action","indicator","vulnerability","software","product","organization","identity",
  "sector","country","location","city","ipv4-addr","ipv6-addr","domain-name","url","file","email-addr",
  "observed-data","report","sighting","x-mitre-data-source","x-mitre-data-component","observable",
  "user-account","directory","autonomous-system","date"
}
ALLOWED_PREDICATES = {
  "uses","targets","attributed_to","originates_from","exploits","affects","mitigates","indicates",
  "detects","based_on","derived_from","observed_on","communicates_with","hosts","delivers","drops",
  "located_at","resolves_to","uses_technique","subtechnique_of","variant_of","related_to"
}
ANY = ALLOWED_TYPES
PRED_SCHEMA = {
  "uses":            ({"threat-actor","intrusion-set","campaign"}, {"malware","tool","infrastructure","attack-pattern"}),
  "targets":         ({"threat-actor","intrusion-set","campaign","malware","attack-pattern"}, {"organization","identity","sector","location","country"}),
  "attributed_to":   ({"campaign","intrusion-set"}, {"threat-actor"}),
  "originates_from": ({"threat-actor","intrusion-set"}, {"location","country"}),
  "exploits":        ({"threat-actor","malware","tool"}, {"vulnerability"}),
  "affects":         ({"software","product","tool","malware"}, {"vulnerability"}),
  "mitigates":       ({"course-of-action","software","organization","product"}, {"vulnerability","malware","attack-pattern"}),
  "indicates":       ({"indicator"}, {"malware","campaign","intrusion-set","tool","infrastructure","attack-pattern","vulnerability","organization","sector","location"}),
  "detects":         ({"indicator","tool","x-mitre-data-source"}, {"malware","attack-pattern","campaign","intrusion-set","infrastructure","tool","vulnerability"}),
  "based_on":        ({"indicator"}, {"file","url","domain-name","ipv4-addr","ipv6-addr","email-addr","artifact","observable"}),
  "derived_from":    ({"indicator"}, {"report","observed-data","artifact","log"}),
  "observed_on":     ({"threat-actor","malware","tool","infrastructure","indicator","attack-pattern"}, {"date"}),
  "communicates_with": ({"infrastructure","malware","tool"}, {"ipv4-addr","ipv6-addr","domain-name","url"}),
  "hosts":           ({"infrastructure"}, {"domain-name","ipv4-addr","ipv6-addr","url","file"}),
  "delivers":        ({"infrastructure","malware","tool"}, {"malware","tool","file","url"}),
  "drops":           ({"malware","tool"}, {"malware","tool","file"}),
  "located_at":      ({"infrastructure","organization","identity"}, {"location","country","city"}),
  "resolves_to":     ({"domain-name"}, {"ipv4-addr","ipv6-addr"}),
  "uses_technique":  ({"threat-actor","malware","tool","campaign"}, {"attack-pattern"}),
  "subtechnique_of": ({"attack-pattern"}, {"attack-pattern"}),
  "variant_of":      ({"malware","tool","indicator","attack-pattern"}, {"malware","tool","indicator","attack-pattern"}),
  "related_to":      (ANY, ANY)
}

#load paragraphs
def load_paragraphs(p):
    if not (p and p.lower().endswith(".json") and os.path.exists(p)): return []
    try: data=json.load(open(p,"r",encoding="utf-8"))
    except: return []
    out=[]
    if isinstance(data,dict) and "pages" in data:
        for pg in data.get("pages",[]):
            for ch in pg.get("chunks",[]):
                t=(ch.get("text") or ch.get("paragraph") or ch.get("content") or "").strip()
                if t: out.append(t)
    elif isinstance(data,list):
        for it in data:
            if isinstance(it,dict):
                t=(it.get("text") or it.get("paragraph") or it.get("content") or "").strip()
                if t: out.append(t)
            elif isinstance(it,str):
                t=it.strip()
                if t: out.append(t)
    return out

def load_triples(p):
    try:
        data=json.load(open(p,"r",encoding="utf-8"))
        return data.get("triples") if isinstance(data,dict) else data
    except: return []

#validation and normalization
def norm_text(s): return re.sub(r"\s+"," ", (s or "").strip())[:200]
def norm_pred(p): return re.sub(r"[^a-z_]", "", (p or "").strip().lower().replace("-","_"))

def triple_valid_prompt_rule(t):
    if not isinstance(t,dict): return False
    s=t.get("subject") or {}; o=t.get("object") or {}; p=t.get("predicate")
    if not isinstance(s,dict) or not isinstance(o,dict) or not isinstance(p,str): return False
    p = norm_pred(p)
    if not p or p not in ALLOWED_PREDICATES: return False
    sname, oname = norm_text(s.get("name","")), norm_text(o.get("name",""))
    st, ot = (s.get("type") or ""), (o.get("type") or "")
    if not sname or not oname or st not in ALLOWED_TYPES or ot not in ALLOWED_TYPES: return False
    dom, ran = PRED_SCHEMA.get(p, (None,None))
    if dom is not None and st not in dom: return False
    if ran is not None and ot not in ran: return False
    return True

def normalize_triple(t):
    s=t.get("subject") or {}; o=t.get("object") or {}
    return {
        "subject": {"name": norm_text(s.get("name","")), "type": s.get("type","")},
        "predicate": norm_pred(t.get("predicate","")),
        "object": {"name": norm_text(o.get("name","")), "type": o.get("type","")}
    }

def extract_pid(md):
    if md is None: return None
    for k in ("paragraph_id","para_id","paragraphIndex","chunk_id","chunk_index","paraIndex"):
        v=md.get(k)
        if isinstance(v,int): return v
        if isinstance(v,str):
            m=re.search(r'\d+', v)
            if m: return int(m.group(0))
    return None

def score(t):
    s,o=t.get("subject",{}), t.get("object",{})
    type_bonus=(1 if s.get("type") else 0)+(1 if o.get("type") else 0)
    conf=float(t.get("confidence",0) or 0)
    name_len=len(s.get("name",""))+len(o.get("name",""))
    return (type_bonus, conf, name_len)

#main
paras   = load_paragraphs(PAR_PATH)
triples = load_triples(TRIPLES_PATH) or []

by_para={i:[] for i in range(len(paras))}
for t in triples:
    if not triple_valid_prompt_rule(t): continue
    md=t.get("metadata") or {}
    pid=extract_pid(md)
    if isinstance(pid,int) and 0<=pid<len(paras):
        by_para[pid].append(normalize_triple(t))

final=[]
for idx, para_text in enumerate(paras):
    cands = by_para.get(idx, [])
    if not cands: continue
    cands.sort(key=score, reverse=True)
    top = cands[:PER_PAR_MAX]
    ctx = (para_text[:CTX_MAX_CH] + ("..." if len(para_text)>CTX_MAX_CH else ""))
    for t in top:
        t["metadata"]={"paragraph_id": idx, "context": ctx}
        final.append(t)

with open(OUT_PATH,"w",encoding="utf-8") as f:
    json.dump(final, f, ensure_ascii=False, indent=2)

print("Gemma Worker C wrote", OUT_PATH, "triples:", len(final))


