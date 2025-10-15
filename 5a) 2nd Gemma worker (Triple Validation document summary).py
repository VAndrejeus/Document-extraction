'''
	DONE Read the preprocessed paragraphs with an LLM
	DONE Find a main theme, put it in several sentences, generate a summary as a paragraph on the parameters below:
    DONE Who is threat actor? Country of origin, organization, 
    DONE What does it do? Send a file, steal data, vector of attack, etc.
    DONE Who is the target? Broad target or specific target
	TODO Generate a JSON file with sentences or paragraph
	TODO Compare new file with old file and drop all the triples that are not similar to the new JSON summary.'''

import os, re, json

DOC_PATH = os.environ.get("DOC_PATH", "page_paragraphs.json")
OUT_JSON = os.environ.get("OUT_JSON", "main_theme.json")

#Load JSON with paragraphs
def load_text(path: str) -> str:
    if not (path and path.lower().endswith(".json") and os.path.exists(path)): return ""
    try:
        data = json.load(open(path, "r", encoding="utf-8"))
    except Exception:
        return ""
    #shape: {"pages":[{"chunks":[{"text":"..."}]}]}
    if isinstance(data, dict) and "pages" in data:
        return "\n".join(ch.get("text","") for p in data["pages"] for ch in p.get("chunks",[]) if ch.get("text"))
    #shape: [{"text":"..."}, {"paragraph":"..."}, ...]
    if isinstance(data, list):
        return "\n".join((it.get("text") or it.get("paragraph") or it.get("content") or "") for it in data if isinstance(it,dict))
    return ""

T = load_text(DOC_PATH)

#Remove connector words, isolate key words
STOP=set("a an the of for to in on at by with from as is are was were be been being this that these those and or if but into over under against during without within while after before above below it its their his her they them he she we us you your our".split())
tok = lambda s: re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]*", s or "")
ctok= lambda s: [t for t in tok((s or "").lower()) if t not in STOP] #split sentences into content tokens and remove STOP words
sent= lambda s: [x.strip() for x in re.split(r'(?<=[\.\?!])\s+', s or "") if x.strip()]

#Summarize text
def summarize(s, k=6, lim=900, lam=0.7):
    S = sent(s)
    if not S: return ""
    bag={}; [bag.__setitem__(w,bag.get(w,0)+1) for se in S for w in ctok(se)]
    rel=lambda se: (sum(bag.get(w,0) for w in ctok(se)) / (1+len(ctok(se)))) if ctok(se) else 0.0
    jac=lambda a,b: (len(set(ctok(a))&set(ctok(b))) / (len(set(ctok(a))|set(ctok(b))) or 1)) # Jaccard similarity of sentences a and b
    R=[rel(x) for x in S]; m=max(R) or 1.0; R=[r/m for r in R]
    chosen=[]; used=set(); seed=max(range(max(1,len(S)//3)), key=lambda i:R[i]); used.add(seed); chosen.append(S[seed])
    while len(chosen)<k and len(used)<len(S):
        best=(-9,None)
        for i,x in enumerate(S):
            if i in used: continue
            red=max((jac(x,c) for c in chosen), default=0.0) #Jaccard
            sc=lam*R[i]-(1-lam)*red
            if sc>best[0]: best=(sc,i)
        if best[1] is None: break
        used.add(best[1]); chosen.append(S[best[1]])
    return " ".join(sorted(chosen, key=lambda x:S.index(x)))[:lim]

summary = summarize(T)

#Find campaigns
def find_campaign(s):
    m=re.findall(r'\b(Operation|Campaign)\s+([A-Z][A-Za-z0-9_-]+)\b', s)
    return f"{m[0][0]} {m[0][1]}" if m else ""

#Find threat actors
def find_actor(s):
    a=re.findall(r'\bAPT\s?\d+\b', s, re.I)
    b=[x+" Group" for x in re.findall(r'\b([A-Z][A-Za-z0-9_-]+(?:\s+[A-Z][A-Za-z0-9_-]+)*)\s+Group\b', s)]
    c=[m.group(1) for m in re.finditer(r'\b(?:known as|aka|called)\s+([A-Z][A-Za-z0-9 _-]+)\b', s, re.I)]
    cand=[*a,*b,*c]
    cand=[x for x in cand if not re.match(r'^(Operation|Campaign)\b', x)]
    return max(set(cand), key=cand.count) if cand else ""

#Find tools
def find_tool(s):
    m=re.findall(r'\b([A-Z][A-Za-z0-9_-]+)\b(?:\s+(?:RAT|malware|backdoor|trojan|loader|stealer|spyware|framework|beacon))', s, re.I)
    return max(set(m), key=m.count) if m else ""

#Find targets
def find_target(s):
    for p in [r'\btarget(?:ing|s|ed)?\s+(?:of\s+)?(.{1,80})', r'\bagainst\s+(.{1,80})', r'\baim(?:ed)?\s+at\s+(.{1,80})']:
        m=re.search(p, s, re.I)
        if m:
            frag=re.split(r'[.;:\n]', m.group(1))[0]
            frag=re.sub(r'^\s*(the|a|an)\s+', '', frag, flags=re.I).strip()
            name=" ".join(frag.split()[:8])
            #rough category
            words=name.split()
            if not name: return {}
            if len(words)==1 and words[0][0].isupper(): cat="country_or_org"
            elif all(w[0].isupper() for w in words):   cat="organization"
            else:                                       cat="identity_or_sector"
            bs="broad" if (name.endswith('s') or len(words)<=1) else "specific"
            return {"name":name,"type":cat,"broad_or_specific":bs}
    return {}

campaign=find_campaign(T)
actor=find_actor(T)
tool=find_tool(T)
target=find_target(T)

#Pick a triple combination based on STIX 2.1
if campaign and target:
    triple={"subject":{"name":campaign,"type":"campaign"},"predicate":"targets","object":{"name":target["name"],"type":target["type"]}}
elif (actor or campaign) and tool:
    subj=(campaign,"campaign") if campaign else (actor,"threat-actor")
    triple={"subject":{"name":subj[0],"type":subj[1]},"predicate":"uses","object":{"name":tool,"type":"tool"}}
elif actor and target:
    triple={"subject":{"name":actor,"type":"threat-actor"},"predicate":"targets","object":{"name":target["name"],"type":target["type"]}}
else:
    triple={}

#Look for key findings
org  = re.search(r'\b(linked to|sponsored by|unit|bureau|ministry|group)\s+([A-Z][A-Za-z0-9&\-\s]{2,})', T)
orig = re.search(r'\b(based in|from|originating from)\s+([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)?)', T)
acts = [lbl for rg,lbl in [
    ("phish|spearphish|email","phishing email"),
    ("attachment|zip|rar|docx|pdf|xls|macro","sends malicious file"),
    ("drop|install|loader","drops/installs payload"),
    ("exfiltrat|steal|exfil","steals data"),
    ("c2|command and control|beacon","C2/beaconing"),
    ("credential|password|keylog","credential theft"),
    ("powershell|script|vbs|batch","scripted execution"),
    ("exploit|cve-","exploits vulnerability")
] if re.search(rg, T, re.I)]
key_findings={
  "threat_actor": actor or "",
  "origin_country": (orig.group(2) if orig else ""),
  "organization": (org.group(2).strip() if org else ""),
  "actions": sorted(set(acts))[:6],
  "target": {"name": target.get("name",""), "category": target.get("type",""), "broad_or_specific": target.get("broad_or_specific","")}
}

json.dump({"summary":summary,"main_triple":triple,"key_findings":key_findings},
          open(OUT_JSON,"w",encoding="utf-8"), ensure_ascii=False, indent=2)
print("2nd Gemma worker A wrote:", OUT_JSON); print("Main triple:", json.dumps(triple, ensure_ascii=False))
