import torch
import json
import re
from collections import defaultdict

from docling.document_converter import DocumentConverter
from docling_core.types.doc import DocItemLabel


#CUDA checjk
is_there_cuda = torch.cuda.is_available()
pin_memory = True if is_there_cuda else False 
print(f"CUDA available: {is_there_cuda}")



converter = DocumentConverter()

#Convert signle source for now to test the pipeline
source = "Cyble_OperationShadowCat-Targeting-Indian-Political-Observers(07-24-2024).pdf"

result = converter.convert(source)
doc = result.document

#Normalize content layer
doc_content_layer = doc

#Extract page number from TextItem provenance
def _get_page_no(item) -> int | None:
    if getattr(item, "prov", None) and item.prov and (item.prov[0].page_no is not None):
        return item.prov[0].page_no
    return None

# Find bullets, treat them as paragraphs
def _looks_like_bullet(text: str) -> bool:
    t = text.lstrip()
    return (
        t.startswith(("-", "•", "◦", "∙", "‣"))
        or bool(re.match(r"^\(?\d+[\.)]\s+", t))
        or bool(re.match(r"^[A-Za-z]\)\s+", t)) 
    )

# join two lines separated by hyphen
def _dehyphenate_join(prev: str, cur: str) -> str:

    prev_r = prev.rstrip()
    if prev_r.endswith("-"):
        # Remove the trailing hyphen and DON'T add a space.
        return prev_r[:-1] + cur.lstrip()
    # Normal case: add exactly one space between fragments.
    if prev and not prev.endswith(" "):
        return prev + " " + cur.lstrip()
    return prev + cur.lstrip()


# Merge paragraph like items
PARAGRAPH_LIKE = {DocItemLabel.PARAGRAPH, DocItemLabel.TEXT}
# What should *not* merge into paragraphs (standalone chunks)?
HEADER_LIKE = {DocItemLabel.TITLE, DocItemLabel.SECTION_HEADER}

# Chunk builder
def build_page_paragraph_chunks(docling_doc):
    
    dcl = docling_doc
    pages = defaultdict(list)

    # Tracking
    current_page = None      
    current_paragraph = ""   

    #Put paragraph accumulator into pages
    def flush_paragraph():
        
        nonlocal current_paragraph, current_page
        if current_paragraph.strip():
            idx = len(pages[current_page])
            pages[current_page].append({
                "id": f"Page {current_page} - Chunk {idx}",
                "text": current_paragraph.strip()
            })
        current_paragraph = ""

    #Iterate over text items 
    for item in dcl.texts:
        raw_text = (item.text or "").strip()
        if not raw_text:
            #Skip empty strings
            continue

        page_no = _get_page_no(item)
        label = item.label 

        # Finilize current paragraph if pages are switching, no cross-page paragraphuing
        if page_no != current_page:
            if current_page is not None:
                flush_paragraph()
            current_page = page_no

        #Headers, list items, bullet lines are treated as standalone.
        if (
            label in HEADER_LIKE
            or label == DocItemLabel.LIST_ITEM
            or _looks_like_bullet(raw_text)
            or label not in PARAGRAPH_LIKE
        ):
            #Finish any paragraph we were building, then push this item as its own chunk.
            flush_paragraph()
            idx = len(pages[current_page])
            pages[current_page].append({
                "id": f"Page {current_page} - Chunk {idx}",
                "text": raw_text
            })
            continue

        #Otherwise, it's paragraph-like: merge it with the running paragraph buffer.
        if current_paragraph:
            current_paragraph = _dehyphenate_join(current_paragraph, raw_text)
        else:
            current_paragraph = raw_text

    #End-of-loop: make sure the last buffered paragraph is recorded.
    if current_page is not None:
        flush_paragraph()

    #Serialize pages in numeric order; anything without a page number (rare) goes last.
    ordered_pages = []
    numbered_pages = sorted([p for p in pages.keys() if p is not None])
    for p in numbered_pages:
        ordered_pages.append({"page": int(p), "chunks": pages[p]})
    if None in pages:
        ordered_pages.append({"page": None, "chunks": pages[None]})

    #Try to include origin metadata (filename or URL) if available.
    origin = getattr(dcl, "origin", None)
    source_name = ""
    if origin is not None:
        source_name = getattr(origin, "uri", None) or getattr(origin, "filename", "") or ""

    return {
        "source": source_name,
        "pages": ordered_pages
    }


#Build JSON file for paragraphs
page_paragraphs = build_page_paragraph_chunks(doc_content_layer)

with open("page_paragraphs.json", "w", encoding="utf-8") as f:
    json.dump(page_paragraphs, f, ensure_ascii=False, indent=2)

print("JSON paragraph file created: page_paragraphs.json")
