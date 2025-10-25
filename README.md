Testing program for extracting Cyber Threat Intelligence (CTI) entities and creating triples from .pdf files. 
It uses Dolcing to parse .pdf, spaCy to pre-filter the results of Docling and prepare prompts for LLM, and use local Ollama LLM to create tripples. 
Program runs via three separate steps/scripts as following:

1) Chunks pdf into paragraphs and outputs JSON. 

2) prefilters JSON with spaCy with 5 NERs, several regex rules and  applies some CTI rules (not based on UCO Ontology yet, just general cybersecurity rules). It then creates a JSON file with LLM ready prompts for each identified sentence. 

3) Gemma 2:9b worker script that runs that JSON file through a local Ollama on my PC and outputs a JSON file with triples.

4) (Optional) Can run full document extraction/ validation. Validation currently does not work properly. reserved for future experiments.

   Validation workers:
5a) This worker analyzes the full CTI document to generate an automated summary and infer its central theme. It scans paragraph text for key elements such as threat actor, country of origin, tools used, and primary targets, then synthesizes this information into a coherent summary paragraph. Using token weighting and Jaccard similarity, it selects the most relevant sentences and extracts one representative triple—typically identifying who attacks whom and how. It also detects campaign names, actor aliases, and actions (e.g., phishing, data theft) to produce a structured JSON file containing the summary, main triple, and key findings, providing contextual insight into the document’s intelligence focus

5b) This worker performs rigorous rule-based validation of extracted triples against STIX 2.1 entity and relationship schemas. It verifies that each triple follows structural, lexical, and semantic constraints—checking valid subject/object types, allowable predicates, proper domain–range pairing, and numeric confidence values. Invalid triples are logged with explicit error reasons, while valid ones are preserved for knowledge-graph integration. The worker outputs two JSON files for valid and invalid results along with a summary report, effectively serving as a quality-control stage to ensure all triples adhere to cybersecurity ontology standards.

5c) This worker refines and critiques previous triple-extraction outputs by re-evaluating them at the paragraph level. It reloads document paragraphs and matches triples to their paragraph IDs, validating them with predefined STIX entity and predicate rules. For each paragraph, it ranks candidate triples by completeness, confidence, and text relevance, keeping only the top three and embedding their surrounding context for interpretability. The resulting JSON file provides a concise, paragraph-anchored set of high-quality triples, improving contextual coherence and filtering out redundant or low-confidence relationships

(Optional) uco_common_dictionary_extraction.py this script can pull UCO objects from the official documentation and put them into a JSON file.
