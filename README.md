Testing program for extracting Cyber Threat Intelligence (CTI) entities and creating triples from .pdf files. 
It uses Dolcing to parse .pdf, spaCy to pre-filter the results of Docling and prepare prompts for LLM, and use local Ollama LLM to create tripples. 
Program runs via three separate steps/scripts aas following:

1) Chunks pdf into paragraphs and outputs JSON. 

2) prefilters JSON with spaCy with 5 NERs, several regex rules and  applies some CTI rules (not based on UCO Ontology yet, just general cybersecurity rules). It then creates a JSON file with LLM ready prompts for each identified sentence. 

3) Gemma 2:9b worker script that runs that JSON file through a local Ollama on my PC and outputs a JSON file with triples.
