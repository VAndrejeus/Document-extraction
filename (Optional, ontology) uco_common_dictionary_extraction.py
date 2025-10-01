import json, pathlib

UCO_LIST = {
  "subjects": [
    "action:Action",
    "core:Relationship",
    "identity:Identity",
    "identity:Person",
    "identity:Organization",
    "tool:Tool",
    "observable:ObservableObject",
    "observable:Vulnerability",
    "observable:File",
    "observable:URL",
    "observable:DomainName",
    "observable:IPAddress",
    "observable:EmailAddress",
    "location:Location"
  ],

  "predicates": [
    "action:performer",
    "action:instrument",
    "action:object",
    "action:location",
    "action:startTime",
    "action:endTime",
    "action:participant",
    "action:objective",
    "action:result",
    "action:phase",
    "action:actionStatus",
    "action:environment",
    "action:error",

    "core:name",
    "core:description",
    "core:confidence",
    "core:createdBy",
    "core:modifiedTime",
    "core:externalReference",
    "core:objectMarking",
    "core:hasFacet",
    "core:source",
    "core:target",

    "identity:givenName",
    "identity:familyName",
    "identity:birthdate",
    "identity:address",

    "observable:addressValue",
    "observable:destination",
    "observable:destinationPort",
    "observable:fileName",
    "observable:filePath",
    "observable:fullValue"
  ],

  "objects": [
    "identity:Identity",
    "identity:Person",
    "identity:Organization",
    "tool:Tool",
    "observable:ObservableObject",
    "observable:Vulnerability",
    "observable:File",
    "observable:URL",
    "observable:DomainName",
    "observable:IPAddress",
    "observable:EmailAddress",
    "location:Location"
  ]
}

if __name__ == "__main__":
    out = pathlib.Path("uco_ontology_list.json")
    out.write_text(json.dumps(UCO_LIST, indent=2))
    print(f"Wrote {out.resolve()}")

