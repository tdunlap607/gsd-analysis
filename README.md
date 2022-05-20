# GSD Analysis

The primary goal of this analysis is to understand the data sources, schema, and counts of the Global Security Database ([GSD](https://github.com/cloudsecurityalliance/gsd-database#gsd-repos)). 

The below analysis was completed on the GSD timestamp: 2022-05-20T05:00:05:000. To replicate the below results checkout the gsd-database at commit SHA *d8ce33d48de2f00130e821e9828c3e04b9a4b520*. 



## GSD Counts

![alt text](https://github.com/tdunlap607/gsd-analysis/blob/main/data/figs/gsd_total_count.png?raw=true)



## GSD Complete Schema

The schema  was generated using the [GenSON](https://pypi.org/project/genson/0.1.0/) package. Each GSD JSON was opened and added to the GenSON schema object to create an overall schema for all potential entries within GSD. 

Below is a condensed schema after loading all GSD entries. The complete schema can be seen here:

```json
{
    "GSD": {"type":  "object"},
    "OSV": {"type":  "object"},
    "namespaces": {
        "properties": {
            "cisa.gov": {"type":  "object"},
            "cve.org": {"type":  "object"},
            "gitlab.com": {"type":  "object"},
            "nvd.nist.gov": {"type":  "object"},
            "github.com/kurtseifried:582211": {"type":  "object"}
        }
    },
    "overlay": {
        "properties": {
            "cve.org": {"type":  "object"}
        }
    }
}
```

## Data Sources

From the above schema a set of data sources/keys can be identified:

- [GSD](#GSD)
- [OSV](#OSV)
- Namespaces
  - [cisa.gov](#cisagov)
  - [cve.org](#cveorg)
  - [gitlab.com](#gitlabcom)
  - [nvd.nist.gov](#nvdnistgov)
  - [github.com/kurseifried:582211](#githubcomkurseifried582211)
- [overlay](#overlay)

------

### GSD:

- Ideally, every entry should have a GSD identifier. 

##### GSD Schema:

Full schema can be seen here: ADD LINK / FILE

```json
{
    "affected": {"type":  "array"},
    "affected_component": {"type":  "string"},
    "affects": {"type":  "object"},
    "alias": {"type":  "string"},
    "attack_vector": {"type":  "string"},
    "credit": {"type":  "string"},
    "data_format": {"type":  "string"},
    "data_type": {"type":  "string"},
    "data_version": {"type":  "string"},
    "description": {"type":  "string"},
    "details": {"type":  "string"},
    "duplicate": {"type":  "string"},
    "extended_references": {"type":  "array"},
    "id": {"type":  "string"},
    "impact": {"type":  "object"},
    "modified":{"type":  "string"},
    "notes": {"type":  "string"},
    "product_name": {"type": "object"},
    "product_version": {"type":  "string"},
    "published": {"type":  "string"},
    "references": {"type":  "array"},
    "reporter": {"type":  "string"},
    "reporter_id": {"type":  "integer"},
    "summary": {"type":  "string"},
    "vendor_name": {"type":  "string"},
    "vulnerability_type": {"type": "object"},
    "withdrawn": {"type":  "string"}
}
```

##### GSD Outliers:

- Two entries are **missing** GSD identifiers, both come from GitLab advisories:

  1. https://raw.globalsecuritydatabase.org/GSD-2016-1000249
  2. https://raw.globalsecuritydatabase.org/GSD-2016-1000253

- 18 entries only contain GSD keys:

  - 15 of these are very short, example format:

    ```json
    {
        "GSD": {
            "alias": "CVE-YYYY-XXXXX",
            "id": "GSD-YYYY-XXXXX",
            "references": ["string"]
        }
    }
    ```

    1. https://raw.globalsecuritydatabase.org/GSD-2009-5515
    2. https://raw.globalsecuritydatabase.org/GSD-2010-13616
    3. https://raw.globalsecuritydatabase.org/GSD-2010-26432
    4. https://raw.globalsecuritydatabase.org/GSD-2014-1197
    5. https://raw.globalsecuritydatabase.org/GSD-2015-9679
    6. https://raw.globalsecuritydatabase.org/GSD-2016-1000212
    7. https://raw.globalsecuritydatabase.org/GSD-2016-1000247
    8. https://raw.globalsecuritydatabase.org/GSD-2017-171479
    9. https://raw.globalsecuritydatabase.org/GSD-2019-1000029
    10. https://raw.globalsecuritydatabase.org/GSD-2019-1002162
    11. https://raw.globalsecuritydatabase.org/GSD-2019-14560
    12. https://raw.globalsecuritydatabase.org/GSD-2019-15167
    13. https://raw.globalsecuritydatabase.org/GSD-2019-15690
    14. https://raw.globalsecuritydatabase.org/GSD-2021-3513
    15. https://raw.globalsecuritydatabase.org/GSD-2021-47527

  - Two entries come from "kurtseifried" as the reporter and are much more detailed: 

    1. https://raw.globalsecuritydatabase.org/GSD-2022-1000000
    2. https://raw.globalsecuritydatabase.org/GSD-2022-1000006

  - One is a GSD duplicate: https://raw.globalsecuritydatabase.org/GSD-2022-1000292

------

### OSV:

The actual OSV format: https://ossf.github.io/osv-schema/

Examples from GSD with an OSV object:

- https://raw.globalsecuritydatabase.org/GSD-2021-1001247
- https://raw.globalsecuritydatabase.org/GSD-2022-1000988

##### OSV Schema

```json
{
    "properties": {
        "affected": {"type":  "array"},
        "alias": {"type":  "string"},
        "details": {"type":  "string"}, 
        "id": {"type":  "string"},
        "modified": {"type":  "string"},
        "published": {"type":  "string"},
        "references": {"type":  "array"},
        "summary": {"type":  "string"}
    },
    "required": [
        "affected",
        "details",
        "id",
        "modified",
        "published",
        "summary"
    ],
    "type": "object"
}
```

------

### cisa.gov:

Examples:

- https://raw.globalsecuritydatabase.org/GSD-2014-6332
- https://raw.globalsecuritydatabase.org/GSD-2021-27085

##### cisa.gov schema:

```json
{
    "properties": {
        "cveID": {"type": "string"},
        "dateAdded": {"type": "string"},
        "dueDate": {"type": "string"},
        "product": {"type": "string"},
        "requiredAction": {"type": "string"},
        "shortDescription": {"type": "string"},
        "vendorProject": {"type": "string"},
        "vulnerabilityName": {"type": "string"}
    },
    "required": [
        "cveID",
        "dateAdded",
        "dueDate",
        "product",
        "requiredAction",
        "shortDescription",
        "vendorProject",
        "vulnerabilityName"
    ],
    "type": "object"
}
```

------

### cve.org:

Examples:

- https://raw.globalsecuritydatabase.org/GSD-2018-3367
- https://raw.globalsecuritydatabase.org/GSD-2020-4008

##### cve.org schema:

```json
{
    "properties": {
        "CVE_data_meta": {"type":  "object"},
        "affects": {"type":  "object"},
        "configuration": {"type":  "object"},
        "credit": {"type":  "object"},
        "cve_id": {"type":  "string"},
        "data_format": {"type":  "string"},
        "data_type": {"type":  "string"},
        "data_version": {"type":  "string"},
        "description": {"type":  "object"},
        "discoverer": {"type":  "string"},
        "exploit": {"type":  "object"},
        "generator": {"type":  "object"},
        "impact": {"type":  "object"},
        "problemtype": {"type":  "object"},
        "references": {"type":  "object"},
        "solution": {"type":  "object"},
        "source": {"type":  "object"},
        "timeline": {"type":  "array"},
        "work_around": {"type":  "array"},
        "workaround": {"type":  "object"},
        "x_advisoryEoL": {"type":  "boolean"},
        "x_affectedList": {"type":  "array"},
        "x_likelyAffectedList": {"type":  "array"}
    },
    "required": [
        "CVE_data_meta",
        "data_format",
        "data_type",
        "data_version",
        "description"
    ],
    "type": "object"
}
```

------

### gitlab.com:

Examples:

- https://raw.globalsecuritydatabase.org/GSD-2018-1000805
- https://raw.globalsecuritydatabase.org/GSD-2020-5301

gitlab.com schema:

```json
{
    "properties": {
        "advisories": {
            "items": {
                "properties": {
                    "_git_import_path": {"type":  "string"},
                    "affected_range": {"type":  "string"},
                    "affected_versions": {"type":  "string"},
                    "credit": {"type":  "string"},
                    "cvss_v2": {"type":  "string"},
                    "cvss_v3": {"type":  "string"},
                    "cwe_ids": {"type":  "array"},
                    "date": {"type":  "string"},
                    "description": {"type":  "string"},
                    "fixed_versions": {"type":  "array"},
                    "identifier": {"type":  "string"},
                    "identifiers": {"type":  "array"},
                    "not_impacted": {"type":  "string"},
                    "package_slug": {"type":  "string"},
                    "pubdate": {"type":  "string"},
                    "solution": {"type":  "string"},
                    "title": {"type":  "string"},
                    "urls": {"type":  "array"},
                    "uuid": {"type":  "string"},
                    "versions": {"type":  "array"}
                },
                "required": [
                    "affected_range",
                    "affected_versions",
                    "cwe_ids",
                    "date",
                    "description",
                    "fixed_versions",
                    "identifier",
                    "identifiers",
                    "package_slug",
                    "pubdate",
                    "title",
                    "urls",
                    "uuid"
                ],
                "type": "object"
            },
            "type": "array"
        }
    },
    "required": [
        "advisories"
    ],
    "type": "object"
}
```

------

### nvd.nist.gov:

Examples:

- https://raw.globalsecuritydatabase.org/GSD-2017-12452
- https://raw.globalsecuritydatabase.org/GSD-2021-21956

nvd.nist.gov schema:

```json
{
    "properties": {
        "configurations": {"type":  "object"},
        "cve": {"type":  "object"},
        "impact": {"type":  "object"},
        "lastModifiedDate": {"type":  "string"},
        "publishedDate": {"type":  "string"}
    },
    "required": [
        "configurations",
        "cve",
        "impact",
        "lastModifiedDate",
        "publishedDate"
    ],
    "type": "object"
}
```

------

### github.com/kurtseifried:582211:

- Eight entries contain a kurtseifried:582211 key: 
  1. https://raw.globalsecuritydatabase.org/GSD-2022-1000001
  2. https://raw.globalsecuritydatabase.org/GSD-2022-1000002 
  3. https://raw.globalsecuritydatabase.org/GSD-2022-1000003
  4. https://raw.globalsecuritydatabase.org/GSD-2022-1000004
  5. https://raw.globalsecuritydatabase.org/GSD-2022-1000005
  6. https://raw.globalsecuritydatabase.org/GSD-2022-1000066
  7. https://raw.globalsecuritydatabase.org/GSD-2022-1000067
  8. https://raw.globalsecuritydatabase.org/GSD-2022-1000068

------

### overlay:

- Two entries have an overlay key:
  1. https://raw.globalsecuritydatabase.org/GSD-2021-1002352
  2. https://raw.globalsecuritydatabase.org/GSD-2021-1002353