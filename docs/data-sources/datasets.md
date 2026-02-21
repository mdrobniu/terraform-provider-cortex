---
page_title: "cortex_datasets Data Source - terraform-provider-cortex"
subcategory: ""
description: |-
  Retrieves a list of all datasets in XSIAM.
---

# cortex_datasets (Data Source)

Retrieves a read-only list of all datasets configured in XSIAM. Datasets are the underlying storage objects for logs, events, and lookup tables. Each dataset entry includes its type, size, event count, and source query.

~> **Note:** This data source is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

## Example Usage

```terraform
data "cortex_datasets" "all" {}

output "dataset_names" {
  value = data.cortex_datasets.all.datasets[*].name
}

output "lookup_datasets" {
  value = [
    for ds in data.cortex_datasets.all.datasets : ds.name
    if ds.type == "LOOKUP"
  ]
}
```

## Schema

### Read-Only

- `datasets` (List of Object) The list of all datasets in XSIAM.
  - `id` (Number) The unique numeric identifier of the dataset.
  - `name` (String) The name of the dataset.
  - `type` (String) The dataset type. One of `SYSTEM`, `LOOKUP`, `RAW`, `USER`, `SNAPSHOT`, `CORRELATION`, or `SYSTEM_AUDIT`.
  - `total_size_bytes` (Number) The total storage size of the dataset in bytes.
  - `total_events_stored` (Number) The total number of events stored in the dataset.
  - `source_query` (String) The XQL source query associated with the dataset, if any.
