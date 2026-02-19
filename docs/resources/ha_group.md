---
page_title: "cortex_ha_group Resource - terraform-provider-cortex"
subcategory: ""
description: |-
  Manages a High Availability (HA) group in Cortex XSOAR 6. HA groups define clusters of XSOAR hosts backed by a shared Elasticsearch instance for multi-tenant deployments.
---

# cortex_ha_group (Resource)

Manages a High Availability (HA) group in Cortex XSOAR 6. HA groups define clusters of XSOAR hosts that share an Elasticsearch backend, enabling multi-tenant deployments with high availability. Each HA group is associated with a specific Elasticsearch URL and index prefix.

Supported on XSOAR 6 only.

~> **Note:** Changing the `elasticsearch_url` or `elastic_index_prefix` forces replacement of the resource (destroy and recreate).

## Example Usage

### Basic HA Group

```terraform
resource "cortex_ha_group" "production" {
  name                 = "production-cluster"
  elasticsearch_url    = "https://es-prod.internal:9200"
  elastic_index_prefix = "xsoar-prod"
}
```

### Multiple HA Groups for Environment Separation

```terraform
resource "cortex_ha_group" "production" {
  name                 = "production"
  elasticsearch_url    = "https://es-prod.internal:9200"
  elastic_index_prefix = "xsoar-prod"
}

resource "cortex_ha_group" "staging" {
  name                 = "staging"
  elasticsearch_url    = "https://es-staging.internal:9200"
  elastic_index_prefix = "xsoar-staging"
}
```

### HA Group with Host and Account

```terraform
resource "cortex_ha_group" "main" {
  name                 = "main-cluster"
  elasticsearch_url    = "https://elasticsearch.internal:9200"
  elastic_index_prefix = "xsoar-main"
}

resource "cortex_host" "app_host" {
  name          = "xsoar-app-01"
  ha_group_name = cortex_ha_group.main.name
}

resource "cortex_account" "tenant" {
  name            = "tenant-alpha"
  host_group_name = cortex_ha_group.main.name
}
```

## Schema

### Required

- `name` (String) The unique name of the HA group.
- `elasticsearch_url` (String, Forces Replacement) The URL of the Elasticsearch instance backing this HA group. Changing this forces a new resource.
- `elastic_index_prefix` (String, Forces Replacement) The index prefix used in Elasticsearch for this HA group. Changing this forces a new resource.

### Read-Only

- `id` (String) The identifier of the HA group.
- `account_ids` (List of String) The list of account IDs associated with this HA group.
- `host_ids` (List of String) The list of host IDs associated with this HA group.

## Import

HA groups can be imported using the HA group ID:

```shell
terraform import cortex_ha_group.production <ha-group-id>
```
