---
page_title: "cortex_host Resource - terraform-provider-cortex"
subcategory: ""
description: |-
  Manages a host registration in Cortex XSOAR 6. Hosts are XSOAR server nodes that can be assigned to HA groups for multi-tenant deployments.
---

# cortex_host (Resource)

Manages a host registration in Cortex XSOAR 6. Hosts represent XSOAR server nodes that can be assigned to HA groups for multi-tenant and high-availability deployments. This resource manages host registration via the API only -- it does not perform SSH-based provisioning or software installation.

Supported on XSOAR 6 only.

~> **Note:** This resource manages host registration through the XSOAR API. It does not install or configure the XSOAR software on the host. The host must be accessible and running XSOAR before it can be registered.

~> **Note:** Changing the `name` attribute forces replacement of the resource (destroy and recreate).

## Example Usage

### Standalone Host

```terraform
resource "cortex_host" "app_server" {
  name = "xsoar-app-01"
}
```

### Host in an HA Group

```terraform
resource "cortex_ha_group" "production" {
  name                 = "production-cluster"
  elasticsearch_url    = "https://es-prod.internal:9200"
  elastic_index_prefix = "xsoar-prod"
}

resource "cortex_host" "app_server_01" {
  name          = "xsoar-app-01"
  ha_group_name = cortex_ha_group.production.name
}

resource "cortex_host" "app_server_02" {
  name          = "xsoar-app-02"
  ha_group_name = cortex_ha_group.production.name
}
```

## Schema

### Required

- `name` (String, Forces Replacement) The unique name of the host. Changing this forces a new resource.

### Optional

- `ha_group_name` (String) The name of the HA group to assign this host to. If not specified, the host is not assigned to any HA group. This attribute is also computed -- if the host is assigned to a group outside of Terraform, this value will be populated on read.

### Read-Only

- `id` (String) The identifier of the host.
- `ha_group_id` (String) The ID of the HA group this host belongs to.
- `status` (String) The current status of the host (e.g., `"active"`, `"inactive"`).

## Import

Hosts can be imported using the host ID:

```shell
terraform import cortex_host.app_server <host-id>
```
