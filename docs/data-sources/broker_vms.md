---
page_title: "cortex_broker_vms Data Source - terraform-provider-cortex"
subcategory: ""
description: |-
  Retrieves a list of all broker VM devices in XSIAM.
---

# cortex_broker_vms (Data Source)

Retrieves a read-only list of all broker VM devices registered in XSIAM. Broker VMs act as on-premises data collectors and forwarders, bridging network-isolated environments with the XSIAM cloud platform. This data source can be used to reference broker VMs when configuring collector policies or other resources that target specific broker devices.

~> **Note:** This data source is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

## Example Usage

```terraform
data "cortex_broker_vms" "all" {}

output "broker_vm_names" {
  value = data.cortex_broker_vms.all.vms[*].name
}

output "active_brokers" {
  value = [
    for vm in data.cortex_broker_vms.all.vms : vm.name
    if vm.status == "CONNECTED"
  ]
}
```

## Schema

### Read-Only

- `vms` (List of Object) The list of all broker VM devices in XSIAM.
  - `device_id` (String) The unique identifier of the broker VM device.
  - `name` (String) The display name of the broker VM.
  - `status` (String) The current connection status of the broker VM (e.g., `CONNECTED`, `DISCONNECTED`).
  - `fqdn` (String) The fully qualified domain name of the broker VM host.
  - `is_cluster` (Boolean) Whether this broker VM is part of a high-availability cluster.
