---
page_title: "cortex_device_control_class Resource - cortex"
subcategory: ""
description: |-
  Manages device control classes in XSIAM.
---

# cortex_device_control_class (Resource)

Manages device control classes in XSIAM. Device control classes define categories of USB and peripheral devices that can be allowed or blocked by endpoint security policies.

Each class has a system-assigned UUID identifier and a user-defined type. The type is immutable after creation -- changing it requires destroying and recreating the resource.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

## Example Usage

```terraform
resource "cortex_device_control_class" "usb_storage" {
  type = "Removable Storage"
}

resource "cortex_device_control_class" "bluetooth" {
  type = "Bluetooth"
}
```

## Argument Reference

* `type` - (Required, Forces new resource) The device class type name. Changing this value will destroy and recreate the resource.

## Attributes Reference

* `identifier` - The UUID assigned to this device control class by XSIAM.

## Import

Device control classes can be imported using their UUID identifier:

```shell
terraform import cortex_device_control_class.usb_storage a1b2c3d4-e5f6-7890-abcd-ef1234567890
```
