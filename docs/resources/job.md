---
page_title: "cortex_job Resource - cortex"
subcategory: ""
description: |-
  Manages a scheduled job in Cortex XSOAR/XSIAM.
---

# cortex_job (Resource)

Manages a scheduled job in Cortex XSOAR/XSIAM.

Jobs are scheduled tasks that can trigger playbooks at defined intervals. They are commonly used for recurring operations such as threat feed ingestion, report generation, and automated housekeeping.

Supported on XSOAR 6, XSOAR 8 OPP, XSOAR 8 SaaS, and XSIAM.

~> **XSIAM Note:** XSIAM requires `human_cron` and `start_date` instead of a standard `cron` expression. The `cron` attribute is not used on XSIAM.

## Example Usage

### Basic scheduled job (XSOAR 6/8)

```terraform
resource "cortex_job" "feed_sync" {
  name        = "Daily Feed Sync"
  playbook_id = "FeedSync"
  type        = "Feed Maintenance"
  scheduled   = true
  cron        = "0 */6 * * *"
  recurrent   = true
}
```

### Simple one-time job

```terraform
resource "cortex_job" "onboarding" {
  name        = "Initial Onboarding"
  playbook_id = "OnboardingPlaybook"
  type        = "Unclassified"
  scheduled   = false
}
```

### Job with tags and trigger behavior (XSOAR 6/8)

```terraform
resource "cortex_job" "cleanup" {
  name               = "Nightly Cleanup"
  playbook_id        = "CloseStaleIncidents"
  type               = "Housekeeping"
  scheduled          = true
  cron               = "0 2 * * *"
  recurrent          = true
  should_trigger_new = true
  tags               = ["maintenance", "nightly"]
}
```

### XSIAM job with human_cron (every 2 hours)

```terraform
resource "cortex_job" "xsiam_feed" {
  name               = "XSIAM Feed Ingestion"
  type               = "Unclassified"
  scheduled          = true
  recurrent          = true
  should_trigger_new = true
  start_date         = "2026-03-01T00:00:00Z"
  ending_type        = "never"

  human_cron = {
    time_period_type = "hours"
    time_period      = 2
    days             = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
  }
}
```

### XSIAM job with human_cron (every 30 minutes, weekdays only)

```terraform
resource "cortex_job" "xsiam_business_hours" {
  name               = "Business Hours Check"
  type               = "Unclassified"
  scheduled          = true
  recurrent          = true
  should_trigger_new = true
  start_date         = "2026-01-01T08:00:00Z"
  ending_type        = "never"

  human_cron = {
    time_period_type = "minutes"
    time_period      = 30
    days             = ["MON", "TUE", "WED", "THU", "FRI"]
  }
}
```

### XSIAM job with end date

```terraform
resource "cortex_job" "xsiam_temp" {
  name               = "Temporary Monitoring Job"
  type               = "Unclassified"
  scheduled          = true
  recurrent          = true
  should_trigger_new = true
  start_date         = "2026-03-01T00:00:00Z"
  ending_date        = "2026-06-01T00:00:00Z"
  ending_type        = "by_date"

  human_cron = {
    time_period_type = "hours"
    time_period      = 1
    days             = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
  }
}
```

## Schema

### Required

- `name` (String) The display name of the job.

### Optional

- `playbook_id` (String) The ID of the playbook to execute when the job runs.
- `type` (String) The incident type associated with the job (e.g., `"Unclassified"`, `"Feed Maintenance"`). Defaults to empty string.
- `scheduled` (Boolean) Whether the job should run on a schedule. Defaults to `false`.
- `cron` (String) A cron expression defining the job schedule (e.g., `"0 */6 * * *"` for every 6 hours). Used on XSOAR 6 and XSOAR 8. Not used on XSIAM -- use `human_cron` instead.
- `recurrent` (Boolean) Whether the job should repeat according to the schedule. Defaults to `false`.
- `should_trigger_new` (Boolean) Whether to trigger a new incident each time the job runs, even if a previous one is still active. Defaults to `false`.
- `tags` (List of String) A list of tags to associate with the job.
- `start_date` (String) The start date for the job schedule in ISO 8601 format (e.g., `"2026-03-01T00:00:00Z"`). Required on XSIAM.
- `ending_date` (String) The ending date for the job schedule in ISO 8601 format. Defaults to `start_date` value if not specified.
- `ending_type` (String) When the job should stop running. Valid values: `"never"` (default), `"by_date"`.
- `human_cron` (Object) Human-readable schedule definition. Required on XSIAM, optional on XSOAR. Attributes:
  - `time_period_type` (String, Required) The time period unit. Valid values: `"minutes"`, `"hours"`, `"days"`, `"weeks"`, `"months"`.
  - `time_period` (Number) The interval value (e.g., `2` with `time_period_type = "hours"` means every 2 hours). Defaults to `1`.
  - `days` (List of String) Days of the week to run. Valid values: `"SUN"`, `"MON"`, `"TUE"`, `"WED"`, `"THU"`, `"FRI"`, `"SAT"`. If omitted, runs every day.

### Read-Only

- `id` (String) The unique identifier of the job.
- `version` (Number) The internal version of the job, used for optimistic locking.

## Import

Import is supported using the job name:

```shell
terraform import cortex_job.feed_sync "Daily Feed Sync"
```
