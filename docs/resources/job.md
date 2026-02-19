---
page_title: "cortex_job Resource - cortex"
subcategory: ""
description: |-
  Manages a scheduled job in XSOAR.
---

# cortex_job (Resource)

Manages a scheduled job in XSOAR.

Jobs are scheduled tasks that can trigger playbooks at defined intervals using cron expressions. They are commonly used for recurring operations such as threat feed ingestion, report generation, and automated housekeeping.

## Example Usage

### Basic scheduled job

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

### Job with tags and trigger behavior

```terraform
resource "cortex_job" "cleanup" {
  name               = "Nightly Cleanup"
  playbook_id        = "CleanupOldIncidents"
  type               = "Housekeeping"
  scheduled          = true
  cron               = "0 2 * * *"
  recurrent          = true
  should_trigger_new = true
  tags               = ["maintenance", "nightly"]
}
```

## Schema

### Required

- `name` (String) The display name of the job.

### Optional

- `playbook_id` (String) The ID of the playbook to execute when the job runs.
- `type` (String) The incident type associated with the job (e.g., `"Unclassified"`, `"Feed Maintenance"`).
- `scheduled` (Boolean) Whether the job should run on a schedule.
- `cron` (String) A cron expression defining the job schedule (e.g., `"0 */6 * * *"` for every 6 hours).
- `recurrent` (Boolean) Whether the job should repeat according to the cron schedule.
- `should_trigger_new` (Boolean) Whether to trigger a new incident each time the job runs, even if a previous one is still active.
- `tags` (List of String) A list of tags to associate with the job.

### Read-Only

- `id` (String) The unique identifier of the job.
- `version` (Number) The internal version of the job, used for optimistic locking.

## Import

Import is supported using the job ID:

```shell
terraform import cortex_job.feed_sync "Daily Feed Sync"
```
