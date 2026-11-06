# SSM Patch Manager: a baseline (what is approved), a patch group (which instances), a maintenance window (when)
# and a task (run AWS-RunPatchBaseline). LocalStack stores these but runs no instance, so patching is "defined",
# never "observed" (docs/localstack-limitations.md).

resource "aws_ssm_patch_baseline" "this" {
  name             = "${var.name_prefix}-baseline"
  description      = "Security and bug-fix patches, Critical and Important, approved after ${var.approve_after_days} days"
  operating_system = var.operating_system

  approval_rule {
    approve_after_days = var.approve_after_days
    compliance_level   = "HIGH"

    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security", "Bugfix"]
    }

    patch_filter {
      key    = "SEVERITY"
      values = ["Critical", "Important"]
    }
  }
}

resource "aws_ssm_patch_group" "this" {
  baseline_id = aws_ssm_patch_baseline.this.id
  patch_group = var.patch_group
}

resource "aws_ssm_maintenance_window" "this" {
  name                       = "${var.name_prefix}-patching"
  schedule                   = var.schedule
  duration                   = 3
  cutoff                     = 1
  allow_unassociated_targets = false
}

resource "aws_ssm_maintenance_window_target" "this" {
  window_id     = aws_ssm_maintenance_window.this.id
  name          = "${var.name_prefix}-patch-group"
  resource_type = "INSTANCE"

  targets {
    key    = "tag:Patch Group"
    values = [var.patch_group]
  }
}

resource "aws_ssm_maintenance_window_task" "patch" {
  window_id       = aws_ssm_maintenance_window.this.id
  name            = "${var.name_prefix}-install-patches"
  task_type       = "RUN_COMMAND"
  task_arn        = "AWS-RunPatchBaseline"
  priority        = 1
  max_concurrency = "50%"
  max_errors      = "25%"

  targets {
    key    = "WindowTargetIds"
    values = [aws_ssm_maintenance_window_target.this.id]
  }

  task_invocation_parameters {
    run_command_parameters {
      parameter {
        name   = "Operation"
        values = ["Install"]
      }
    }
  }
}
