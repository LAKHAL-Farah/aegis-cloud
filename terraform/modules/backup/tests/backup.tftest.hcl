mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = {
      arn = "arn:aws:kms:us-east-1:444444444444:key/00000000-0000-0000-0000-000000000000"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::444444444444:role/mock-role"
    }
  }
}

variables {
  account_id    = "444444444444"
  resource_arns = ["arn:aws:s3:::aegis-data-444444444444"]
}

run "vault_is_encrypted_with_a_rotating_key" {
  command = apply

  assert {
    condition     = aws_kms_key.vault.enable_key_rotation == true && aws_backup_vault.this.kms_key_arn != null
    error_message = "Backups must be encrypted with a customer key that rotates."
  }
}

run "plan_keeps_backups_for_at_least_a_month" {
  command = plan

  assert {
    condition     = one(one(aws_backup_plan.daily.rule).lifecycle).delete_after >= 30
    error_message = "A restore after a slow-burning incident needs more than a week of history."
  }
}

run "selection_exists_only_when_there_is_something_to_back_up" {
  command = plan

  assert {
    condition     = length(aws_backup_selection.this) == 1
    error_message = "A resource list must produce a selection."
  }
}

run "no_selection_without_resources" {
  command = plan

  variables {
    resource_arns = []
  }

  assert {
    condition     = length(aws_backup_selection.this) == 0
    error_message = "An empty selection is invalid."
  }
}
