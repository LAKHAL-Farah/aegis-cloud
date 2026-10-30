mock_provider "aws" {
  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::444444444444:policy/aegis-permission-boundary"
    }
  }
}




variables {
  account_id = "444444444444"
}

run "password_policy_meets_cis" {
  command = plan

  assert {
    condition     = aws_iam_account_password_policy.this.minimum_password_length >= 14
    error_message = "CIS 1.8: minimum password length must be 14 or more."
  }

  assert {
    condition     = aws_iam_account_password_policy.this.password_reuse_prevention >= 24
    error_message = "CIS 1.9: password reuse prevention must be 24."
  }
}

run "deployer_role_is_bounded" {
  command = apply

  assert {
    condition     = aws_iam_role.deployer.permissions_boundary != null
    error_message = "The deployer role must carry the permission boundary."
  }
}

run "boundary_blocks_user_creation" {
  command = plan

  assert {
    condition     = strcontains(aws_iam_policy.boundary.policy, "iam:CreateUser")
    error_message = "The boundary must deny iam:CreateUser (no backdoor users)."
  }
}

run "break_glass_requires_mfa" {
  command = plan

  assert {
    condition     = strcontains(aws_iam_role.break_glass.assume_role_policy, "aws:MultiFactorAuthPresent")
    error_message = "The break-glass role must require MFA to assume."
  }
}