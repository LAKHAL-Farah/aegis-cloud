package main

import rego.v1

# Every IAM policy document in the plan, decoded from its JSON string.
policy_docs contains {"addr": r.address, "doc": json.unmarshal(r.change.after.policy)} if {
	some r in input.resource_changes
	r.type in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_group_policy"}
	is_string(r.change.after.policy)
}

statements(doc) := doc.Statement if is_array(doc.Statement)

statements(doc) := [doc.Statement] if is_object(doc.Statement)

as_list(x) := x if is_array(x)

as_list(x) := [x] if is_string(x)

# CIS 1.16: no policy may allow "*" on "*"
deny contains msg if {
	some pd in policy_docs
	some st in statements(pd.doc)
	st.Effect == "Allow"
	some action in as_list(st.Action)
	action in {"*", "*:*"}
	some res in as_list(st.Resource)
	res == "*"
	msg := sprintf("[AEG-IAM-001] %s allows Action %q on Resource '*' (CIS 1.16)", [pd.addr, action])
}

# Permissions go on roles/groups, never inline on a user. (Design rule: no IAM users.)
deny contains msg if {
	some r in input.resource_changes
	r.type in {"aws_iam_user_policy", "aws_iam_user_policy_attachment"}
	msg := sprintf("[AEG-IAM-002] %s attaches permissions to an IAM user; use a role", [r.address])
}