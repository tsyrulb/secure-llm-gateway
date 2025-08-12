package gateway

deny contains msg if {
  input.model == "openai:gpt-4o"
  input.tenant != "trusted_tenant"
  msg := "gpt-4o only allowed for trusted tenants"
}

deny contains msg if {
  input.max_tokens != null
  input.max_tokens > 2048
  msg := "max_tokens exceeds policy cap"
}

deny contains msg if {
  input.egress_url != ""
  not startswith(input.egress_url, "https://api.my-allowlist.com/")
  msg := sprintf("egress blocked: %s", [input.egress_url])
}
