package vault

import "strings"

// kindPrefixes maps well-known secret prefixes to placeholder types. The type
// depends only on the value, never on which rule found it, so the same secret
// always gets the same placeholder regardless of context (prefix cache).
var kindPrefixes = []struct{ prefix, kind string }{
	{"-----BEGIN", "PRIVATE_KEY"},
	{"sk-ant-", "ANTHROPIC_KEY"},
	{"sk-proj-", "OPENAI_KEY"},
	{"sk-svcacct-", "OPENAI_KEY"},
	{"sk-admin-", "OPENAI_KEY"},
	{"sk-or-", "OPENROUTER_KEY"},
	{"sk-", "API_KEY"},
	{"ghp_", "GITHUB_TOKEN"},
	{"gho_", "GITHUB_TOKEN"},
	{"ghu_", "GITHUB_TOKEN"},
	{"ghs_", "GITHUB_TOKEN"},
	{"ghr_", "GITHUB_TOKEN"},
	{"github_pat_", "GITHUB_TOKEN"},
	{"glpat-", "GITLAB_TOKEN"},
	{"glrt-", "GITLAB_TOKEN"},
	{"AKIA", "AWS_KEY"},
	{"ASIA", "AWS_KEY"},
	{"AIza", "GOOGLE_KEY"},
	{"ya29.", "GOOGLE_TOKEN"},
	{"xoxb-", "SLACK_TOKEN"},
	{"xoxp-", "SLACK_TOKEN"},
	{"xapp-", "SLACK_TOKEN"},
	{"hf_", "HF_TOKEN"},
	{"gsk_", "GROQ_KEY"},
	{"npm_", "NPM_TOKEN"},
	{"pypi-", "PYPI_TOKEN"},
	{"dop_v1_", "DO_TOKEN"},
	{"sk_live_", "STRIPE_KEY"},
	{"rk_live_", "STRIPE_KEY"},
	{"sk_test_", "STRIPE_KEY"},
	{"eyJ", "JWT"},
	{"ssh-rsa ", "SSH_KEY"},
	{"ssh-ed25519 ", "SSH_KEY"},
	{"postgres://", "DB_URI"},
	{"postgresql://", "DB_URI"},
	{"mysql://", "DB_URI"},
	{"mongodb://", "DB_URI"},
	{"mongodb+srv://", "DB_URI"},
	{"redis://", "DB_URI"},
	{"rediss://", "DB_URI"},
	{"amqp://", "DB_URI"},
}

// Kind returns the placeholder type for a secret value.
func Kind(value string) string {
	for _, p := range kindPrefixes {
		if strings.HasPrefix(value, p.prefix) {
			return p.kind
		}
	}
	return "TOKEN"
}
