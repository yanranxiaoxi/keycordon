package veto

import "testing"

func TestReject(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// paths
		{"~/.ssh/id_ed25519", true},
		{"./config/secrets.yaml", true},
		{"../secrets.env", true},
		{"/home/alice/.ssh/id_rsa", true},
		{"/Users/alice/legacy_credentials/x7k2/adc.json", true},
		{`C:\Users\alice\proj`, true},
		{"/etc/ssl/private/server.key", true},
		// versions
		{"9.2.0-beta1", true},
		{"2.4.0-beta02", true},
		{"^4.0.0-beta.1", true},
		{"v1.2.3", true},
		{"1.0.0-rc1", true},
		// moments
		{"2026-08-30T11:44:31.312645+08:00", true},
		{"2026-08-30T11", true},
		{"2026-08-30T11:44:31Z", true},
		// line references
		{"L643-669", true},
		{"L12", true},
		{"643:12", true},
		// names in code
		{"get_access_token_v2", true},
		{"env.SECRET_V2", true},
		{"refreshToken", true},
		{"max_tokens_v3", true},
		{"os.environ", true},
		{"config.settings.database", true},
		// next field
		{"UI_ADDR=127.0.0.1:39117", true},

		// real secrets must survive
		{"ghp_NqVwYS81VP7Hb1DX8pQ2mZ7xL4kR9tWcB3vE", false},
		{"sk-proj-AbCdEf1234567890GhIjKlMnOpQrStUvWx", false},
		{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY", false},
		{"hunter2-but-longer", false},
		{"Sup3rS3cretPw9x", false},
		{"Zx8Kq2Lm9Pw4Rt7Yv3Bn6Hs1Jd5Gf0Ac", false},
		{"AKIAQX2LMNB7RT5KJW3P", false},
		{"correcthorsebattery", false},
		{"pa55word-9x", false},
		{"Zq7xLm2Vp9r", false},
		{"sk-live-9f8a7b6c5d4e3f2a1b0c", false},
		{"12345678", false},
		{"aB3$k9_Qz-7mP+x2Lw/Rt4!", false},
	}
	for _, c := range cases {
		if got := Reject(c.in, 0, len(c.in)); got != c.want {
			t.Errorf("Reject(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestRejectRange(t *testing.T) {
	s := `x = "~/.ssh/id_ed25519"`
	if !Reject(s, 5, len(s)-1) {
		t.Fatal("range not honoured")
	}
	if Reject(s, 0, 0) || Reject(s, 5, 100) || Reject(s, -1, 3) {
		t.Fatal("bad range accepted")
	}
}

func TestIdentWords(t *testing.T) {
	cases := map[string][]string{
		"refreshToken2":       {"refresh", "Token2"},
		"get_access_token_v2": {"get", "access", "token", "v2"},
		"env.SECRET_V2":       {"env", "SECRET", "V2"},
	}
	for in, want := range cases {
		got := identWords(in)
		if len(got) != len(want) {
			t.Fatalf("%q: %q want %q", in, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%q: %q want %q", in, got, want)
			}
		}
	}
}
