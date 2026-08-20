package policy

import (
	"strings"
	"testing"
)

func TestDetectAndRedactDoesNotRetainValues(t *testing.T) {
	input := "Contact Ada at ada@example.com with sk-live_abcdefghijklmnop"
	findings := Detect(input)
	if len(findings) != 2 {
		t.Fatalf("findings %#v", findings)
	}
	output := Redact(input, findings)
	if strings.Contains(output, "ada@example.com") || strings.Contains(output, "abcdefghijklmnop") {
		t.Fatal("sensitive value remained")
	}
	for _, finding := range findings {
		if len(finding.Fingerprint) != 16 {
			t.Fatal("unexpected fingerprint")
		}
	}
}
func TestNoFalseMatchForOrdinaryText(t *testing.T) {
	if got := Detect("hello from the privacy gateway"); len(got) != 0 {
		t.Fatalf("got %#v", got)
	}
}
