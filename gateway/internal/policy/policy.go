package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

type Finding struct {
	Type        string `json:"type"`
	Start       int    `json:"start"`
	End         int    `json:"end"`
	Fingerprint string `json:"fingerprint"`
}

var patterns = []struct {
	name  string
	regex *regexp.Regexp
}{
	{"email", regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)},
	{"credit_card", regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)},
	{"api_key", regexp.MustCompile(`\b(?:sk|pk|api)[-_][A-Za-z0-9_-]{16,}\b`)},
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{"india_pan", regexp.MustCompile(`\b[A-Z]{5}[0-9]{4}[A-Z]\b`)},
}

func Detect(text string) []Finding {
	out := []Finding{}
	for _, pattern := range patterns {
		for _, indexes := range pattern.regex.FindAllStringIndex(text, -1) {
			value := text[indexes[0]:indexes[1]]
			sum := sha256.Sum256([]byte(strings.ToLower(value)))
			out = append(out, Finding{Type: pattern.name, Start: indexes[0], End: indexes[1], Fingerprint: hex.EncodeToString(sum[:8])})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}
func Redact(text string, findings []Finding) string {
	if len(findings) == 0 {
		return text
	}
	var b strings.Builder
	cursor := 0
	for _, finding := range findings {
		if finding.Start < cursor {
			continue
		}
		b.WriteString(text[cursor:finding.Start])
		b.WriteString("[REDACTED_" + strings.ToUpper(finding.Type) + "]")
		cursor = finding.End
	}
	b.WriteString(text[cursor:])
	return b.String()
}
