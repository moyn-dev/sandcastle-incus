package domain

import "strings"

// CoveredByProjectCertificate matches precisely one non-wildcard label.
// The apex is deliberately excluded: public zone apex orders remain per-name.
func CoveredByProjectCertificate(hostname, projectDomain string) bool {
	h := strings.ToLower(strings.Trim(strings.TrimSpace(hostname), "."))
	d := strings.ToLower(strings.Trim(strings.TrimSpace(projectDomain), "."))
	if d == "" || !strings.HasSuffix(h, "."+d) {
		return false
	}
	label := strings.TrimSuffix(h, "."+d)
	return label != "" && !strings.ContainsAny(label, ".*")
}
