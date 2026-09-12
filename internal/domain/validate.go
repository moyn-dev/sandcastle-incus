package domain

import (
	"fmt"
	"strings"
)

type Policy struct {
	AllowedSuffixes []string
	DeniedSuffixes  []string
}

func ValidateTenantDNSSuffix(value string, policy Policy) (string, error) {
	suffix := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if suffix == "" {
		return "", fmt.Errorf("tenant DNS suffix is required")
	}
	if strings.Contains(suffix, ".") {
		return "", fmt.Errorf("tenant DNS suffix %q must be a single DNS label", suffix)
	}
	if err := validateDomainLabels(suffix, value, "tenant DNS suffix"); err != nil {
		return "", err
	}
	allowedSuffixes, err := normalizePolicySuffixes("allowed", policy.AllowedSuffixes)
	if err != nil {
		return "", err
	}
	deniedSuffixes, err := normalizePolicySuffixes("denied", policy.DeniedSuffixes)
	if err != nil {
		return "", err
	}
	if !suffixAllowed(suffix, allowedSuffixes) {
		if specialUseName := deniedSpecialUseDomain(suffix); specialUseName != "" {
			return "", fmt.Errorf("tenant DNS suffix %q uses denied special-use suffix %q", suffix, specialUseName)
		}
		if publicTLDs[suffix] {
			return "", fmt.Errorf("tenant DNS suffix %q uses denied public TLD %q", suffix, suffix)
		}
	}
	for _, deniedSuffix := range deniedSuffixes {
		if suffix == deniedSuffix || strings.HasSuffix(suffix, "."+deniedSuffix) {
			return "", fmt.Errorf("tenant DNS suffix %q uses admin-denied suffix %q", suffix, deniedSuffix)
		}
	}
	return suffix, nil
}

func NormalizePolicySuffix(value string) (string, error) {
	suffix := strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), "."), ".")
	if suffix == "" {
		return "", fmt.Errorf("domain suffix is required")
	}
	if err := validateDomainLabels(suffix, value, "domain suffix"); err != nil {
		return "", err
	}
	return suffix, nil
}

func normalizePolicySuffixes(kind string, suffixes []string) ([]string, error) {
	output := make([]string, 0, len(suffixes))
	for _, suffix := range suffixes {
		if strings.TrimSpace(suffix) == "" {
			continue
		}
		normalized, err := NormalizePolicySuffix(suffix)
		if err != nil {
			return nil, fmt.Errorf("invalid %s domain suffix %q: %w", kind, suffix, err)
		}
		output = append(output, normalized)
	}
	return output, nil
}

func suffixAllowed(domain string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}

func deniedSpecialUseDomain(domain string) string {
	for name := range specialUseNames {
		if domain == name || strings.HasSuffix(domain, "."+name) {
			return name
		}
	}
	return ""
}

// NormalizePublicDNSZone normalizes a Public DNS Zone name (ADR-0027):
// lowercase, trimmed, one trailing dot stripped, labels validated like every
// other DNS name on the install. A zone is a registered domain, so it must
// carry at least two labels — a bare TLD is never a zone an admin can hold.
func NormalizePublicDNSZone(value string) (string, error) {
	zone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if zone == "" {
		return "", fmt.Errorf("public DNS zone is required")
	}
	if err := validateDomainLabels(zone, value, "public DNS zone"); err != nil {
		return "", err
	}
	if !strings.Contains(zone, ".") {
		return "", fmt.Errorf("invalid public DNS zone %q: a zone needs at least two labels", value)
	}
	return zone, nil
}

func validateDomainLabels(domain string, original string, label string) error {
	if strings.ContainsAny(domain, "/ ") {
		return fmt.Errorf("invalid %s %q", label, original)
	}
	labels := strings.Split(domain, ".")
	for _, part := range labels {
		if part == "" || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return fmt.Errorf("invalid %s %q", label, original)
		}
		for _, r := range part {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("invalid %s %q", label, original)
			}
		}
	}
	return nil
}
