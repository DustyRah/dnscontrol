// Package dynu implements a DNSControl provider for Dynu (https://www.dynu.com).
// API docs: https://www.dynu.com/en-US/Resources/API
// Auth: set api_key in creds.json.
// Module: github.com/DNSControl/dnscontrol/v4
package dynu

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DNSControl/dnscontrol/v4/models"
	"github.com/DNSControl/dnscontrol/v4/pkg/diff2"
	"github.com/DNSControl/dnscontrol/v4/pkg/providers"
)

var features = providers.DocumentationNotes{
	providers.CanGetZones:   providers.Can(),
	providers.CanConcur:     providers.Cannot(),
	providers.CanUseSRV:     providers.Can(),
	providers.CanUseCAA:     providers.Can(),
	providers.CanUseTLSA:    providers.Can(),
	providers.CanUseSSHFP:   providers.Can(),
	providers.CanUseAlias:   providers.Cannot(),
	providers.CanAutoDNSSEC: providers.Cannot(),
}

func init() {
	fns := providers.DspFuncs{
		Initializer:   New,
		RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType("DYNU", fns, features)
	providers.RegisterCredsMetadata("DYNU", providers.CredsMetadata{
		DisplayName: "Dynu",
		Kind:        providers.KindDNS,
		DocsURL:     "https://docs.dnscontrol.org/provider/dynu",
		PortalURL:   "https://www.dynu.com/en-US/ControlPanel",
		Fields: []providers.CredsField{
			{Key: "api_key", Label: "API Key", Required: true, Secret: true},
		},
	})
}

// New creates a Dynu provider from credentials.
func New(m map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	apiKey := m["api_key"]
	if apiKey == "" {
		return nil, fmt.Errorf("missing Dynu API key")
	}
	return &dynuProvider{
		apiKey:    apiKey,
		domainIDs: map[string]int64{},
	}, nil
}

// GetNameservers returns Dynu's authoritative nameservers.
func (d *dynuProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	return models.ToNameservers([]string{
		"ns1.dynu.com",
		"ns2.dynu.com",
		"ns3.dynu.com",
		"ns4.dynu.com",
		"ns5.dynu.com",
		"ns6.dynu.com",
	})
}

// GetZoneRecords downloads all records for the zone and returns them as RecordConfigs.
func (d *dynuProvider) GetZoneRecords(dc *models.DomainConfig) (models.Records, error) {
	domainID, err := d.getDomainID(dc.Name)
	if err != nil {
		return nil, err
	}
	records, err := d.getRecords(domainID)
	if err != nil {
		return nil, err
	}
	var existing models.Records
	for _, r := range records {
		rc, err := toRc(r, dc.Name)
		if err != nil {
			return nil, err
		}
		if rc != nil {
			existing = append(existing, rc)
		}
	}
	return existing, nil
}

// GetZoneRecordsCorrections computes the corrections needed to bring the zone to the desired state.
func (d *dynuProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, existing models.Records) ([]*models.Correction, int, error) {
	domainID, err := d.getDomainID(dc.Name)
	if err != nil {
		return nil, 0, err
	}

	instructions, _, err := diff2.ByRecord(existing, dc, nil)
	if err != nil {
		return nil, 0, err
	}

	var corrections []*models.Correction
	for _, inst := range instructions {
		// Apex NS records are managed by Dynu internally and cannot be created,
		// modified, or deleted via the API.
		if inst.New != nil && len(inst.New) > 0 && inst.New[0].Type == "NS" && inst.New[0].Name == "@" {
			continue
		}
		if inst.Old != nil && len(inst.Old) > 0 && inst.Old[0].Type == "NS" && inst.Old[0].Name == "@" {
			continue
		}

		switch inst.Type {
		case diff2.CREATE:
			req := toReq(inst.New[0])
			msg := strings.Join(inst.Msgs, "\n")
			corrections = append(corrections, &models.Correction{
				Msg: msg,
				F: func() error {
					return d.createRecord(domainID, req)
				},
			})
		case diff2.CHANGE:
			// Dynu overrides NS record TTL to 3600 and does not allow modifying NS content.
			// Silently skip CHANGE corrections for NS records to maintain idempotency.
			if inst.New[0].Type == "NS" {
				continue
			}
			// Dynu's API returns 500 when updating an existing MX record to a null MX
			// (priority=0, target="."). Work around this by deleting and recreating.
			if inst.New[0].Type == "MX" && inst.New[0].MxPreference == 0 && inst.New[0].GetTargetField() == "." {
				oldID := inst.Old[0].Original.(*dynuRecord).ID
				req := toReq(inst.New[0])
				msg := strings.Join(inst.Msgs, "\n")
				corrections = append(corrections, &models.Correction{
					Msg: msg,
					F: func() error {
						if err := d.deleteRecord(domainID, oldID); err != nil {
							return err
						}
						return d.createRecord(domainID, req)
					},
				})
				continue
			}
			req := toReq(inst.New[0])
			oldID := inst.Old[0].Original.(*dynuRecord).ID
			msg := strings.Join(inst.Msgs, "\n")
			corrections = append(corrections, &models.Correction{
				Msg: msg,
				F: func() error {
					return d.updateRecord(domainID, oldID, req)
				},
			})
		case diff2.DELETE:
			oldID := inst.Old[0].Original.(*dynuRecord).ID
			msg := strings.Join(inst.Msgs, "\n")
			corrections = append(corrections, &models.Correction{
				Msg: msg,
				F: func() error {
					return d.deleteRecord(domainID, oldID)
				},
			})
		}
	}
	return corrections, len(corrections), nil
}

// GetZones returns all DNS zones in the account (implements providers.ZoneLister).
func (d *dynuProvider) GetZones() ([]string, error) {
	domains, err := d.getDomains()
	if err != nil {
		return nil, err
	}
	zones := make([]string, len(domains))
	for i, dom := range domains {
		zones[i] = dom.Name
	}
	return zones, nil
}

// AuditRecords returns errors for any record types not supported by Dynu.
func AuditRecords(records []*models.RecordConfig) []error {
	var errs []error
	for _, rc := range records {
		switch rc.Type {
		case "A", "AAAA", "CAA", "CNAME", "DNAME", "MX", "NAPTR", "NS", "PTR", "SRV", "SSHFP", "TLSA", "TXT":
			if rc.Type == "TXT" && rc.GetTargetTXTJoined() == "" {
				errs = append(errs, fmt.Errorf("Dynu does not support empty TXT records (label: %q)", rc.NameFQDN))
			}
			if rc.Type == "SRV" && rc.GetTargetField() == "." {
				errs = append(errs, fmt.Errorf("Dynu does not support null SRV targets (label: %q)", rc.NameFQDN))
			}
			if strings.HasPrefix(rc.Name, "*") {
				errs = append(errs, fmt.Errorf("Dynu does not support wildcard records (label: %q)", rc.NameFQDN))
			}
		default:
			errs = append(errs, fmt.Errorf("Dynu provider does not support %q records (label: %q)", rc.Type, rc.NameFQDN))
		}
	}
	return errs
}

// toRc converts a Dynu API record to a DNSControl RecordConfig.
// Returns (nil, nil) for record types that are managed by Dynu internally (SOA, WCA)
// or are not yet supported, so callers should skip nil results.
func toRc(r *dynuRecord, domain string) (*models.RecordConfig, error) {
	switch r.RecordType {
	case "SOA", "WCA":
		return nil, nil
	}

	rc := &models.RecordConfig{
		Type:     r.RecordType,
		TTL:      uint32(r.TTL),
		Original: r,
	}
	rc.SetLabel(r.NodeName, domain)

	var err error
	switch r.RecordType {
	case "A":
		err = rc.SetTarget(r.IPv4Address)
	case "AAAA":
		err = rc.SetTarget(r.IPv6Address)
	case "CNAME":
		err = rc.SetTarget(ensureTrailingDot(r.Host))
	case "DNAME":
		err = rc.SetTarget(ensureTrailingDot(r.Host))
	case "MX":
		host := r.Host
		// Dynu stores null MX (priority 0, target ".") by returning the zone name as host.
		// Normalise that back to "." so DNSControl sees a stable null MX target.
		if intOrZero(r.Priority) == 0 && (host == "" || strings.TrimSuffix(host, ".") == domain) {
			host = "."
		}
		err = rc.SetTargetMX(uint16(intOrZero(r.Priority)), ensureTrailingDot(host))
	case "NS":
		err = rc.SetTarget(ensureTrailingDot(r.Host))
	case "PTR":
		err = rc.SetTarget(ensureTrailingDot(r.Host))
	case "SPF", "TXT":
		// Dynu stores SPF as a separate type; normalise to TXT.
		rc.Type = "TXT"
		err = rc.SetTargetTXT(r.TextData)
	case "SRV":
		err = rc.SetTargetSRV(uint16(intOrZero(r.Priority)), uint16(intOrZero(r.Weight)), uint16(intOrZero(r.Port)), ensureTrailingDot(r.Host))
	case "CAA":
		err = rc.SetTargetCAA(uint8(intOrZero(r.Flags)), r.Tag, r.Value)
	case "TLSA":
		// Dynu stores cert-associated-data as base64; DNSControl expects hex.
		certHex, convErr := base64ToHex(r.CertificateAssociatedData)
		if convErr != nil {
			return nil, fmt.Errorf("TLSA certAssocData base64 decode for %s: %w", r.Hostname, convErr)
		}
		err = rc.SetTargetTLSA(uint8(intOrZero(r.CertificateUsage)), uint8(intOrZero(r.Selector)), uint8(intOrZero(r.MatchingType)), certHex)
	case "SSHFP":
		// Dynu stores the fingerprint as base64; DNSControl expects hex.
		fpHex, convErr := base64ToHex(r.FingerPrint)
		if convErr != nil {
			return nil, fmt.Errorf("SSHFP fingerprint base64 decode for %s: %w", r.Hostname, convErr)
		}
		err = rc.SetTargetSSHFP(uint8(intOrZero(r.Algorithm)), uint8(intOrZero(r.FingerPrintType)), fpHex)
	case "NAPTR":
		err = rc.SetTargetNAPTR(uint16(intOrZero(r.Order)), uint16(intOrZero(r.Preference)), r.NaptrFlags, r.Services, r.RegExp, ensureTrailingDot(r.Replacement))
	default:
		// Unsupported type from the API — silently skip rather than failing the sync.
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("record %s %s: %w", r.RecordType, r.Hostname, err)
	}
	return rc, nil
}

// toReq converts a DNSControl RecordConfig to a Dynu API create/update request body.
func toReq(rc *models.RecordConfig) *dynuRecord {
	nodeName := rc.Name
	if nodeName == "@" {
		nodeName = ""
	}
	req := &dynuRecord{
		NodeName:   nodeName,
		RecordType: rc.Type,
		TTL:        int(rc.TTL),
		State:      true,
	}
	switch rc.Type {
	case "A":
		req.IPv4Address = rc.GetTargetField()
	case "AAAA":
		req.IPv6Address = rc.GetTargetField()
	case "CNAME", "NS", "PTR", "DNAME":
		req.Host = strings.TrimSuffix(rc.GetTargetField(), ".")
	case "MX":
		req.Host = strings.TrimSuffix(rc.GetTargetField(), ".")
		pref := int(rc.MxPreference)
		req.Priority = &pref
	case "TXT":
		req.TextData = rc.GetTargetTXTJoined()
	case "SRV":
		req.Host = strings.TrimSuffix(rc.GetTargetField(), ".")
		prio := int(rc.SrvPriority)
		weight := int(rc.SrvWeight)
		port := int(rc.SrvPort)
		req.Priority = &prio
		req.Weight = &weight
		req.Port = &port
	case "CAA":
		flags := int(rc.CaaFlag)
		req.Flags = &flags
		req.Tag = rc.CaaTag
		req.Value = rc.GetTargetField()
	case "TLSA":
		usage := int(rc.TlsaUsage)
		selector := int(rc.TlsaSelector)
		mtype := int(rc.TlsaMatchingType)
		req.CertificateUsage = &usage
		req.Selector = &selector
		req.MatchingType = &mtype
		// DNSControl uses hex; Dynu API expects base64.
		req.CertificateAssociatedData = hexToBase64(rc.GetTargetField())
	case "SSHFP":
		algo := int(rc.SshfpAlgorithm)
		fptype := int(rc.SshfpFingerprint)
		req.Algorithm = &algo
		req.FingerPrintType = &fptype
		// DNSControl uses hex; Dynu API expects base64.
		req.FingerPrint = hexToBase64(rc.GetTargetField())
	case "NAPTR":
		order := int(rc.NaptrOrder)
		pref := int(rc.NaptrPreference)
		req.Order = &order
		req.Preference = &pref
		req.NaptrFlags = rc.NaptrFlags
		req.Services = rc.NaptrService
		req.RegExp = rc.NaptrRegexp
		req.Replacement = strings.TrimSuffix(rc.GetTargetField(), ".")
	}
	return req
}

// base64ToHex converts a base64-encoded string to its lowercase hex representation.
func base64ToHex(b64 string) (string, error) {
	if b64 == "" {
		return "", nil
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hexToBase64 converts a hex string to standard base64.
// Returns the input unchanged if it cannot be hex-decoded (defensive fallback).
func hexToBase64(hexStr string) string {
	if hexStr == "" {
		return ""
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return hexStr
	}
	return base64.StdEncoding.EncodeToString(b)
}

func intOrZero(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func ensureTrailingDot(s string) string {
	if s == "" || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}
