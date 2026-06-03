package dynu

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const apiBase = "https://api.dynu.com/v2"

type dynuProvider struct {
	apiKey    string
	domainIDs map[string]int64
}

type apiResponse struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message,omitempty"`
}

type dynuDomain struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type domainsResponse struct {
	apiResponse
	Domains []dynuDomain `json:"domains"`
}

// dynuRecord maps to the Dynu API dnsRecord JSON object.
// Only fields used by the supported record types are included.
type dynuRecord struct {
	ID         int64  `json:"id,omitempty"`
	DomainID   int64  `json:"domainId,omitempty"`
	DomainName string `json:"domainName,omitempty"`
	NodeName   string `json:"nodeName"`
	Hostname   string `json:"hostname,omitempty"`
	RecordType string `json:"recordType"`
	TTL        int    `json:"ttl"`
	State      bool   `json:"state"`
	Content    string `json:"content,omitempty"`

	// A
	IPv4Address string `json:"ipv4Address,omitempty"`
	// AAAA
	IPv6Address string `json:"ipv6Address,omitempty"`
	// CNAME / DNAME / MX / NS / PTR / SRV / NAPTR (replacement)
	Host string `json:"host,omitempty"`
	// MX / SRV / URI / NAPTR (order) / CERT
	Priority *int `json:"priority,omitempty"`
	// SRV / KEY / SSHFP (fingerprint type) / NAPTR (flags via Weight field in DB, but exposed as naptrFlags)
	Weight *int `json:"weight,omitempty"`
	// SRV / TLSA (matching type) / KEY
	Port *int `json:"port,omitempty"`
	// CAA / KEY
	Flags *int `json:"flags,omitempty"`
	// CAA
	Tag   string `json:"tag,omitempty"`
	Value string `json:"value,omitempty"`
	// TXT / SPF
	TextData string `json:"textData,omitempty"`
	// SSHFP
	Algorithm       *int   `json:"algorithm,omitempty"`
	FingerPrintType *int   `json:"fingerPrintType,omitempty"`
	FingerPrint     string `json:"fingerPrint,omitempty"`
	// TLSA / SMIMEA
	CertificateUsage          *int   `json:"certificateUsage,omitempty"`
	Selector                  *int   `json:"selector,omitempty"`
	MatchingType              *int   `json:"matchingType,omitempty"`
	CertificateAssociatedData string `json:"certificateAssociatedData,omitempty"`
	// NAPTR
	Order       *int   `json:"order,omitempty"`
	Preference  *int   `json:"preference,omitempty"`
	NaptrFlags  string `json:"naptrFlags,omitempty"`
	Services    string `json:"services,omitempty"`
	RegExp      string `json:"regExp,omitempty"`
	Replacement string `json:"replacement,omitempty"`
}

type recordsResponse struct {
	apiResponse
	DNSRecords []dynuRecord `json:"dnsRecords"`
}

func (d *dynuProvider) do(method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewBuffer(data)
	}

	req, err := http.NewRequest(method, apiBase+path, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("API-Key", d.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		var apiErr apiResponse
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Message != "" {
			return nil, fmt.Errorf("Dynu API error %d: %s", resp.StatusCode, apiErr.Message)
		}
		return nil, fmt.Errorf("Dynu API HTTP %d for %s %s", resp.StatusCode, method, path)
	}

	return respBody, nil
}

func (d *dynuProvider) getDomains() ([]dynuDomain, error) {
	data, err := d.do("GET", "/dns", nil)
	if err != nil {
		return nil, err
	}
	var resp domainsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return resp.Domains, nil
}

func (d *dynuProvider) getDomainID(domain string) (int64, error) {
	if id, ok := d.domainIDs[domain]; ok {
		return id, nil
	}
	domains, err := d.getDomains()
	if err != nil {
		return 0, err
	}
	for _, dom := range domains {
		d.domainIDs[dom.Name] = dom.ID
	}
	if id, ok := d.domainIDs[domain]; ok {
		return id, nil
	}
	return 0, fmt.Errorf("domain %q not found in Dynu account", domain)
}

func (d *dynuProvider) getRecords(domainID int64) ([]*dynuRecord, error) {
	data, err := d.do("GET", fmt.Sprintf("/dns/%d/record", domainID), nil)
	if err != nil {
		return nil, err
	}
	var resp recordsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	records := make([]*dynuRecord, len(resp.DNSRecords))
	for i := range resp.DNSRecords {
		records[i] = &resp.DNSRecords[i]
	}
	return records, nil
}

func (d *dynuProvider) createRecord(domainID int64, req *dynuRecord) error {
	_, err := d.do("POST", fmt.Sprintf("/dns/%d/record", domainID), req)
	return err
}

func (d *dynuProvider) updateRecord(domainID, recordID int64, req *dynuRecord) error {
	_, err := d.do("POST", fmt.Sprintf("/dns/%d/record/%d", domainID, recordID), req)
	return err
}

func (d *dynuProvider) deleteRecord(domainID, recordID int64) error {
	_, err := d.do("DELETE", fmt.Sprintf("/dns/%d/record/%d", domainID, recordID), nil)
	return err
}
