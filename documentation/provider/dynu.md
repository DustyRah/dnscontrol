## Configuration

To use this provider, add an entry to `creds.json` with `TYPE` set to `DYNU`
along with your Dynu API key. You can generate an API key from the
[Dynu Control Panel](https://www.dynu.com/en-US/ControlPanel) under **API Credentials**.

Example:

{% code title="creds.json" %}
```json
{
  "dynu": {
    "TYPE": "DYNU",
    "api_key": "your-dynu-api-key"
  }
}
```
{% endcode %}

## Metadata

This provider does not recognize any special metadata fields unique to Dynu.

## Usage

An example configuration:

{% code title="dnsconfig.js" %}
```javascript
var REG_NONE = NewRegistrar("none");
var DSP_DYNU = NewDnsProvider("dynu");

D("example.com", REG_NONE, DnsProvider(DSP_DYNU),
    A("test", "1.2.3.4"),
    MX("@", 10, "mail.example.com."),
    TXT("@", "v=spf1 include:example.com ~all"),
);
```
{% endcode %}

## Activation

1. Log in to the [Dynu Control Panel](https://www.dynu.com/en-US/ControlPanel).
2. Navigate to **API Credentials**.
3. Generate a new API key.
4. Add the key to `creds.json` as shown above.

## Supported record types

| Type  | Notes |
| ----- | ----- |
| A     | |
| AAAA  | |
| CAA   | |
| CNAME | |
| DNAME | |
| MX    | Null MX (priority 0, target `.`) is supported at creation; updating an existing record back to null MX uses a delete-and-recreate internally |
| NAPTR | |
| NS    | Subdomain delegation only; see Caveats |
| PTR   | |
| SRV   | Null target (`.`) is not supported |
| SSHFP | |
| TLSA  | |
| TXT   | Empty TXT records are not supported |

## Caveats

### Apex NS records

Dynu manages its own authoritative nameservers (`ns1.dynu.com` through `ns6.dynu.com`) and does not permit creating, modifying, or deleting apex NS records via the API. DNSControl will not attempt to manage them. Subdomain NS delegations are fully supported.

### NS record TTL

Dynu forces all NS records to a TTL of 3600, regardless of the value specified in `dnsconfig.js`. TTL-only changes to NS records are silently ignored to maintain idempotency.

### Wildcard records

Dynu does not support wildcard DNS records (e.g. `*.example.com`) via the API. DNSControl will reject them at audit time.

### SOA records

Dynu manages SOA records internally. They are not returned by the API and cannot be modified via DNSControl.

### Empty TXT records

Dynu rejects TXT records with an empty string value. DNSControl will reject them at audit time.

### Null SRV targets

SRV records with a null target (`.`) are rejected by the Dynu API. DNSControl will reject them at audit time.
