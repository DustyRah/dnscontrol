# Dynu DNS Provider

## Description

Manages DNS zones and records via the [Dynu REST API v2](https://www.dynu.com/en-US/Resources/API).

## Credentials

| Key       | Description                         |
|-----------|-------------------------------------|
| `api_key` | API key from the Dynu control panel |

Generate an API key at **Control Panel → API Credentials**.

Example `creds.json`:

```json
{
  "dynu": {
    "TYPE": "DYNU",
    "api_key": "YOUR_API_KEY_HERE"
  }
}
```

## Usage

Example `dnsconfig.js`:

```js
var REG_NONE = NewRegistrar("none");
var DNS_DYNU = NewDnsProvider("dynu");

D("example.com", REG_NONE, DnsProvider(DNS_DYNU),
  A("@", "1.2.3.4"),
  MX("@", 10, "mail.example.com."),
  TXT("@", "v=spf1 include:example.com ~all"),
  CNAME("www", "example.com."),
  END
);
```

## Supported Record Types

| Type    | Notes                      |
|---------|----------------------------|
| A       |                            |
| AAAA    |                            |
| CAA     |                            |
| CNAME   |                            |
| DNAME   |                            |
| MX      |                            |
| NAPTR   |                            |
| NS      |                            |
| PTR     |                            |
| SRV     |                            |
| SSHFP   |                            |
| TLSA    |                            |
| TXT     | SPF records are normalised to TXT |

## Integration Testing

Add to `integrationTest/profiles.json`:

```json
{
  "DYNU": {
    "TYPE": "DYNU",
    "api_key": "$DYNU_API_KEY",
    "domain": "$DYNU_DOMAIN"
  }
}
```

Run tests:

```sh
cd integrationTest
export DYNU_API_KEY='YOUR_API_KEY'
export DYNU_DOMAIN='your-test-domain.com'
go test -v -args -verbose -profile DYNU
```

## Registration in `_all/all.go`

Add the following import to `pkg/providers/_all/all.go`:

```go
_ "github.com/DNSControl/dnscontrol/v4/providers/dynu"  // import path of the dynu package itself stays under providers/
```

## Notes

- SOA records are managed by Dynu internally and are not synced.
- HTTPS / SVCB record types are not yet implemented; the provider rejects them at audit time.
- The Dynu API uses base64 encoding for SSHFP fingerprints and TLSA certificate-associated-data; the provider converts to/from the hex encoding that DNSControl uses internally.
