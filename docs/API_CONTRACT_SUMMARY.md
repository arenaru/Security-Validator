# API Contract Summary

This file summarizes the contract in docs/openapi.yaml for quick implementation alignment.

## Base URL
- Local: http://localhost:8000

## Endpoints
- GET /api/health
- POST /api/scans
- GET /api/scans/{scanId}
- GET /api/scans/{scanId}/summary
- GET /api/scans/{scanId}/report.xlsx

## Core Request
POST /api/scans

```json
{
  "targets": ["example.com", "https://target.tld"],
  "modules": [
    "SSL Certificate Check",
    "Security Headers Check"
  ],
  "options": {
    "timeoutSeconds": 30,
    "parallelism": 6
  }
}
```

## Core Status Enum
- pending
- running
- done
- failed
- partial

## Core Result Status Enum
- secure
- warning
- insecure
- error
- info

## Module Names (Canonical)
- SSL Certificate Check
- SSL Certificate Hostname Mismatch
- SSLv3 Detection
- TLS 1.0 Detection
- TLS 1.1 Detection
- Response Code Check
- HSTS Security Check
- Security Headers Check
- Cookie Secure Flag
- Cookie HttpOnly Flag
- Laravel Debug Mode
- Node.js Debug Mode
- PHP Version Disclosure

## Error Envelope
```json
{
  "error": {
    "code": "SCAN_NOT_FOUND",
    "message": "scanId not found",
    "traceId": "b4ee3eac4a"
  }
}
```

## Notes for Frontend
- Build against this contract first (mock or MSW).
- Treat results as grouped by module with normalized item entries.
- Report download endpoint returns XLSX binary.

## Source of Truth
- docs/openapi.yaml
