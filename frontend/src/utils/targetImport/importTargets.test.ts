import { describe, expect, it } from 'vitest'
import { importTargets, MAX_TARGETS_PER_SCAN, type ImportResult, type SkipReason } from './index'

const b64 = (value: unknown) => btoa(JSON.stringify(value))

/** Values skipped for a given reason. */
const skippedOf = (result: ImportResult, reason: SkipReason) =>
  result.skipped.filter(entry => entry.reason === reason).map(entry => entry.value)

/** Minimal Acunetix-style HTML: parseData() marker plus base64 JSON lines. */
function acunetixHtml(lines: string[]): string {
  return [
    '<!DOCTYPE html><html><head><title>Comprehensive Report</title></head><body>',
    '<script type="text/javascript">function parseData(data) { /* ... */ }</script>',
    '<script id="reportData" type="application/octet-stream">',
    ...lines,
    '</script></body></html>',
  ].join('\n')
}

describe('Acunetix HTML', () => {
  it('extracts hosts from target info blocks only', () => {
    const html = acunetixHtml([
      b64({ host: 'app.example.com', start_url: 'https://app.example.com/', source_type: 'scans', start_date: '2026-10-01' }),
      b64({ vt_id: 'x', app_id: 'db/vuln.yaml', name: 'XSS', severity: 3 }),
      b64({ loc_id: 2, path: '/', name: 'https://app.example.com/' }),
      b64({ loc_url: 'https://app.example.com/', vt_id: 'x', app_id: 'a', vuln_hash: 'h' }),
      'H4sIAAAAAAAAA+0Za2/bOPK7gfwHrhcF4kK0JdmyFTkptpttt93rC9fs4fZuDwdKomxtJFGg6Fd8',
      'eyJub3QtdmFsaWQtYmFzZTY0!!!',
      '',
      b64({ host: 'api.example.com', start_url: 'https://api.example.com/v1/', source_type: 'scans' }),
      b64({ host: 'app.example.com', start_url: 'https://app.example.com/', source_type: 'scans' }),
    ])

    const result = importTargets(html, 'report.html')
    expect(result.format.id).toBe('acunetix-html')
    expect(result.isGeneric).toBe(false)
    expect(result.hosts).toEqual(['app.example.com', 'api.example.com'])
    expect(result.skipped).toEqual([{ reason: 'duplicate', value: 'app.example.com', detail: '×2' }])
  })

  it('falls back to start_url when host is empty', () => {
    const html = acunetixHtml([b64({ host: '', start_url: 'https://fallback.example.com/path' })])
    expect(importTargets(html).hosts).toEqual(['fallback.example.com'])
  })
})

describe('Burp Suite XML', () => {
  it('reads issue hosts (URL form)', () => {
    const xml = `<?xml version="1.0"?>
<!DOCTYPE issues [<!ELEMENT issues (issue*)>]>
<issues burpVersion="2024.1" exportTime="Mon Oct 27 2026">
  <issue>
    <serialNumber>1</serialNumber>
    <type>5245344</type>
    <name>Cross-site scripting</name>
    <host ip="203.0.113.10">https://shop.example.com</host>
    <path><![CDATA[/search]]></path>
    <references><![CDATA[<a href="https://portswigger.net/web-security/cross-site-scripting">XSS</a>]]></references>
  </issue>
  <issue>
    <host ip="203.0.113.11">http://admin.example.com:8080</host>
  </issue>
  <issue>
    <host ip="203.0.113.10">https://shop.example.com</host>
  </issue>
</issues>`
    const result = importTargets(xml, 'burp.xml')
    expect(result.format.id).toBe('burp-xml')
    expect(result.hosts).toEqual(['shop.example.com', 'admin.example.com'])
    expect(skippedOf(result, 'duplicate')).toEqual(['shop.example.com'])
  })

  it('reads proxy history items', () => {
    const xml = `<?xml version="1.0"?>
<items burpVersion="2024.1" exportTime="Mon Oct 27 2026">
  <item>
    <url><![CDATA[https://api.example.com/login]]></url>
    <host ip="203.0.113.20">api.example.com</host>
    <port>443</port>
  </item>
  <item>
    <url><![CDATA[https://cdn.example.com/a.js]]></url>
  </item>
</items>`
    const result = importTargets(xml)
    expect(result.format.id).toBe('burp-xml')
    expect(result.hosts).toEqual(['api.example.com', 'cdn.example.com'])
  })
})

describe('Nessus', () => {
  it('prefers host-fqdn, then ReportHost name', () => {
    const xml = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy><policyName>Basic</policyName></Policy>
  <Report name="Scan">
    <ReportHost name="198.51.100.5">
      <HostProperties>
        <tag name="host-ip">198.51.100.5</tag>
        <tag name="host-fqdn">web.example.com</tag>
      </HostProperties>
      <ReportItem port="443" pluginName="SSL"><see_also>https://www.tenable.com/plugins</see_also></ReportItem>
    </ReportHost>
    <ReportHost name="198.51.100.6">
      <HostProperties><tag name="host-ip">198.51.100.6</tag></HostProperties>
    </ReportHost>
    <ReportHost name="mail.example.com">
      <HostProperties></HostProperties>
    </ReportHost>
  </Report>
</NessusClientData_v2>`
    const result = importTargets(xml, 'scan.nessus')
    expect(result.format.id).toBe('nessus')
    expect(result.hosts).toEqual(['web.example.com', '198.51.100.6', 'mail.example.com'])
  })
})

describe('Nmap XML', () => {
  it('uses hostnames, falls back to IPv4 and skips down hosts', () => {
    const xml = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - example.com" version="7.94">
  <host>
    <status state="up"/>
    <address addr="203.0.113.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="ptr.isp.example.net" type="PTR"/>
      <hostname name="example.com" type="user"/>
    </hostnames>
  </host>
  <host>
    <status state="up"/>
    <address addr="203.0.113.2" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <hostnames/>
  </host>
  <host>
    <status state="down"/>
    <address addr="203.0.113.3" addrtype="ipv4"/>
  </host>
</nmaprun>`
    const result = importTargets(xml, 'nmap.xml')
    expect(result.format.id).toBe('nmap-xml')
    expect(result.hosts).toEqual(['example.com', '203.0.113.2'])
  })
})

describe('OWASP ZAP', () => {
  it('reads XML site hosts', () => {
    const xml = `<?xml version="1.0"?>
<OWASPZAPReport programName="ZAP" version="2.15.0">
  <site name="https://app.example.com" host="app.example.com" port="443" ssl="true">
    <alerts><alertitem><reference>https://owasp.org/www-project-top-ten/</reference></alertitem></alerts>
  </site>
  <site name="http://legacy.example.com" host="legacy.example.com" port="80" ssl="false"/>
</OWASPZAPReport>`
    const result = importTargets(xml, 'zap.xml')
    expect(result.format.id).toBe('zap')
    expect(result.hosts).toEqual(['app.example.com', 'legacy.example.com'])
  })

  it('reads JSON site hosts', () => {
    const json = JSON.stringify({
      '@programName': 'ZAP',
      '@version': '2.15.0',
      site: [
        { '@name': 'https://app.example.com', '@host': 'app.example.com', alerts: [] },
        { '@name': 'https://other.example.com', alerts: [] },
      ],
    })
    const result = importTargets(json, 'zap.json')
    expect(result.format.id).toBe('zap')
    expect(result.hosts).toEqual(['app.example.com', 'other.example.com'])
  })
})

describe('generic fallback', () => {
  it('reads a plain text list', () => {
    const result = importTargets('example.com\nhttps://api.example.com/v1\n# comment\n10.1.2.3\n\nexample.com\n', 'list.txt')
    expect(result.isGeneric).toBe(true)
    expect(result.format.id).toBe('generic')
    expect(result.hosts).toEqual(['example.com', 'api.example.com', '10.1.2.3'])
    expect(skippedOf(result, 'duplicate')).toEqual(['example.com'])
  })

  it('reads a Nessus-style CSV export', () => {
    const csv = [
      'Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,See Also',
      '10107,,,None,web.example.com,tcp,443,HTTP Server Type,https://www.tenable.com/plugins/nessus/10107',
      '57582,,6.4,Medium,198.51.100.7,tcp,443,SSL Self-Signed,"https://cwe.mitre.org/data/definitions/295.html"',
    ].join('\n')
    const result = importTargets(csv, 'export.csv')
    expect(result.isGeneric).toBe(true)
    expect(result.hosts).toEqual(['web.example.com', '198.51.100.7'])
    expect(skippedOf(result, 'reference')).toEqual(['www.tenable.com', 'cwe.mitre.org'])
  })

  it('walks arbitrary JSON using known keys', () => {
    const json = JSON.stringify({
      scan: { targets: ['one.example.com', 'https://two.example.com/'] },
      findings: [{ host: 'three.example.com', description: 'see https://owasp.org/' }, { url: 'https://nvd.nist.gov/vuln' }],
    })
    const result = importTargets(json, 'custom.json')
    expect(result.hosts).toEqual(['one.example.com', 'two.example.com', 'three.example.com'])
    expect(skippedOf(result, 'reference')).toEqual(['nvd.nist.gov'])
  })

  it('pulls URLs from unknown HTML while ignoring scripts, assets and references', () => {
    const html = `<html><head>
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">
<script>window.location.href = 'x'; console.log(document.title); var s = "evil.example.org";</script>
<style>.a { background: url(img/logo.png) }</style>
</head><body>
<h1>Findings for portal.example.com</h1>
<p>Target: <a href="https://portal.example.com/login">https://portal.example.com/login</a></p>
<p>Asset: https://portal.example.com/static/app.js and main.css</p>
<p>Ref: <a href="https://cheatsheetseries.owasp.org/">OWASP</a>, <a href="https://www.w3.org/TR/">W3C</a></p>
<p>Also scanned: 203.0.113.50 and backup.example.co.id</p>
</body></html>`
    const result = importTargets(html, 'other-scanner.html')
    expect(result.isGeneric).toBe(true)
    expect(result.hosts).toEqual(['portal.example.com', '203.0.113.50', 'backup.example.co.id'])
    expect(result.hosts).not.toContain('evil.example.org')
    expect(skippedOf(result, 'reference')).toEqual(['fonts.googleapis.com', 'cheatsheetseries.owasp.org', 'www.w3.org'])
    expect(result.hosts).not.toContain('main.css')
  })

  it('does not treat code identifiers or file names as hosts', () => {
    const text = 'console.log(window.location); import x from "lodash.debounce"; file report.pdf app.min.js data.json'
    expect(importTargets(text).hosts).toEqual([])
  })

  it('handles an unrecognized XML file', () => {
    const xml = '<?xml version="1.0"?><report><target>https://legacy.example.com</target><target>intranet.example.com</target></report>'
    const result = importTargets(xml, 'unknown.xml')
    expect(result.isGeneric).toBe(true)
    expect(result.hosts).toEqual(['legacy.example.com', 'intranet.example.com'])
  })
})

describe('edge cases', () => {
  it('returns no hosts for empty input', () => {
    const result = importTargets('', 'empty.txt')
    expect(result.hosts).toEqual([])
    expect(result.exceedsLimit).toBe(false)
  })

  it('returns no hosts for a file with no targets', () => {
    expect(importTargets('Hello world. Nothing to see here!').hosts).toEqual([])
  })

  it('falls back to generic when a dedicated parser finds nothing', () => {
    // Looks like Acunetix but contains no target blocks
    const html = acunetixHtml([b64({ vt_id: 'x', app_id: 'a', severity: 1 })]).replace(
      '</body>',
      '<p>Scanned https://fallback.example.com</p></body>',
    )
    const result = importTargets(html)
    expect(result.isGeneric).toBe(true)
    expect(result.hosts).toEqual(['fallback.example.com'])
  })

  it('falls back to generic on malformed XML', () => {
    const result = importTargets('<NessusClientData_v2><ReportHost name="x.example.com">', 'broken.nessus')
    expect(result.isGeneric).toBe(true)
    expect(result.hosts).toEqual(['x.example.com'])
  })

  it('flags lists above the backend limit', () => {
    const list = Array.from({ length: MAX_TARGETS_PER_SCAN + 1 }, (_, i) => `host${i}.example.com`).join('\n')
    const result = importTargets(list)
    expect(result.hosts).toHaveLength(MAX_TARGETS_PER_SCAN + 1)
    expect(result.exceedsLimit).toBe(true)
  })

  it('does not flag lists at the backend limit', () => {
    const list = Array.from({ length: MAX_TARGETS_PER_SCAN }, (_, i) => `host${i}.example.com`).join('\n')
    expect(importTargets(list).exceedsLimit).toBe(false)
  })
})
