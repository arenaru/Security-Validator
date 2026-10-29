import type { ParserOutput, SkippedEntry, TargetParser } from '../types'
import { normalizeHost } from '../normalize'

/**
 * Fallback for any file no dedicated parser recognizes (TXT, CSV, unknown
 * HTML/XML, arbitrary JSON...). Best effort, so results must be reviewed.
 *
 * - JSON: collect string values under well-known keys (host, url, target...).
 * - Otherwise (or when JSON yields nothing): regex extraction of URLs,
 *   hostnames and IPv4 addresses.
 *
 * Noise reduction:
 * - Hosts whose last label is a file extension (`app.js`, `style.css`) are dropped.
 * - Bare hostnames (without a URL scheme) must end in a ccTLD or a common gTLD,
 *   so code like `console.log` or `window.location` is not picked up.
 * - Reference / vendor sites that appear in vulnerability write-ups are dropped.
 * Dropped values are returned in `skipped` so the UI can list them.
 */

/** Reference, advisory, vendor and CDN hosts commonly embedded in reports. Matches the domain and its subdomains. */
export const REFERENCE_BLOCKLIST: readonly string[] = [
  // Standards and vulnerability databases
  'w3.org', 'owasp.org', 'mitre.org', 'cve.org', 'nist.gov', 'first.org', 'cisa.gov',
  'cvedetails.com', 'exploit-db.com', 'securityfocus.com', 'rfc-editor.org', 'ietf.org',
  'wikipedia.org', 'schema.org', 'xmlsoap.org', 'openxmlformats.org', 'purl.org',
  // Scanner vendors
  'portswigger.net', 'tenable.com', 'nessus.org', 'acunetix.com', 'invicti.com',
  'netsparker.com', 'rapid7.com', 'zaproxy.org', 'nmap.org', 'insecure.org', 'qualys.com',
  // Documentation sites
  'developer.mozilla.org', 'learn.microsoft.com', 'docs.microsoft.com', 'support.microsoft.com',
  'msrc.microsoft.com', 'cheatsheetseries.owasp.org',
  // Public CDNs / font hosts referenced by report templates
  'fonts.googleapis.com', 'fonts.gstatic.com', 'cdnjs.cloudflare.com', 'cdn.jsdelivr.net',
  'unpkg.com', 'code.jquery.com',
]

/** Last labels that indicate a file name rather than a host. */
const FILE_EXTENSIONS = new Set([
  'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'css', 'scss', 'less', 'map', 'vue',
  'html', 'htm', 'xhtml', 'php', 'asp', 'aspx', 'jsp', 'cgi', 'do', 'action',
  'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'webp', 'bmp',
  'woff', 'woff2', 'ttf', 'eot', 'otf',
  'json', 'xml', 'yaml', 'yml', 'txt', 'csv', 'log', 'ini', 'conf', 'cfg', 'bak',
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'exe', 'dll', 'jar', 'war', 'class', 'java',
])

/** Common generic TLDs accepted for bare hostnames (all 2-letter ccTLDs are accepted too). */
const COMMON_GTLDS = new Set([
  'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'name', 'pro', 'mobi', 'asia',
  'app', 'dev', 'cloud', 'online', 'site', 'website', 'web', 'xyz', 'tech', 'store', 'shop',
  'live', 'digital', 'network', 'systems', 'solutions', 'services', 'group', 'company', 'world',
  'space', 'blog', 'news', 'media', 'agency', 'email', 'page', 'link', 'host', 'zone', 'life',
  'today', 'global', 'center', 'club', 'inc', 'ltd', 'llc', 'travel', 'bank', 'insurance',
  'finance', 'money', 'fun', 'one', 'top', 'icu', 'vip', 'work', 'studio', 'design', 'software',
  'local', 'internal', 'corp', 'lan', 'test',
])

/** Keys whose string values are treated as targets when walking JSON. */
const JSON_TARGET_KEYS = new Set([
  'host', 'hostname', 'host_name', 'fqdn', 'domain', 'url', 'start_url', 'target', 'targets',
  'address', 'ip', 'ip_address', 'ipaddress', 'site', 'endpoint', 'uri',
])

const URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s"'<>()[\]{}\\,;]+/gi
const BARE_HOST_RE =
  /(?<![\w@.\-/])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?::\d{1,5})?(?![\w-]|\.[a-z0-9])/gi
const IPV4_RE = /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)/g

export function isBlockedReference(host: string): boolean {
  return REFERENCE_BLOCKLIST.some(domain => host === domain || host.endsWith(`.${domain}`))
}

function lastLabel(host: string): string {
  return host.slice(host.lastIndexOf('.') + 1)
}

function looksLikeFileName(host: string): boolean {
  return FILE_EXTENSIONS.has(lastLabel(host))
}

function hasPlausibleTld(host: string): boolean {
  const tld = lastLabel(host)
  return tld.length === 2 || COMMON_GTLDS.has(tld) || tld.startsWith('xn--')
}

function collectJsonTargets(value: unknown, out: string[], key = ''): void {
  if (typeof value === 'string') {
    if (JSON_TARGET_KEYS.has(key.toLowerCase().replace(/^@/, ''))) out.push(value)
    return
  }
  if (Array.isArray(value)) {
    for (const item of value) collectJsonTargets(item, out, key)
    return
  }
  if (value && typeof value === 'object') {
    for (const [childKey, child] of Object.entries(value)) collectJsonTargets(child, out, childKey)
  }
}

function tryParseJson(text: string): unknown {
  const trimmed = text.trimStart()
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return undefined
  try {
    return JSON.parse(trimmed)
  } catch {
    return undefined
  }
}

/** Replace a match with spaces of the same length so string offsets stay aligned. */
const blank = (match: string) => ' '.repeat(match.length)

/**
 * Blank out <script>/<style> bodies so bare-host matching only sees visible
 * text and attributes (avoids `window.location`, `evil.example.org` in code).
 */
function blankMarkupCode(text: string): string {
  return text.replace(/<script\b[\s\S]*?<\/script>/gi, blank).replace(/<style\b[\s\S]*?<\/style>/gi, blank)
}

/** Extract URLs, bare hostnames and IPv4 addresses in order of appearance. */
function extractWithRegex(text: string): string[] {
  const found: Array<{ index: number; value: string }> = []

  // URLs are matched on the full text: a scheme makes them unambiguous
  for (const match of text.matchAll(URL_RE)) found.push({ index: match.index ?? 0, value: match[0] })

  const visible = /<[a-z!?/]/i.test(text) ? blankMarkupCode(text) : text
  const withoutUrls = visible.replace(URL_RE, blank)
  for (const match of withoutUrls.matchAll(BARE_HOST_RE)) {
    if (hasPlausibleTld(match[1].toLowerCase())) found.push({ index: match.index ?? 0, value: match[0] })
  }
  for (const match of withoutUrls.matchAll(IPV4_RE)) found.push({ index: match.index ?? 0, value: match[0] })

  return found.sort((a, b) => a.index - b.index).map(item => item.value)
}

/** Drop file-like names and reference sites, recording what was removed. */
export function filterNoise(rawTargets: string[]): ParserOutput {
  const targets: string[] = []
  const skipped: SkippedEntry[] = []

  for (const raw of rawTargets) {
    const host = normalizeHost(raw)
    if (!host || looksLikeFileName(host)) skipped.push({ reason: 'invalid', value: host ?? raw.trim() })
    else if (isBlockedReference(host)) skipped.push({ reason: 'reference', value: host })
    else targets.push(raw)
  }

  return { targets, skipped }
}

export const genericParser: TargetParser = {
  id: 'generic',
  label: 'Deteksi Umum',

  canParse() {
    return true
  },

  parse(text): ParserOutput {
    const json = tryParseJson(text)
    if (json !== undefined) {
      const fromJson: string[] = []
      collectJsonTargets(json, fromJson)
      const result = filterNoise(fromJson)
      if (result.targets.length > 0) return result
    }
    return filterNoise(extractWithRegex(text))
  },
}
