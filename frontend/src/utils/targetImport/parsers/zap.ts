import type { ParserOutput, TargetParser } from '../types'
import { parseXml } from '../xml'

/**
 * OWASP ZAP traditional reports:
 * - XML:  `<OWASPZAPReport programName="ZAP"><site name="https://example.com" host="example.com" ...>`
 * - JSON: `{"@programName": "ZAP", "site": [{"@name": "...", "@host": "..."}]}`
 */

function isZapJson(head: string): boolean {
  return /"@programName"\s*:\s*"(OWASP )?ZAP"/.test(head)
}

export const zapParser: TargetParser = {
  id: 'zap',
  label: 'OWASP ZAP',

  canParse(text) {
    const head = text.slice(0, 8192)
    return head.includes('<OWASPZAPReport') || isZapJson(head)
  },

  parse(text): ParserOutput {
    const targets: string[] = []

    if (isZapJson(text.slice(0, 8192))) {
      const data = JSON.parse(text) as { site?: unknown }
      const sites = Array.isArray(data.site) ? data.site : data.site ? [data.site] : []
      for (const site of sites) {
        if (!site || typeof site !== 'object') continue
        const record = site as Record<string, unknown>
        const value = record['@host'] ?? record['@name']
        if (typeof value === 'string' && value) targets.push(value)
      }
      return { targets }
    }

    const doc = parseXml(text)
    if (!doc) throw new Error('Invalid ZAP XML')
    for (const site of Array.from(doc.getElementsByTagName('site'))) {
      const value = site.getAttribute('host') || site.getAttribute('name')
      if (value) targets.push(value)
    }
    return { targets }
  },
}
