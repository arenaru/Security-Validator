import type { ParserOutput, TargetParser } from '../types'
import { childrenByTag, parseXml } from '../xml'

/**
 * Tenable Nessus `.nessus` (v2) export:
 * `<NessusClientData_v2><Report><ReportHost name="..."><HostProperties><tag name="host-fqdn">`
 *
 * Prefers `host-fqdn`, then `host-rdns`, then the `ReportHost` name (often an IP).
 */
export const nessusParser: TargetParser = {
  id: 'nessus',
  label: 'Nessus',

  canParse(text) {
    return text.slice(0, 8192).includes('<NessusClientData_v2')
  },

  parse(text): ParserOutput {
    const doc = parseXml(text)
    if (!doc) throw new Error('Invalid Nessus XML')

    const targets: string[] = []
    for (const reportHost of Array.from(doc.getElementsByTagName('ReportHost'))) {
      const props: Record<string, string> = {}
      for (const hostProps of childrenByTag(reportHost, 'HostProperties')) {
        for (const tag of childrenByTag(hostProps, 'tag')) {
          const name = tag.getAttribute('name')
          if (name) props[name] = tag.textContent?.trim() ?? ''
        }
      }

      const host = props['host-fqdn'] || props['host-rdns'] || reportHost.getAttribute('name') || props['host-ip']
      if (host) targets.push(host)
    }

    return { targets }
  },
}
