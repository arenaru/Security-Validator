import type { ParserOutput, TargetParser } from '../types'
import { childrenByTag, parseXml } from '../xml'

/**
 * Nmap XML output (`nmap -oX`):
 * `<nmaprun><host><status state="up"/><address addr="..." addrtype="ipv4"/><hostnames><hostname name="..." type="user"/>`
 *
 * Hosts reported as down are skipped. Prefers the user-supplied hostname,
 * then any hostname (PTR), then the IPv4 address.
 */
export const nmapXmlParser: TargetParser = {
  id: 'nmap-xml',
  label: 'Nmap XML',

  canParse(text) {
    return text.slice(0, 8192).includes('<nmaprun')
  },

  parse(text): ParserOutput {
    const doc = parseXml(text)
    if (!doc) throw new Error('Invalid Nmap XML')

    const targets: string[] = []
    for (const host of Array.from(doc.getElementsByTagName('host'))) {
      const status = childrenByTag(host, 'status')[0]
      if (status && status.getAttribute('state') !== 'up') continue

      const hostnames = childrenByTag(host, 'hostnames').flatMap(el => childrenByTag(el, 'hostname'))
      const userHostname = hostnames.find(h => h.getAttribute('type') === 'user')
      const name = (userHostname ?? hostnames[0])?.getAttribute('name')
      if (name) {
        targets.push(name)
        continue
      }

      const ipv4 = childrenByTag(host, 'address').find(a => a.getAttribute('addrtype') === 'ipv4')
      const addr = ipv4?.getAttribute('addr')
      if (addr) targets.push(addr)
    }

    return { targets }
  },
}
