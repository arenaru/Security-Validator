import type { ParserOutput, TargetParser } from '../types'

/**
 * Burp Suite XML exports:
 * - Scanner issues report: `<issues burpVersion="..."><issue><host ip="...">https://example.com</host>`
 * - Proxy/HTTP history items: `<items burpVersion="..."><item><host ip="...">example.com</host>`
 *
 * Burp wraps most values in CDATA and embeds a DTD, which some XML parsers
 * handle inconsistently, so this parser reads the elements with targeted
 * regexes instead of a DOM.
 */

const BLOCK_RE = /<(issue|item)\b[^>]*>([\s\S]*?)<\/\1>/g
const HOST_RE = /<host\b[^>]*>([\s\S]*?)<\/host>/
const URL_RE = /<url\b[^>]*>([\s\S]*?)<\/url>/

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }

/** Unwrap CDATA and decode the basic XML entities. */
function elementText(raw: string): string {
  const cdata = raw.match(/^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/)
  const value = cdata ? cdata[1] : raw.replace(/&(amp|lt|gt|quot|apos);/g, (_, name: string) => ENTITIES[name])
  return value.trim()
}

export const burpXmlParser: TargetParser = {
  id: 'burp-xml',
  label: 'Burp Suite XML',

  canParse(text) {
    return /<(issues|items)\s[^>]*burpVersion=/.test(text.slice(0, 8192))
  },

  parse(text): ParserOutput {
    const targets: string[] = []

    for (const block of text.matchAll(BLOCK_RE)) {
      const body = block[2]
      const host = elementText(body.match(HOST_RE)?.[1] ?? '')
      if (host) {
        targets.push(host)
        continue
      }
      // Fallback: Burp items always carry a <url>
      const url = elementText(body.match(URL_RE)?.[1] ?? '')
      if (url) targets.push(url)
    }

    return { targets }
  },
}
