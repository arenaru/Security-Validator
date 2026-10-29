import type { ParserOutput, TargetParser } from '../types'

/**
 * Acunetix / Invicti "Comprehensive" HTML report.
 *
 * The report embeds its data as one base64 string per line inside a <script>
 * block. Lines starting with `eyJ` decode to JSON objects (base64 of `{"`);
 * lines starting with `H4sI` are gzipped HTTP responses and are ignored.
 * A target/scan info object is any object with both `host` and `start_url`,
 * mirroring the report's own `parseData()` logic.
 */

function decodeBase64Json(line: string): unknown {
  try {
    const binary = atob(line)
    const bytes = Uint8Array.from(binary, ch => ch.charCodeAt(0))
    return JSON.parse(new TextDecoder('utf-8').decode(bytes))
  } catch {
    return undefined
  }
}

export const acunetixHtmlParser: TargetParser = {
  id: 'acunetix-html',
  label: 'Acunetix HTML',

  canParse(text) {
    return /<html/i.test(text.slice(0, 4096)) && text.includes('function parseData(') && /^\s*eyJ/m.test(text)
  },

  parse(text): ParserOutput {
    const targets: string[] = []

    for (const rawLine of text.split('\n')) {
      const line = rawLine.trim()
      if (!line.startsWith('eyJ')) continue

      const obj = decodeBase64Json(line)
      if (!obj || typeof obj !== 'object' || Array.isArray(obj)) continue

      const record = obj as Record<string, unknown>
      if (!('host' in record) || !('start_url' in record)) continue

      const host = typeof record.host === 'string' ? record.host : ''
      const startUrl = typeof record.start_url === 'string' ? record.start_url : ''
      if (host || startUrl) targets.push(host || startUrl)
    }

    return { targets }
  },
}
