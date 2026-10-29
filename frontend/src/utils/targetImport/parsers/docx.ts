import { unzipSync } from 'fflate'
import type { ParserOutput, SkippedEntry } from '../types'
import { filterNoise, genericParser } from './generic'

/**
 * Word `.docx` reports (e.g. manually written VA reports).
 *
 * Tables first: any table whose header row has a URL/Domain/Host/Target/Asset
 * (or IP) column contributes that column's values. Rows are skipped when:
 * - the first cell spans several columns (group/apex label like "S-gift.app"),
 * - the row's Status column is clearly negative ("not exist", "inactive"...).
 * When no table yields targets, the whole document text goes through the
 * generic parser.
 */

const HOST_HEADER_RE = /\b(url|domain|host|hostname|target|asset|fqdn|endpoint)s?\b/i
const IP_HEADER_RE = /^\s*ip(\s*address)?\s*$/i
const STATUS_HEADER_RE = /\b(status|state|availability)\b/i
const NEGATIVE_STATUS_RE =
  /\b(not\s*exists?|non-?exist\w*|no\s*record|not\s*found|nxdomain|inactive|down|dead|offline|unreachable|not\s*accessible|decommissioned|removed|deleted|expired)\b|tidak\s*(ada|aktif|dapat\s*diakses|terjangkau)|nonaktif|\bmati\b/i
/** URL or host-like token inside a cell. */
const TOKEN_RE = /(?:[a-z][a-z0-9+.-]*:\/\/)?[a-z0-9*](?:[a-z0-9.-]*[a-z0-9])?\.[a-z0-9-]{2,}(?::\d+)?(?:\/\S*)?/gi

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }
const decode = (s: string) => s.replace(/&(amp|lt|gt|quot|apos);/g, (_, n: string) => ENTITIES[n])

interface Cell {
  text: string
  span: number
}

/** Visible text of an XML fragment: `<w:t>` runs, paragraphs separated by spaces. */
function textOf(xml: string): string {
  const parts = xml.split(/<\/w:p>/).map(p => [...p.matchAll(/<w:t(?:\s[^>]*)?>([^<]*)<\/w:t>/g)].map(m => m[1]).join(''))
  return decode(parts.join(' ')).replace(/\s+/g, ' ').trim()
}

function parseRows(tableXml: string): Cell[][] {
  return [...tableXml.matchAll(/<w:tr\b[\s\S]*?<\/w:tr>/g)].map(row =>
    [...row[0].matchAll(/<w:tc\b[\s\S]*?<\/w:tc>/g)].map(cell => ({
      text: textOf(cell[0]),
      span: Number(cell[0].match(/<w:gridSpan w:val="(\d+)"/)?.[1] ?? 1),
    })),
  )
}

/** Text of the cell covering grid column `col` (accounts for horizontal merges). */
function cellAt(row: Cell[], col: number): Cell | undefined {
  let pos = 0
  for (const cell of row) {
    if (col < pos + cell.span) return cell
    pos += cell.span
  }
  return undefined
}

function columnIndex(header: Cell[], re: RegExp): number {
  let pos = 0
  for (const cell of header) {
    if (re.test(cell.text)) return pos
    pos += cell.span
  }
  return -1
}

function parseTables(xml: string): ParserOutput {
  const targets: string[] = []
  const skipped: SkippedEntry[] = []

  // Nested tables are rare in reports; top-level matching is enough here
  for (const table of xml.matchAll(/<w:tbl>[\s\S]*?<\/w:tbl>/g)) {
    const [header, ...rows] = parseRows(table[0])
    if (!header) continue
    let hostCol = columnIndex(header, HOST_HEADER_RE)
    if (hostCol === -1) hostCol = columnIndex(header, IP_HEADER_RE)
    if (hostCol === -1) continue
    const statusCol = columnIndex(header, STATUS_HEADER_RE)

    for (const row of rows) {
      const first = row[0]
      if (!first) continue
      if (first.span > 1 && hostCol < first.span) {
        if (first.text) skipped.push({ reason: 'group', value: first.text })
        continue
      }

      const value = cellAt(row, hostCol)?.text ?? ''
      if (!value || value === '-') continue // empty or vertically merged cell

      const status = statusCol === -1 ? '' : cellAt(row, statusCol)?.text ?? ''
      const tokens = value.match(TOKEN_RE) ?? []
      // Cells without any host-like token (e.g. "Total") are plain text, not targets
      if (tokens.length === 0) continue
      if (status && NEGATIVE_STATUS_RE.test(status)) {
        for (const token of tokens) skipped.push({ reason: 'status', value: token, detail: status })
      } else {
        targets.push(...tokens)
      }
    }
  }

  const filtered = filterNoise(targets)
  return { targets: filtered.targets, skipped: [...skipped, ...(filtered.skipped ?? [])] }
}

export const docxParser = {
  id: 'docx',
  label: 'Word (DOCX)',

  /** ZIP signature `PK\x03\x04`. */
  canParse(bytes: Uint8Array, fileName: string): boolean {
    return /\.docx$/i.test(fileName) && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04
  },

  parse(bytes: Uint8Array): { output: ParserOutput; generic: boolean } {
    const files = unzipSync(bytes, { filter: file => file.name === 'word/document.xml' })
    const docXml = files['word/document.xml']
    if (!docXml) throw new Error('Not a Word document')
    const xml = new TextDecoder('utf-8').decode(docXml)

    const fromTables = parseTables(xml)
    if (fromTables.targets.length > 0) return { output: fromTables, generic: false }

    // No usable table: treat the document text like any other text file
    const text = xml.split(/<\/w:p>/).map(textOf).join('\n')
    return { output: genericParser.parse(text), generic: true }
  },
}
