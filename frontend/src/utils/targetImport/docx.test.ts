import { strToU8, zipSync } from 'fflate'
import { describe, expect, it } from 'vitest'
import { importDocx, importTargetsFromFile } from './index'

type Row = Array<string | { text: string; span: number }>

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;')

function cellXml(cell: Row[number]): string {
  const { text, span } = typeof cell === 'string' ? { text: cell, span: 1 } : cell
  const props = span > 1 ? `<w:tcPr><w:gridSpan w:val="${span}"/></w:tcPr>` : ''
  return `<w:tc>${props}<w:p><w:r><w:t>${esc(text)}</w:t></w:r></w:p></w:tc>`
}

const tableXml = (rows: Row[]) => `<w:tbl>${rows.map(r => `<w:tr>${r.map(cellXml).join('')}</w:tr>`).join('')}</w:tbl>`
const paraXml = (text: string) => `<w:p><w:r><w:t>${esc(text)}</w:t></w:r></w:p>`

/** Build a minimal .docx (only word/document.xml is read by the parser). */
function docx(body: string): Uint8Array {
  const xml = `<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${body}</w:body></w:document>`
  return zipSync({ '[Content_Types].xml': strToU8('<Types/>'), 'word/document.xml': strToU8(xml) })
}

const skippedOf = (bytes: Uint8Array, reason: string) =>
  importDocx(bytes).skipped.filter(s => s.reason === reason).map(s => (s.detail ? `${s.value} (${s.detail})` : s.value))

describe('DOCX', () => {
  const report = docx(
    paraXml('See https://nvd.nist.gov/vuln/detail/CVE-2020-11022 for details.') +
      tableXml([
        ['URL / Domain', 'IP', 'Status'],
        [{ text: 'Example.com', span: 3 }],
        ['app.example.com', '203.0.113.1', 'exist'],
        ['old.example.com', '-', 'not exist'],
        ['https://api.example.com/v1/', '-', 'Active'],
        ['cdn.example.com/preload/', '-', 'exist'],
        ['cdn.example.com', '-', 'exist'],
        ['', '203.0.113.9', ''],
        ['mati.example.com', '-', 'tidak aktif'],
      ]) +
      tableXml([
        ['Vulnerability', 'Risk', 'Description'],
        ['XSS', 'Low', 'Found on evil.example.org, see portswigger.net'],
      ]) +
      tableXml([
        ['Host', 'Grade'],
        ['app.example.com', 'A'],
        ['Total', '-'],
      ]),
  )

  it('reads host columns from tables only', () => {
    const result = importDocx(report)
    expect(result.format.id).toBe('docx')
    expect(result.isGeneric).toBe(false)
    expect(result.hosts).toEqual(['app.example.com', 'api.example.com', 'cdn.example.com'])
  })

  it('lists skipped group rows, inactive rows and duplicates', () => {
    expect(skippedOf(report, 'group')).toEqual(['Example.com'])
    expect(skippedOf(report, 'status')).toEqual(['old.example.com (not exist)', 'mati.example.com (tidak aktif)'])
    expect(skippedOf(report, 'duplicate')).toEqual(['app.example.com (×2)', 'cdn.example.com (×2)'])
    expect(skippedOf(report, 'reference')).toEqual([])
  })

  it('falls back to document text when no table has a host column', () => {
    const result = importDocx(
      docx(paraXml('Scope: portal.example.com and 198.51.100.4') + paraXml('Ref: https://owasp.org/Top10')),
    )
    expect(result.isGeneric).toBe(true)
    expect(result.hosts).toEqual(['portal.example.com', '198.51.100.4'])
    expect(skippedOf(docx(paraXml('Ref: https://owasp.org/Top10')), 'reference')).toEqual(['owasp.org'])
  })

  it('is detected from a File by name and ZIP signature', async () => {
    const file = new File([new Uint8Array(report)], 'report.docx')
    const result = await importTargetsFromFile(file)
    expect(result.format.id).toBe('docx')
    expect(result.hosts).toHaveLength(3)
  })

  it('rejects a corrupt .docx', async () => {
    const file = new File([new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2, 3])], 'broken.docx')
    await expect(importTargetsFromFile(file)).rejects.toMatchObject({ code: 'read-failed' })
  })
})
