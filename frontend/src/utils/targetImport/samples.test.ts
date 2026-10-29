/**
 * Regression tests against real reports in `<repo>/sample/`.
 *
 * The sample reports contain client data and are git-ignored, so these
 * tests are skipped automatically when the files are not present.
 */
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { importDocx, importTargets } from './index'

const SAMPLE_DIR = resolve(__dirname, '../../../../sample')
const MULTI = resolve(SAMPLE_DIR, '20261027_Comprehensive_new__Multiple_targets.html')
const ANALYTIC = resolve(SAMPLE_DIR, 'T1 - Analytic (2).html')
const DOCX = resolve(SAMPLE_DIR, 'VA_Report_PT_Samsung_Electronics_Indonesia_SEIN_30_September_2026 (2).docx')

describe.skipIf(!existsSync(MULTI))('sample: Comprehensive multiple targets', () => {
  it('extracts 43 unique hosts and reports the duplicate', () => {
    const result = importTargets(readFileSync(MULTI, 'utf-8'), MULTI)
    expect(result.format.id).toBe('acunetix-html')
    expect(result.hosts).toHaveLength(43)
    expect(result.skipped).toEqual([{ reason: 'duplicate', value: 'cms.s-appstation.com', detail: '×2' }])
    expect(result.hosts[0]).toBe('ticket.srinapps.com')
    expect(result.hosts[result.hosts.length - 1]).toBe('app.s-appstation.com')
    // start_url with a path is reduced to the host
    expect(result.hosts).toContain('cdn.s-gift.app')
    expect(result.hosts.every(h => !h.includes('/'))).toBe(true)
  })
})

describe.skipIf(!existsSync(ANALYTIC))('sample: T1 Analytic', () => {
  it('extracts 9 hosts', () => {
    const result = importTargets(readFileSync(ANALYTIC, 'utf-8'), ANALYTIC)
    expect(result.format.id).toBe('acunetix-html')
    expect(result.hosts).toEqual([
      'api-analytic.brompit.net',
      'ead.modakita.com',
      'apianalytic-admin.sinarsentosaprimatama.com',
      'apianalytic.menara-agung.com',
      'apianalytic-moski.kemakmuran.com',
      'apianalytic.bahunda.com',
      'detector-dev.modakita.com',
      'detector-writer.modakita.com',
      'targetting.ads.modakita.com',
    ])
    expect(result.skipped).toEqual([])
  })
})

describe.skipIf(!existsSync(DOCX))('sample: VA report DOCX', () => {
  it('extracts hosts from tables and skips apex group rows', () => {
    const result = importDocx(new Uint8Array(readFileSync(DOCX)))
    expect(result.format.id).toBe('docx')
    expect(result.isGeneric).toBe(false)
    expect(result.hosts).toHaveLength(105)
    expect(result.hosts[0]).toBe('bacula.srinapps.com')
    expect(result.hosts).toContain('cdn.s-gift.app')
    expect(result.hosts).not.toContain('srinapps.com')
    expect(result.skipped.filter(s => s.reason === 'group').map(s => s.value)).toEqual([
      'Srinapps.com',
      'Srinapps2.com',
      'S-gift.app',
      'S-lime.com',
      'S-salaam.com',
      'S-pay-id.com',
      'S-appstation.com',
    ])
    // Reference links live in description columns, not host columns
    expect(result.skipped.some(s => s.reason === 'reference')).toBe(false)
  })
})
