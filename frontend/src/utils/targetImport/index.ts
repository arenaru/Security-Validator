/**
 * Import scan targets from scanner report files.
 *
 * Dedicated parsers are tried in order; the first whose `canParse` matches
 * and yields at least one target wins. Anything else goes through the
 * generic heuristic parser. Output is always a normalized, de-duplicated
 * host list ready for the targets textarea, plus a list of what was skipped.
 *
 * To add a text format: create `parsers/<name>.ts` implementing `TargetParser`
 * and add it to `PARSERS` below. Binary formats (DOCX) are handled in
 * `importTargetsFromFile`.
 */
import { normalizeAndDedupe } from './normalize'
import { acunetixHtmlParser } from './parsers/acunetixHtml'
import { burpXmlParser } from './parsers/burpXml'
import { docxParser } from './parsers/docx'
import { genericParser } from './parsers/generic'
import { nessusParser } from './parsers/nessus'
import { nmapXmlParser } from './parsers/nmapXml'
import { zapParser } from './parsers/zap'
import type { ImportResult, ParserOutput, SkipReason, TargetParser } from './types'

export type { ImportResult, SkippedEntry, SkipReason, TargetParser } from './types'

/** Backend limit (`MAX_TARGETS_PER_SCAN` in backend/models/scan_models.py). */
export const MAX_TARGETS_PER_SCAN = 200

/** Files above this size are rejected to keep the browser responsive. */
export const MAX_IMPORT_FILE_BYTES = 50 * 1024 * 1024

export const ACCEPTED_FILE_TYPES = '.html,.htm,.xml,.nessus,.json,.csv,.txt,.log,.md,.docx'

export const PARSERS: readonly TargetParser[] = [
  acunetixHtmlParser,
  burpXmlParser,
  nessusParser,
  nmapXmlParser,
  zapParser,
]

export type ImportErrorCode = 'too-large' | 'binary' | 'read-failed'

export class TargetImportError extends Error {
  constructor(public readonly code: ImportErrorCode, message: string) {
    super(message)
    this.name = 'TargetImportError'
  }
}

function runParser(parser: TargetParser, text: string): ParserOutput | null {
  try {
    const output = parser.parse(text)
    return output.targets.length > 0 ? output : null
  } catch {
    return null
  }
}

/** Display order of skip reasons. */
const REASON_ORDER: SkipReason[] = ['duplicate', 'status', 'group', 'reference', 'invalid']

function buildResult(format: { id: string; label: string }, output: ParserOutput, isGeneric: boolean): ImportResult {
  const { hosts, skipped: dedupeSkipped } = normalizeAndDedupe(output.targets)

  // One entry per reason + value (the same reference link can appear many times)
  const seen = new Set<string>()
  const skipped = [...(output.skipped ?? []), ...dedupeSkipped]
    .filter(entry => {
      const key = `${entry.reason}\u0000${entry.value.toLowerCase()}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
    .sort((a, b) => REASON_ORDER.indexOf(a.reason) - REASON_ORDER.indexOf(b.reason))

  return { hosts, format, isGeneric, skipped, exceedsLimit: hosts.length > MAX_TARGETS_PER_SCAN }
}

const genericFormat = { id: genericParser.id, label: genericParser.label }

/** Extract targets from already-loaded file content. */
export function importTargets(text: string, fileName = ''): ImportResult {
  for (const parser of PARSERS) {
    if (!parser.canParse(text, fileName)) continue
    const output = runParser(parser, text)
    if (output) {
      const result = buildResult({ id: parser.id, label: parser.label }, output, false)
      if (result.hosts.length > 0) return result
    }
  }
  return buildResult(genericFormat, runParser(genericParser, text) ?? { targets: [] }, true)
}

/** Extract targets from a Word `.docx` file. */
export function importDocx(bytes: Uint8Array): ImportResult {
  const { output, generic } = docxParser.parse(bytes)
  return buildResult({ id: docxParser.id, label: docxParser.label }, output, generic)
}

/** True when the content looks binary (NUL bytes), e.g. a PDF, image or archive. */
function looksBinary(text: string): boolean {
  return text.slice(0, 8192).includes('\u0000')
}

/** Read a user-selected file and extract targets. Throws `TargetImportError`. */
export async function importTargetsFromFile(file: File): Promise<ImportResult> {
  if (file.size > MAX_IMPORT_FILE_BYTES) {
    throw new TargetImportError('too-large', `File exceeds ${MAX_IMPORT_FILE_BYTES} bytes`)
  }

  let bytes: Uint8Array
  try {
    bytes = new Uint8Array(await file.arrayBuffer())
  } catch {
    throw new TargetImportError('read-failed', 'Unable to read file')
  }

  if (docxParser.canParse(bytes, file.name)) {
    try {
      return importDocx(bytes)
    } catch {
      throw new TargetImportError('read-failed', 'Unable to read Word document')
    }
  }

  const text = new TextDecoder('utf-8').decode(bytes)
  if (text.startsWith('%PDF') || looksBinary(text)) {
    throw new TargetImportError('binary', 'Binary files are not supported')
  }

  return importTargets(text, file.name)
}
