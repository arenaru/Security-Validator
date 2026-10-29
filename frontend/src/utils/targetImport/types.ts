/**
 * Shared types for importing scan targets from scanner report files
 * (Acunetix, Burp, Nessus, Nmap, ZAP, Word DOCX, or any text-based file).
 */

/** Why an entry from the file was not added to the target list. */
export type SkipReason = 'duplicate' | 'status' | 'group' | 'reference' | 'invalid'

export interface SkippedEntry {
  reason: SkipReason
  /** Value as found in the file (or the normalized host for duplicates). */
  value: string
  /** Extra context, e.g. `×2` for duplicates or the status text. */
  detail?: string
}

/** Raw output of a single parser, before normalization and de-duplication. */
export interface ParserOutput {
  /** Hosts, URLs or IPs exactly as found in the file. */
  targets: string[]
  /** Entries the parser deliberately dropped (references, group rows, inactive rows...). */
  skipped?: SkippedEntry[]
}

/**
 * A text-based report format. To support a new scanner, implement this
 * interface in a new file and register it in `index.ts` (`PARSERS`).
 */
export interface TargetParser {
  /** Stable identifier, e.g. `acunetix-html`. */
  id: string
  /** Human readable name shown in the UI, e.g. `Acunetix HTML`. */
  label: string
  /** Cheap check on the file content (and name) to decide if this parser applies. */
  canParse(text: string, fileName: string): boolean
  /** Extract raw targets. May throw; the importer falls back to the generic parser. */
  parse(text: string): ParserOutput
}

export interface ImportResult {
  /** Normalized, de-duplicated host list (order of first appearance). */
  hosts: string[]
  /** Parser that produced the result. */
  format: { id: string; label: string }
  /** True when no dedicated parser matched and heuristics were used. */
  isGeneric: boolean
  /** Everything that was found but not added, with the reason. */
  skipped: SkippedEntry[]
  /** True when the host count is above the backend per-scan limit. */
  exceedsLimit: boolean
}
