/**
 * Host normalization shared by every parser.
 *
 * Every imported value is reduced to a bare, lowercase hostname or IPv4
 * address (no scheme, credentials, port, path, wildcard or trailing dot),
 * because SecVal scans hosts and the backend strips everything else anyway.
 */

import type { SkippedEntry } from './types'

const SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const TLD_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/

export function isIPv4(value: string): boolean {
  if (!IPV4_RE.test(value)) return false
  return value.split('.').every(octet => {
    // Reject leading zeros ("010") to avoid octal ambiguity
    if (octet.length > 1 && octet.startsWith('0')) return false
    return Number(octet) <= 255
  })
}

export function isHostname(value: string): boolean {
  if (value.length > 253) return false
  const labels = value.split('.')
  if (labels.length < 2) return false
  if (!labels.every(label => LABEL_RE.test(label))) return false
  return TLD_RE.test(labels[labels.length - 1])
}

/**
 * Convert a raw value (URL, host, host:port, wildcard...) to a bare host.
 * Returns `null` when the value is not a valid hostname or IPv4 address.
 */
export function normalizeHost(raw: string): string | null {
  let value = raw.trim().toLowerCase()
  if (!value) return null

  value = value.replace(SCHEME_RE, '')
  // Drop credentials ("user:pass@host")
  const at = value.lastIndexOf('@', value.search(/[/?#]|$/))
  if (at !== -1) value = value.slice(at + 1)
  // Cut path, query and fragment
  value = value.split(/[/?#\\]/, 1)[0]
  // IPv6 literals are not supported by the scanner input
  if (value.startsWith('[')) return null
  // Strip port
  value = value.replace(/:\d*$/, '')
  // Wildcards and fully-qualified trailing dot
  value = value.replace(/^(\*\.)+/, '').replace(/\.+$/, '')

  if (isIPv4(value) || isHostname(value)) return value
  return null
}

export interface DedupeResult {
  hosts: string[]
  /** Duplicate hosts (detail `×N` = total occurrences) and invalid values. */
  skipped: SkippedEntry[]
}

/** Normalize and de-duplicate, keeping the order of first appearance. */
export function normalizeAndDedupe(rawTargets: Iterable<string>): DedupeResult {
  const counts = new Map<string, number>()
  const invalid = new Set<string>()

  for (const raw of rawTargets) {
    const host = normalizeHost(raw)
    if (host) counts.set(host, (counts.get(host) ?? 0) + 1)
    else if (raw.trim()) invalid.add(raw.trim())
  }

  const skipped: SkippedEntry[] = []
  for (const [host, count] of counts) {
    if (count > 1) skipped.push({ reason: 'duplicate', value: host, detail: `×${count}` })
  }
  for (const value of invalid) skipped.push({ reason: 'invalid', value })

  return { hosts: [...counts.keys()], skipped }
}
