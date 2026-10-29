import { describe, expect, it } from 'vitest'
import { isHostname, isIPv4, normalizeAndDedupe, normalizeHost } from './normalize'

describe('normalizeHost', () => {
  it.each([
    ['https://API.example.com:8443/path?q=1#x', 'api.example.com'],
    ['http://example.com', 'example.com'],
    ['example.com/', 'example.com'],
    ['example.com:80', 'example.com'],
    ['*.example.com', 'example.com'],
    ['example.com.', 'example.com'],
    ['https://user:pass@example.com/', 'example.com'],
    ['  sub.example.co.id  ', 'sub.example.co.id'],
    ['10.0.0.1', '10.0.0.1'],
    ['https://192.168.1.10:8080/admin', '192.168.1.10'],
    ['xn--bcher-kva.example.com', 'xn--bcher-kva.example.com'],
    ['shop.xn--p1ai', 'shop.xn--p1ai'],
  ])('%s -> %s', (input, expected) => {
    expect(normalizeHost(input)).toBe(expected)
  })

  it.each(['', '   ', 'localhost', 'not a host', '-bad.example.com', 'example..com', '999.1.1.1', '01.2.3.4', '[::1]', 'example.c0m'])(
    'rejects %j',
    input => {
      expect(normalizeHost(input)).toBeNull()
    },
  )
})

describe('isIPv4 / isHostname', () => {
  it('validates IPv4 octets', () => {
    expect(isIPv4('255.255.255.255')).toBe(true)
    expect(isIPv4('256.0.0.1')).toBe(false)
    expect(isIPv4('1.2.3')).toBe(false)
  })

  it('requires at least two labels and an alphabetic TLD', () => {
    expect(isHostname('a.io')).toBe(true)
    expect(isHostname('intranet')).toBe(false)
    expect(isHostname('1.2.3.4')).toBe(false)
  })
})

describe('normalizeAndDedupe', () => {
  it('keeps order of first appearance and counts duplicates', () => {
    const result = normalizeAndDedupe([
      'https://b.example.com/',
      'a.example.com',
      'B.EXAMPLE.COM',
      'invalid',
      'https://a.example.com:443/x',
    ])
    expect(result.hosts).toEqual(['b.example.com', 'a.example.com'])
    expect(result.skipped).toEqual([
      { reason: 'duplicate', value: 'b.example.com', detail: '×2' },
      { reason: 'duplicate', value: 'a.example.com', detail: '×2' },
      { reason: 'invalid', value: 'invalid' },
    ])
  })
})
