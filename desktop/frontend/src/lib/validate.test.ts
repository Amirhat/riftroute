import { describe, it, expect } from 'vitest'
import {
  validateRouteTarget,
  validateDomain,
  validateAppValue,
  validateProfileName,
  validateGateway,
} from './validate'

describe('validateRouteTarget', () => {
  it('accepts valid IPv4/IPv6 and CIDRs', () => {
    for (const ok of ['10.0.0.0/8', '1.1.1.1', '192.168.0.0/16', 'fd00::/8', '::1', '2001:db8::1']) {
      expect(validateRouteTarget(ok)).toBeNull()
    }
  })
  it('rejects malformed input', () => {
    expect(validateRouteTarget('999.999.999.999')).not.toBeNull()
    expect(validateRouteTarget('999.999.999')).not.toBeNull()
    expect(validateRouteTarget('10.0.0.0/99')).not.toBeNull()
    expect(validateRouteTarget('fd00::/999')).not.toBeNull()
    expect(validateRouteTarget('nope')).not.toBeNull()
    expect(validateRouteTarget('')).not.toBeNull()
  })
})

describe('validateDomain', () => {
  it('accepts domains incl. a single leading wildcard', () => {
    expect(validateDomain('corp.example.com')).toBeNull()
    expect(validateDomain('*.corp.example.com')).toBeNull()
    expect(validateDomain('a.b')).toBeNull()
  })
  it('rejects single labels and bad characters', () => {
    expect(validateDomain('localhost')).not.toBeNull()
    expect(validateDomain('bad_underscore.com')).not.toBeNull()
    expect(validateDomain('')).not.toBeNull()
  })
})

describe('validateAppValue', () => {
  it('uid strategy accepts uid/username only', () => {
    expect(validateAppValue('501', 'uid')).toBeNull()
    expect(validateAppValue('alice', 'uid')).toBeNull()
    expect(validateAppValue('/Applications/Firefox.app', 'uid')).not.toBeNull()
    expect(validateAppValue('', 'uid')).not.toBeNull()
  })
  it('app strategy accepts any non-empty value', () => {
    expect(validateAppValue('firefox.service', 'app')).toBeNull()
    expect(validateAppValue('', 'app')).not.toBeNull()
  })
})

describe('validateProfileName', () => {
  it('requires a unique non-empty name', () => {
    expect(validateProfileName('work', ['home'])).toBeNull()
    expect(validateProfileName('', [])).not.toBeNull()
    expect(validateProfileName('dup', ['dup'])).not.toBeNull()
  })
})

describe('validateGateway', () => {
  it('accepts auto/empty/IP and rejects junk', () => {
    expect(validateGateway('auto')).toBeNull()
    expect(validateGateway('')).toBeNull()
    expect(validateGateway('192.168.1.1')).toBeNull()
    expect(validateGateway('nope')).not.toBeNull()
  })
})
