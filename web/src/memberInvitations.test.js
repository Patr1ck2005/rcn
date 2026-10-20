import { describe, expect, it } from 'vitest';
import { enrollmentOrigin, invitationDocument, invitationState, pendingMetadata,
  newInvitationOperation, cancellationReceipt } from './memberInvitationModel.js';
import { readFileSync } from 'node:fs';

const request = { owner_user_id: 'member', worker: true, control_plane_url: 'https://enrollment.example' };
const document = () => ({ schema_version: 2, enrollment_id: 'enrollment-1', machine_id: 'MEMBER-1',
  ...request, enrollment_code: 'x'.repeat(43), expires_at: '2027-01-01T00:00:00Z' });
const now = Date.parse('2026-09-21T00:00:00Z');

describe('private invitation presentation', () => {
  it('creates separate bounded random identity and delivery material without fallback', () => {
    const sizes = [];
    const source = { getRandomValues(array) { sizes.push(array.length); return array.fill(sizes.length); } };
    const operation = newInvitationOperation(request, source);
    expect(sizes).toEqual([16, 32]);
    expect(operation.operation_id).toMatch(/^[a-f0-9]{32}$/);
    expect(operation.request.delivery_secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Object.isFrozen(operation.request)).toBe(true);
    expect(() => newInvitationOperation(request, null)).toThrow('secure-random-unavailable');
  });
  it('persists operation identity but drops both delivery material and invitation code', () => {
    const result = pendingMetadata({ ...document(), operation_id: 'a'.repeat(32), delivery_secret: 'private',
      state: 'issuing', started_at: '2026-09-21T00:00:00Z' });
    expect(result.operation_id).toBe('a'.repeat(32));
    expect(result).not.toHaveProperty('delivery_secret');
    expect(result).not.toHaveProperty('enrollment_code');
    expect(() => pendingMetadata({ ...result, operation_id: '../../other' })).toThrow();
  });
  it('requires an exact cancellation receipt and preserves registered machines', () => {
    const receipt = { operation_id: 'a'.repeat(32), state: 'cancelled', cancelled: true, existing_machine_revoked: false };
    expect(cancellationReceipt(receipt, receipt.operation_id)).toEqual(receipt);
    expect(cancellationReceipt({ ...receipt, state: 'registered', cancelled: false }, receipt.operation_id).cancelled).toBe(false);
    for (const extra of [{ operation_id: 'b'.repeat(32) }, { cancelled: false }, { existing_machine_revoked: true }, { state: 'unknown' }]) {
      expect(() => cancellationReceipt({ ...receipt, ...extra }, receipt.operation_id)).toThrow();
    }
  });
  it('accepts only the exact issued identity and strips no surprise keys silently', () => {
    expect(invitationDocument(document(), request, now)).toEqual(document());
  });
  for (const [field, value] of [['schema_version', true], ['machine_id', 123], ['machine_id', '../../escape'],
    ['owner_user_id', 'other'], ['worker', false], ['enrollment_code', 'wrong'], ['private_key', 'secret'],
    ['control_plane_url', 'https://other.example'], ['expires_at', '2026-01-01T00:00:00Z'], ['expires_at', 'unknown']]) {
    it(`rejects unexpected ${field}:${value}`, () => {
      expect(() => invitationDocument({ ...document(), [field]: value }, request, now)).toThrow();
    });
  }
  for (const origin of ['http://host.example', 'https://user:pass@host.example', 'https://host.example/path',
    'https://host.example?token=abc', 'https://127.0.0.1', 'https://localhost', 'https://[::1]', 'https://host.example/#fragment']) {
    it(`rejects unsafe endpoint ${origin}`, () => expect(() => enrollmentOrigin(origin)).toThrow());
  }
  it('persists a whitelist of delivery metadata, never the secret document', () => {
    const value = pendingMetadata({ ...document(), state: 'awaiting-delivery', started_at: '2026-09-21T00:00:00Z' });
    expect(Object.keys(value).sort()).toEqual(['state', 'started_at', 'owner_user_id', 'enrollment_id'].sort());
    expect(JSON.stringify(value)).not.toContain('x'.repeat(43));
  });
  for (const corrupt of [null, {}, { state: 'issuing', owner_user_id: { secret: 'not-rendered' } }]) {
    it('rejects malformed stored delivery state instead of rendering it', () => {
      expect(() => pendingMetadata(corrupt)).toThrow('invalid-delivery-checkpoint');
    });
  }
  it('never presents registration as verified compute readiness', () => {
    expect(invitationState({ used_at: '2026-09-21' }, now)).toContain('不代表通过计算验收');
    expect(invitationState({ revoked_at: 'x', used_at: 'x' }, now)).toBe('已撤销');
    expect(invitationState({ expires_at: '2026-09-20' }, now)).toBe('已过期');
  });
  it('is mounted in the actual administrator nodes entry', () => {
    const source = readFileSync(new URL('./AdminConsole.jsx', import.meta.url), 'utf8');
    expect(source).toContain('import MemberInvitations');
    expect(source).toContain('tab === "nodes" && <MemberInvitations');
  });
});
