import { describe, it, expect, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import MemberInvitations from './MemberInvitations.jsx';
import { conditionalInvitation, selectedProfiles } from './MemberAdmissionFields.jsx';
import { newInvitationOperation } from './memberInvitationModel.js';
const projects = [{ project_id: 'scope-project', approved: true, status: 'active', allowed_profiles: ['fixed-profile'], trusted_machine_labels: [] }];
const profiles = [{ profile_id: 'fixed-profile', platforms: ['windows'], allow_arbitrary_command: false }];
const value = () => ({ project_profiles: { 'scope-project': ['fixed-profile'] }, max_cpus: 4, max_memory_mb: 8192, valid_for_days: 30, acknowledge_project_trust: false });
describe('one-operation conditional invitation', () => {
  it('presents the real invitation form with unlimited compute authorization selected by default', () => {
    vi.stubGlobal('sessionStorage', { getItem: () => null });
    vi.stubGlobal('location', { protocol: 'https:' });
    try {
      const html = renderToStaticMarkup(<MemberInvitations actorId="admin" projects={projects} profiles={profiles} />);
      expect(html).toContain('<option value="unlimited" selected="">无到期，直到主动撤销</option>');
      expect(html).not.toContain('aria-label="计算授权有效期（天）"');
    } finally { vi.unstubAllGlobals(); }
  });
  it('preserves scope and one slot', () => expect(conditionalInvitation(value(), projects, profiles)).toEqual({ ...value(), max_concurrent_units: 1 }));
  it('keeps unlimited compute permission explicit and frozen without changing the invitation ticket', () => {
    const scope = conditionalInvitation({ ...value(), valid_for_days: null }, projects, profiles);
    expect(scope.valid_for_days).toBeNull();
    const operation = newInvitationOperation({ owner_user_id: 'member', worker: true, ttl_minutes: 60, conditional_admission: scope }, { getRandomValues: array => array.fill(1) });
    expect(operation.request.conditional_admission.valid_for_days).toBeNull();
    expect(operation.request.ttl_minutes).toBe(60);
    expect(() => operation.request.conditional_admission.valid_for_days = 30).toThrow();
  });
  for (const days of [undefined, true, '30', 366]) {
    it(`rejects invalid lifetime ${days}`, () => expect(() => conditionalInvitation({ ...value(), valid_for_days: days }, projects, profiles)).toThrow());
  }
  for (const change of ['empty', 'unknown-project', 'unknown-profile', 'frozen', 'cpu', 'memory', 'days', 'arbitrary', 'unacknowledged-trust']) {
    it(`rejects ${change}`, () => {
      const v = value(), p = structuredClone(projects), r = structuredClone(profiles);
      if (change === 'empty') v.project_profiles = {};
      if (change === 'unknown-project') v.project_profiles = { another: ['fixed-profile'] };
      if (change === 'unknown-profile') v.project_profiles['scope-project'] = ['unreviewed'];
      if (change === 'frozen') p[0].status = 'frozen';
      if (change === 'cpu') v.max_cpus = 0;
      if (change === 'memory') v.max_memory_mb = 20;
      if (change === 'days') v.valid_for_days = 0;
      if (change === 'arbitrary') r[0].allow_arbitrary_command = true;
      if (change === 'unacknowledged-trust') p[0].trusted_machine_labels = ['sensitive'];
      expect(() => conditionalInvitation(v, p, r)).toThrow();
    });
  }
  it('accepts explicitly acknowledged project trust', () => {
    expect(conditionalInvitation({ ...value(), acknowledge_project_trust: true }, [{ ...projects[0], trusted_machine_labels: ['sensitive'] }], profiles).acknowledge_project_trust).toBe(true);
  });
  it('treats a project named constructor as data, not an inherited selection', () => {
    expect(selectedProfiles({}, 'constructor')).toEqual([]);
    expect(selectedProfiles({ constructor: ['fixed-profile'] }, 'constructor')).toEqual(['fixed-profile']);
    const p = [{ ...projects[0], project_id: 'constructor' }];
    expect(conditionalInvitation({ ...value(), project_profiles: { constructor: ['fixed-profile'] } }, p, profiles).project_profiles.constructor).toEqual(['fixed-profile']);
  });
  it('deep freezes exact request for uncertain retry', () => {
    const scope = value();
    const operation = newInvitationOperation({ owner_user_id: 'new-person', new_member_display_name: 'Person', conditional_admission: scope }, { getRandomValues: array => array.fill(1) });
    scope.project_profiles['scope-project'].push('later-edit');
    expect(operation.request.conditional_admission.project_profiles['scope-project']).toEqual(['fixed-profile']);
    expect(() => operation.request.conditional_admission.max_cpus = 200).toThrow();
  });
});
