// Browser component integration with in-memory HTTPS routes. No listener,
// production server, actual member, or real credential is contacted.
import { build } from 'esbuild';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

let bundle;
test.beforeAll(async () => {
  const result = await build({ stdin: { contents: `
    import React,{useState} from 'react';
    import {createRoot} from 'react-dom/client';
    import MemberInvitations from './src/MemberInvitations.jsx';
    import {api} from './src/api.js';
    function Harness(){
      const [items,setItems]=useState([]);const [visible,setVisible]=useState(true);
      const scoped=new URLSearchParams(location.search).has('scoped');
      const scopeProps=scoped?{projects:[{project_id:'scope-project',approved:true,status:'active',allowed_profiles:['fixed-profile'],trusted_machine_labels:['sensitive']}],
        profiles:[{profile_id:'fixed-profile',platforms:['windows'],allow_arbitrary_command:false}],admissionReady:true}:{};
      return <><button onClick={()=>setVisible(!visible)}>切换页面</button>{visible&&<MemberInvitations actorId="admin"
        users={[{user_id:'member',display_name:'测试成员',active:true,roles:['member','machine_owner']},
        {user_id:'plain',display_name:'普通成员',active:true,roles:['member']}]}
        {...scopeProps} enrollments={items} ready={true} onRefresh={async()=>setItems(await api('/v1/admin/enrollments'))}/>}</>;
    }
    createRoot(document.getElementById('root')).render(<Harness/>);`,
    resolveDir: fileURLToPath(new URL('../', import.meta.url)), loader: 'jsx' },
    bundle: true, write: false, outdir: 'ignored-in-memory', jsx: 'automatic',
    define: { 'process.env.NODE_ENV': '"production"' } });
  bundle = result.outputFiles;
});

async function boot(page, { mode = 'ok', protocol = 'https:', scoped = false } = {}) {
  const calls = [], identities = [], cancellations = []; let records = [];
  const operations = new Map();
  let releaseLate;
  const lateResponse = new Promise(resolve => { releaseLate = resolve; });
  const code = 's'.repeat(43);
  await page.route('**/*', async route => {
    const request = route.request(); const url = new URL(request.url());
    if (url.hostname !== 'rcn-ui.test') throw new Error('Unexpected external request');
    if (url.pathname === '/') return route.fulfill({ contentType: 'text/html', body: '<html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/bundle.css"><div id="root"></div><script src="/bundle.js"></script></html>' });
    if (url.pathname === '/bundle.css') return route.fulfill({ contentType: 'text/css', body: bundle.find(file => file.path.endsWith('.css')).text });
    if (url.pathname === '/bundle.js') return route.fulfill({ contentType: 'application/javascript', body: bundle.find(file => file.path.endsWith('.js')).text });
    if (url.pathname === '/v1/admin/enrollments') return route.fulfill({ json: records });
    const match = url.pathname.match(/^\/v1\/admin\/member-invitation-operations\/([a-f0-9]{32})(\/cancel)?$/);
    if (match) {
      const identity = match[1];
      if (match[2]) {
        cancellations.push(identity);
        if (mode === 'cancel-lost' && cancellations.length === 1) return route.abort('connectionreset');
        if (mode === 'cancel-bad') return route.fulfill({ json: { operation_id: 'wrong', state: 'cancelled', cancelled: true, existing_machine_revoked: false } });
        operations.set(identity, { cancelled: true });
        records = records.map(item => ({ ...item, revoked_at: new Date().toISOString() }));
        return route.fulfill({ json: { operation_id: identity, cancelled: true, state: 'cancelled', existing_machine_revoked: false } });
      }
      expect(request.method()).toBe('PUT');
      calls.push(request.postDataJSON()); identities.push(identity);
      if (operations.get(identity)?.cancelled) return route.fulfill({ status:409,json:{detail:{reason_code:'invitation_operation_unavailable'}} });
      const body = calls.at(-1);
      const document = operations.get(identity)?.document || { schema_version: 2, enrollment_id: 'enrollment-browser', machine_id: 'MEMBER-browser',
        owner_user_id: body.owner_user_id, control_plane_url: body.control_plane_url, worker: body.worker,
        enrollment_code: code, expires_at: new Date(Date.now() + 3600000).toISOString() };
      operations.set(identity, { document });
      records = [{ ...document, enrollment_code: undefined, registration_mode: 'resumable-v1', invited_machine_id: document.machine_id }];
      if (mode === 'lost' || mode.startsWith('cancel-') || (mode === 'lost-once' && calls.length === 1)) return route.abort('connectionreset');
      if (mode === 'late') await lateResponse;
      if (mode === 'slow') await new Promise(resolve => setTimeout(resolve, 350));
      if (mode === 'bad') document.private_key = 'must-not-render';
      return route.fulfill({ json: document });
    }
    if (url.pathname.endsWith('/revoke')) {
      records = records.map(item => ({ ...item, revoked_at: new Date().toISOString() }));
      return route.fulfill({ json: { revoked: true, existing_machine_revoked: false } });
    }
    return route.fulfill({ status: 404, body: '' });
  });
  await page.goto(`${protocol}//rcn-ui.test/${scoped ? '?scoped=1' : ''}`);
  return { calls, code, identities, cancellations, releaseLate };
}
async function fill(page) {
  await page.getByLabel('获邀成员').selectOption('member');
  await page.getByLabel('独立 HTTPS 接入地址').fill('https://enrollment.example');
}

test('issue, download privately, and revoke without exposing secrets in page/storage', async ({ page }, testInfo) => {
  const fixture = await boot(page, { mode: 'slow' }); await fill(page);
  await page.getByRole('button', { name: '签发私密邀请' }).click();
  await expect(page.getByRole('button', { name: '签发私密邀请' })).toBeDisabled();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: '下载私密邀请 JSON' }).click();
  const artifact = await download;
  const saved = JSON.parse(await readFile(await artifact.path(), 'utf8'));
  expect(saved.enrollment_code).toBe(fixture.code);
  expect(artifact.suggestedFilename()).toBe('RCN-invitation-MEMBER-browser.json');
  expect(fixture.calls).toHaveLength(1);
  expect(await page.locator('body').innerText()).not.toContain(fixture.code);
  const storage = await page.evaluate(() => JSON.stringify({ ...sessionStorage, ...localStorage }));
  expect(storage).not.toContain(fixture.code);
  expect(storage).not.toContain(fixture.calls[0].delivery_secret);
  expect(JSON.stringify(saved)).not.toContain(fixture.calls[0].delivery_secret);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBeTruthy();
  await page.screenshot({ path: testInfo.outputPath('invitation-delivery.png'), fullPage: true });
  await page.getByRole('button', { name: '撤销未用邀请' }).click();
  await expect(page.getByText('已撤销', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '下载私密邀请 JSON' })).toHaveCount(0);
});

test('lost issuance response stays blocked across reload and never automatically reissues', async ({ page }) => {
  const fixture = await boot(page, { mode: 'lost' }); await fill(page);
  await page.getByRole('button', { name: '签发私密邀请' }).click();
  await expect(page.getByRole('alert')).toContainText('签发结果未确认');
  await page.reload();
  await expect(page.getByText('上次交付需要核对')).toBeVisible();
  await expect(page.getByRole('button', { name: '签发私密邀请' })).toBeDisabled();
  expect(fixture.calls).toHaveLength(1);
  await expect(page.getByRole('button', { name: '重试同一次签发' })).toHaveCount(0);
  await page.getByRole('button', { name: '取消这次未交付邀请' }).click();
  await expect(page.getByText('本次未交付邀请已取消；迟到的签发请求也不能重新激活它。')).toBeVisible();
  expect(fixture.cancellations).toEqual([fixture.identities[0]]);
  expect(fixture.calls).toHaveLength(1);
});

test('leaving page clears volatile code but preserves non-secret delivery checkpoint', async ({ page }) => {
  const fixture = await boot(page); await fill(page);
  await page.getByRole('button', { name: '签发私密邀请' }).click();
  await expect(page.getByRole('button', { name: '下载私密邀请 JSON' })).toBeVisible();
  await page.getByRole('button', { name: '切换页面' }).click();
  await page.getByRole('button', { name: '切换页面' }).click();
  await expect(page.getByText('上次交付需要核对')).toBeVisible();
  await expect(page.getByRole('button', { name: '下载私密邀请 JSON' })).toHaveCount(0);
  expect(fixture.calls).toHaveLength(1);
});

test('one invitation creates member and explicit project scope without another admin action', async ({ page }, testInfo) => {
  const fixture = await boot(page, { scoped: true });
  await page.getByLabel('创建新成员并同时邀请').check();
  await page.getByLabel('新成员 ID', { exact: true }).fill('new-colleague');
  await page.getByLabel('新成员姓名', { exact: true }).fill('新同事');
  await page.getByLabel('独立 HTTPS 接入地址').fill('https://enrollment.example');
  await expect(page.getByRole('button', { name: '签发私密邀请' })).toBeDisabled();
  await page.getByLabel('scope-project / fixed-profile', { exact: true }).check();
  await expect(page.getByRole('button', { name: '签发私密邀请' })).toBeDisabled();
  await page.getByLabel('明确授权该成员就绪后参与上述项目的当前信任范围；不授予全局可信机器标签。').check();
  await page.getByLabel('授权 CPU 上限', { exact: true }).fill('3');
  await page.getByRole('button', { name: '签发私密邀请' }).click();
  await expect(page.getByRole('button', { name: '下载私密邀请 JSON' })).toBeVisible();
  expect(fixture.calls).toHaveLength(1);
  expect(fixture.calls[0].new_member_display_name).toBe('新同事');
  expect(fixture.calls[0].owner_user_id).toBe('new-colleague');
  expect(fixture.calls[0].conditional_admission.project_profiles).toEqual({ 'scope-project': ['fixed-profile'] });
  expect(fixture.calls[0].conditional_admission.max_cpus).toBe(3);
  expect(fixture.calls[0].conditional_admission.max_concurrent_units).toBe(1);
  expect(fixture.calls[0].conditional_admission.acknowledge_project_trust).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBeTruthy();
  await page.screenshot({ path: testInfo.outputPath('scoped-invitation.png'), fullPage: true });
});

test('uncertain scoped invitation retries unchanged scope and member', async ({ page }) => {
  const fixture = await boot(page, { mode: 'lost-once', scoped: true }); await fill(page);
  await page.getByLabel('scope-project / fixed-profile', { exact: true }).check();
  await page.getByLabel('明确授权该成员就绪后参与上述项目的当前信任范围；不授予全局可信机器标签。').check();
  await page.getByRole('button', { name: '签发私密邀请' }).click();
  await expect(page.getByRole('alert')).toContainText('签发结果未确认');
  await expect(page.getByLabel('授权 CPU 上限', { exact: true })).toBeDisabled();
  await page.getByRole('button', { name: '重试同一次签发' }).click();
  await expect(page.getByRole('button', { name: '下载私密邀请 JSON' })).toBeVisible();
  expect(fixture.calls[1]).toEqual(fixture.calls[0]);
  expect(fixture.identities[1]).toBe(fixture.identities[0]);
});

test('plain HTTP and member without worker role cannot issue worker invitation', async ({ page }) => {
  const fixture = await boot(page, { protocol: 'http:' }); await fill(page);
  await expect(page.getByLabel('获邀成员').locator('option[value="plain"]')).toHaveCount(0);
  await expect(page.getByRole('button', { name: '签发私密邀请' })).toBeDisabled();
  expect(fixture.calls).toHaveLength(0);
});

test('malformed successful response is not downloadable or echoed', async ({ page }) => {
  await boot(page, { mode: 'bad' }); await fill(page);
  await page.getByRole('button', { name: '签发私密邀请' }).click();
  await expect(page.getByRole('alert')).toContainText('签发结果未确认');
  await expect(page.getByRole('button', { name: '下载私密邀请 JSON' })).toHaveCount(0);
  expect(await page.locator('body').innerText()).not.toContain('must-not-render');
});

test('lost response retries the same frozen operation and privately downloads the one invitation', async ({ page }) => {
  const fixture = await boot(page, { mode: 'lost-once' }); await fill(page);
  await page.getByRole('button', { name: '签发私密邀请' }).click();
  await expect(page.getByRole('alert')).toContainText('签发结果未确认');
  await page.getByRole('button', { name: '重试同一次签发' }).click();
  await expect(page.getByRole('button', { name: '下载私密邀请 JSON' })).toBeVisible();
  expect(fixture.calls).toHaveLength(2);
  expect(fixture.calls[1]).toEqual(fixture.calls[0]);
  expect(fixture.identities[1]).toBe(fixture.identities[0]);
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: '下载私密邀请 JSON' }).click();
  const saved = JSON.parse(await readFile(await (await download).path(), 'utf8'));
  expect(saved.enrollment_code).toBe(fixture.code);
  await page.getByRole('button', { name: '已私下交付，清除页面凭据' }).click();
  expect(await page.evaluate(() => sessionStorage.getItem('rcn-member-invitation-pending:admin'))).toBeNull();
});

test('late success from an unmounted page cannot restore a cancelled checkpoint', async ({ page }) => {
  const fixture = await boot(page, { mode: 'late' }); await fill(page);
  await page.getByRole('button', { name: '签发私密邀请' }).click();
  await expect.poll(() => fixture.calls.length).toBe(1);
  await page.getByRole('button', { name: '切换页面' }).click();
  await page.getByRole('button', { name: '切换页面' }).click();
  await page.getByRole('button', { name: '取消这次未交付邀请' }).click();
  await expect(page.getByText('本次未交付邀请已取消；迟到的签发请求也不能重新激活它。')).toBeVisible();
  const response = page.waitForResponse(reply => reply.request().method() === 'PUT');
  // Observe before releasing the response, not after the next request may have finished.
  const refreshed = page.waitForResponse(reply => new URL(reply.url()).pathname === '/v1/admin/enrollments');
  fixture.releaseLate(); await Promise.all([response, refreshed]);
  expect(await page.evaluate(() => sessionStorage.getItem('rcn-member-invitation-pending:admin'))).toBeNull();
  await page.reload();
  await expect(page.getByText('上次交付需要核对')).toHaveCount(0);
});

for (const mode of ['cancel-lost', 'cancel-bad']) {
  test(`${mode} cannot clear an uncertain operation or issue a replacement`, async ({ page }) => {
    const fixture = await boot(page, { mode }); await fill(page);
    await page.getByRole('button', { name: '签发私密邀请' }).click();
    await expect(page.getByRole('alert')).toContainText('签发结果未确认');
    await page.getByRole('button', { name: '取消这次未交付邀请' }).click();
    await expect(page.getByRole('alert')).toContainText('取消结果未确认');
    await expect(page.getByRole('button', { name: '签发私密邀请' })).toBeDisabled();
    expect(fixture.calls).toHaveLength(1);
    if (mode === 'cancel-lost') {
      await page.getByRole('button', { name: '取消这次未交付邀请' }).click();
      await expect(page.getByText('本次未交付邀请已取消；迟到的签发请求也不能重新激活它。')).toBeVisible();
      expect(fixture.cancellations).toEqual([fixture.identities[0], fixture.identities[0]]);
    }
  });
}
