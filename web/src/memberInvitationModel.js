// Only explicit invitation downloads contain a code. Never persist that code in
// web storage or include it in a URL, clipboard, error, DOM or audit message.
const id = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$/;
const keys = ['schema_version', 'enrollment_id', 'machine_id', 'owner_user_id', 'control_plane_url', 'worker', 'enrollment_code', 'expires_at'];

export const invitationOperationsPath = '/v1/admin/member-invitation-operations';

function freezeRequest(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeRequest));
  if (value && typeof value === 'object') return Object.freeze(Object.fromEntries(Object.entries(value).map(([key, item]) => [key, freezeRequest(item)])));
  return value;
}

export function newInvitationOperation(request, source = globalThis.crypto) {
  if (!source || typeof source.getRandomValues !== 'function') throw new Error('secure-random-unavailable');
  const identity = source.getRandomValues(new Uint8Array(16));
  const material = source.getRandomValues(new Uint8Array(32));
  return { operation_id: Array.from(identity, byte => byte.toString(16).padStart(2, '0')).join(''),
    request: freezeRequest({ ...request, delivery_secret: btoa(String.fromCharCode(...material))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') }) };
}

export function cancellationReceipt(value, identity) {
  if (!value || value.operation_id !== identity || value.existing_machine_revoked !== false
      || !((value.state === 'cancelled' && value.cancelled === true)
        || (value.state === 'registered' && value.cancelled === false))) throw new Error('invalid-cancellation-receipt');
  return value;
}

export function enrollmentOrigin(value) {
  if (typeof value !== 'string' || value.length > 512 || /\s|\\/.test(value)) throw new Error('invalid-origin');
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || !['', '/'].includes(url.pathname) || url.search || url.hash
      || /(^127\.|localhost\.?$|^0\.0\.0\.0$|^\[::1\]$)/i.test(url.hostname)) throw new Error('invalid-origin');
  return url.origin;
}

export function invitationDocument(value, request, now = Date.now()) {
  if (!value || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))
      || value.schema_version !== 2 || ['enrollment_id', 'machine_id', 'owner_user_id'].some(key => typeof value[key] !== 'string' || !id.test(value[key]))
      || value.owner_user_id !== request.owner_user_id || value.worker !== request.worker
      || enrollmentOrigin(value.control_plane_url) !== request.control_plane_url
      || typeof value.enrollment_code !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.enrollment_code)
      || typeof value.expires_at !== 'string' || !/(Z|[+-]\d\d:\d\d)$/.test(value.expires_at)
      || !Number.isFinite(Date.parse(value.expires_at)) || Date.parse(value.expires_at) <= now) {
    throw new Error('invalid-invitation-response');
  }
  return Object.fromEntries(keys.map(key => [key, value[key]]));
}

export function invitationState(item, now = Date.now()) {
  if (item.revoked_at) return '已撤销';
  if (item.used_at) return '已登记；不代表通过计算验收';
  const expiry = Date.parse(item.expires_at);
  return !Number.isFinite(expiry) ? '状态待核对' : expiry <= now ? '已过期' : '待成员登记';
}

export function pendingKey(actorId) {
  return `rcn-member-invitation-pending:${actorId}`;
}

export function pendingMetadata(value) {
  // Persist only non-secret delivery state. Whitelist also on rehydration.
  if (!value || !['issuing', 'awaiting-delivery'].includes(value.state)
      || typeof value.owner_user_id !== 'string' || !id.test(value.owner_user_id)
      || (value.enrollment_id != null && (typeof value.enrollment_id !== 'string' || !id.test(value.enrollment_id)))
      || typeof value.started_at !== 'string' || !Number.isFinite(Date.parse(value.started_at))) {
    throw new Error('invalid-delivery-checkpoint');
  }
  if (value.operation_id != null && (typeof value.operation_id !== 'string' || !/^[a-f0-9]{32}$/.test(value.operation_id))) {
    throw new Error('invalid-delivery-checkpoint');
  }
  return { state: value.state, owner_user_id: value.owner_user_id,
    enrollment_id: value.enrollment_id || null, started_at: value.started_at,
    ...(value.operation_id ? { operation_id: value.operation_id } : {}) };
}
