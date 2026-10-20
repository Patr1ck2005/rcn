import { useCallback, useRef, useState } from "react";

// React's disabled state paints on the next render. The ref closes the gap
// between two clicks in the same frame, including form submissions.
export function useMutationGuard() {
  const locked = useRef(false);
  const [busy, setBusy] = useState(false);
  const run = useCallback(async (action, event) => {
    event?.preventDefault?.();
    if (locked.current) return;
    locked.current = true; setBusy(true);
    try { return await action(); }
    finally { locked.current = false; setBusy(false); }
  }, []);
  return { run, busy };
}
