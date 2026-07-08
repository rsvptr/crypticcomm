"use client";

import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Clipboard helper shared by every tool. `copied` holds the tag of the last
 * successful copy for two seconds so buttons can flash a check mark.
 * Returns false when the browser blocks clipboard access, so callers can
 * surface an error toast.
 */
export function useCopy(resetAfterMs = 2000) {
  const [copied, setCopied] = useState<string | null>(null);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    return () => window.clearTimeout(timer.current);
  }, []);

  const copy = useCallback(
    async (text: string, tag = "default") => {
      try {
        await navigator.clipboard.writeText(text);
        setCopied(tag);
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => setCopied(null), resetAfterMs);
        return true;
      } catch {
        return false;
      }
    },
    [resetAfterMs]
  );

  return { copied, copy };
}
