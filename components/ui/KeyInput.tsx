"use client";

import { useEffect, useId, useState } from "react";
import { Check, X } from "lucide-react";
import { keyFingerprint, parsePrivateKeyInput, parsePublicKeyInput } from "@/lib/rsa";
import { StoredKey, useWallet } from "@/components/WalletContext";

export type ParsedKeyInfo =
  | { state: "empty" }
  | { state: "invalid"; error: string }
  | { state: "valid"; bits: number; fingerprint: string; textbookOnly: boolean };

/**
 * Parses a pasted key in the background so tools can show live feedback
 * (key size, fingerprint, missing prime factors) before the user commits
 * to an action. Parse failures are feedback too, not errors.
 */
export function useParsedKeyInfo(raw: string, kind: "public" | "private"): ParsedKeyInfo {
  const [info, setInfo] = useState<ParsedKeyInfo>({ state: "empty" });

  useEffect(() => {
    let cancelled = false;
    const trimmed = raw.trim();
    if (!trimmed) {
      setInfo({ state: "empty" });
      return;
    }

    const parse = kind === "public" ? parsePublicKeyInput : parsePrivateKeyInput;
    parse(trimmed)
      .then(async (record) => {
        const bits = BigInt(record.n).toString(2).length;
        const fingerprint = await keyFingerprint(record.n);
        if (!cancelled) {
          setInfo({
            state: "valid",
            bits,
            fingerprint,
            textbookOnly:
              kind === "private" &&
              !(
                (record as { p?: string }).p &&
                (record as { q?: string }).q
              ),
          });
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setInfo({
            state: "invalid",
            error: error instanceof Error ? error.message : "This key could not be parsed.",
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [raw, kind]);

  return info;
}

export function KeyStatusLine({ info, kind }: { info: ParsedKeyInfo; kind: "public" | "private" }) {
  if (info.state === "empty") {
    return null;
  }

  if (info.state === "invalid") {
    return <p className="mt-2 text-xs leading-4 text-zinc-600">{info.error}</p>;
  }

  return (
    <p className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs leading-4">
      <span className="inline-flex items-center gap-1 text-emerald-400">
        <Check className="h-3 w-3" />
        Valid {info.bits}-bit {kind} key
      </span>
      <span className="font-mono text-zinc-600">{info.fingerprint}</span>
      {info.textbookOnly && (
        <span className="text-amber-400">
          no p and q, so it only works for textbook decryption
        </span>
      )}
    </p>
  );
}

/**
 * Wallet identity picker shared by Encrypt, Decrypt, Sign, and Verify.
 * Renders nothing while the wallet is locked or empty, so the paste box
 * stays the primary path for people who skip the wallet entirely.
 */
export function WalletKeyPicker({
  selectedId,
  onSelect,
}: {
  selectedId: string;
  onSelect: (key: StoredKey | null) => void;
}) {
  const { keys } = useWallet();
  const selectId = useId();

  if (keys.length === 0) {
    return null;
  }

  return (
    <div className="mb-4">
      <label className="field-label" htmlFor={selectId}>
        Wallet identity
      </label>
      <select
        id={selectId}
        value={selectedId}
        onChange={(event) =>
          onSelect(keys.find((key) => key.id === event.target.value) ?? null)
        }
        className="field-input"
      >
        <option value="">Paste a key below, or pick a saved identity</option>
        {keys.map((key) => (
          <option key={key.id} value={key.id}>
            {key.name}
          </option>
        ))}
      </select>
    </div>
  );
}

export function SelectedIdentityNotice({
  name,
  detail,
  onClear,
}: {
  name: string;
  detail: string;
  onClear: () => void;
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-indigo-500/25 bg-indigo-500/[0.06] px-3.5 py-3">
      <div className="min-w-0">
        <p className="truncate font-mono text-[13px] font-medium text-indigo-200">{name}</p>
        <p className="mt-0.5 text-xs leading-4 text-zinc-500">{detail}</p>
      </div>
      <button
        type="button"
        onClick={onClear}
        className="inline-flex h-7 shrink-0 items-center gap-1 rounded-md px-2 text-xs font-medium text-zinc-400 transition-colors duration-150 hover:bg-white/[0.06] hover:text-zinc-100"
      >
        <X className="h-3 w-3" />
        Clear
      </button>
    </div>
  );
}
