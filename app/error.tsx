"use client";

import Image from "next/image";
import favicon from "@/assets/favicon.png";

export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center px-4 text-center">
      <Image src={favicon} alt="" className="h-10 w-10 object-contain opacity-60" />
      <h1 className="mt-5 text-xl font-semibold tracking-tight text-zinc-100">
        Something went wrong
      </h1>
      <p className="mt-2 max-w-md text-sm leading-6 text-zinc-500">
        The page hit an unexpected error. Your wallet is untouched; it lives encrypted in
        localStorage and is only read when you unlock it.
      </p>
      {error?.message && (
        <p className="mt-3 max-w-md break-words rounded-lg border border-white/[0.06] bg-surface-inset px-3 py-2 font-mono text-xs leading-5 text-zinc-500">
          {error.message}
        </p>
      )}
      <button
        type="button"
        onClick={reset}
        className="mt-5 inline-flex h-10 items-center rounded-lg bg-indigo-600 px-4 text-sm font-medium text-white transition-colors duration-150 hover:bg-indigo-500"
      >
        Try again
      </button>
    </main>
  );
}
