import Link from "next/link";
import Image from "next/image";
import favicon from "@/assets/favicon.png";

export default function NotFound() {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center px-4 text-center">
      <Image src={favicon} alt="" className="h-10 w-10 object-contain opacity-60" />
      <p className="mt-5 font-mono text-xs text-zinc-600">404</p>
      <h1 className="mt-1 text-xl font-semibold tracking-tight text-zinc-100">
        This page doesn&apos;t exist
      </h1>
      <p className="mt-2 max-w-sm text-sm leading-6 text-zinc-500">
        CrypticComm is a single-page app, so everything lives at the root. The link that
        brought you here is stale.
      </p>
      <Link
        href="/"
        className="mt-5 inline-flex h-10 items-center rounded-lg bg-indigo-600 px-4 text-sm font-medium text-white transition-colors duration-150 hover:bg-indigo-500"
      >
        Back to the workspace
      </Link>
    </main>
  );
}
