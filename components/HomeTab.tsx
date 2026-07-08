"use client";

import {
  ChevronRight,
  Clock,
  KeyRound,
  Lock,
  MessageSquare,
  PenTool,
  ShieldCheck,
  Unlock,
} from "lucide-react";
import { Button, Card, CardBody, StaggerGroup, StaggerItem } from "@/components/ui/Motion";

type ToolTab =
  | "keygen"
  | "encrypt"
  | "decrypt"
  | "sign"
  | "verify"
  | "network"
  | "history";

const TOOLS: {
  id: ToolTab;
  icon: typeof KeyRound;
  name: string;
  description: string;
}[] = [
  {
    id: "keygen",
    icon: KeyRound,
    name: "Keys",
    description: "Generate 1024 to 4096-bit RSA pairs with JSON and PEM export.",
  },
  {
    id: "encrypt",
    icon: Lock,
    name: "Encrypt",
    description: "Turn plaintext into a segmented payload with OAEP or textbook RSA.",
  },
  {
    id: "decrypt",
    icon: Unlock,
    name: "Decrypt",
    description: "Rebuild the plaintext and see exactly which segments failed.",
  },
  {
    id: "sign",
    icon: PenTool,
    name: "Sign",
    description: "Create RSA-PSS signatures over any message with SHA-256.",
  },
  {
    id: "verify",
    icon: ShieldCheck,
    name: "Verify",
    description: "Check whether a signature matches a message and public key.",
  },
  {
    id: "network",
    icon: MessageSquare,
    name: "Peer chat",
    description: "Connect two browsers over WebRTC and chat with RSA-encrypted messages.",
  },
  {
    id: "history",
    icon: Clock,
    name: "History",
    description: "Review this session's operations. Cleared on refresh by design.",
  },
];

const FIRST_RUN_STEPS = [
  {
    title: "Create a key pair",
    body: "2048 bits is a good default. Save it to the wallet so every tool can use it.",
  },
  {
    title: "Round-trip a message",
    body: "Encrypt something, then follow the payload straight into Decrypt with one click.",
  },
  {
    title: "Prove authorship",
    body: "Sign a message, check it in Verify, then change one character and watch it fail.",
  },
  {
    title: "Go peer to peer",
    body: "Open Peer chat in two windows, swap IDs, and compare key fingerprints.",
  },
];

export default function HomeTab({ onSelectTab }: { onSelectTab: (tabId: ToolTab) => void }) {
  return (
    <StaggerGroup className="space-y-10 py-2 sm:py-6">
      <StaggerItem>
        <div className="max-w-2xl">
          <h1 className="text-3xl font-semibold tracking-tight text-zinc-50 sm:text-4xl">
            Learn RSA by actually using it.
          </h1>
          <p className="mt-4 text-base leading-7 text-zinc-400">
            Generate keys, encrypt and sign messages, then chat over an encrypted peer
            connection. It all runs in your browser.
          </p>
          <div className="mt-6 flex flex-wrap items-center gap-3">
            <Button onClick={() => onSelectTab("keygen")}>
              <KeyRound className="h-4 w-4" />
              Generate a key pair
            </Button>
            <Button variant="secondary" onClick={() => onSelectTab("network")}>
              <MessageSquare className="h-4 w-4" />
              Try peer chat
            </Button>
          </div>
        </div>
      </StaggerItem>

      <StaggerItem>
        <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr] lg:gap-5">
          <Card>
            <CardBody>
              <h2 className="text-[15px] font-semibold tracking-tight text-zinc-100">
                A sensible first run
              </h2>
              <ol className="mt-4 space-y-4">
                {FIRST_RUN_STEPS.map((step, index) => (
                  <li key={step.title} className="flex gap-3.5">
                    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-white/10 bg-white/[0.04] font-mono text-xs text-zinc-400">
                      {index + 1}
                    </span>
                    <div className="min-w-0 pt-0.5">
                      <p className="text-sm font-medium text-zinc-200">{step.title}</p>
                      <p className="mt-0.5 text-[13px] leading-5 text-zinc-500">{step.body}</p>
                    </div>
                  </li>
                ))}
              </ol>
            </CardBody>
          </Card>

          <div className="flex flex-col gap-4 lg:gap-5">
            <Card className="flex-1">
              <CardBody>
                <h2 className="text-[15px] font-semibold tracking-tight text-zinc-100">
                  What runs where
                </h2>
                <div className="mt-4 space-y-4 text-[13px] leading-6">
                  <div>
                    <p className="font-medium text-zinc-300">On this device</p>
                    <p className="mt-0.5 text-zinc-500">
                      Key generation, encryption, decryption, signing, and wallet storage. Keys
                      never leave the browser unless you export them.
                    </p>
                  </div>
                  <div>
                    <p className="font-medium text-zinc-300">Over the network</p>
                    <p className="mt-0.5 text-zinc-500">
                      Peer chat uses a PeerJS server so two browsers can find each other. The
                      messages themselves travel directly between peers, encrypted with the
                      recipient&apos;s public key.
                    </p>
                  </div>
                </div>
              </CardBody>
            </Card>

            <Card>
              <CardBody>
                <h2 className="text-[15px] font-semibold tracking-tight text-zinc-100">
                  About textbook RSA
                </h2>
                <p className="mt-2 text-[13px] leading-6 text-zinc-500">
                  The Encrypt tab includes a raw, unpadded mode. It exists to show why padding
                  matters: without it, identical plaintexts produce identical ciphertexts. Use
                  OAEP for anything you care about.
                </p>
              </CardBody>
            </Card>
          </div>
        </div>
      </StaggerItem>

      <StaggerItem>
        <h2 className="text-[15px] font-semibold tracking-tight text-zinc-100">The tools</h2>
        <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
          {TOOLS.map((tool) => {
            const Icon = tool.icon;
            return (
              <button
                key={tool.id}
                type="button"
                onClick={() => onSelectTab(tool.id)}
                title={tool.description}
                className="group flex items-center gap-3.5 rounded-xl border border-white/[0.08] bg-surface px-4 py-3.5 text-left transition-colors duration-150 hover:border-white/[0.16] hover:bg-surface-raised"
              >
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.04] text-zinc-400 transition-colors duration-150 group-hover:text-indigo-300">
                  <Icon className="h-4 w-4" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium text-zinc-200">{tool.name}</span>
                  <span className="mt-0.5 block truncate text-[13px] text-zinc-500">
                    {tool.description}
                  </span>
                </span>
                <ChevronRight className="h-4 w-4 shrink-0 text-zinc-700 transition-colors duration-150 group-hover:text-zinc-400" />
              </button>
            );
          })}
        </div>
      </StaggerItem>
    </StaggerGroup>
  );
}
