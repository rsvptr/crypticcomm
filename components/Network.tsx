"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Peer, { DataConnection } from "peerjs";
import {
  Check,
  Copy,
  MessageSquare,
  Network as NetworkIcon,
  RefreshCcw,
  Send,
  ShieldCheck,
  Users,
} from "lucide-react";
import {
  decryptSegmentOAEP,
  dictToPrivJwk,
  dictToPubJwk,
  encryptSegmentOAEP,
  segmentMessage,
} from "@/lib/rsa";
import { useToast } from "@/components/ToastContext";
import { useWallet } from "@/components/WalletContext";
import { Card, FadeIn, NeonButton } from "@/components/ui/Motion";

interface ChatMessage {
  id: string;
  sender: "me" | "peer";
  text: string;
  timestamp: number;
}

interface PeerPayload {
  type: "PUB_KEY" | "MSG";
  key?: { n: string; e: string };
  encrypted?: { segments: string[]; oaep: boolean };
}

export default function NetworkTab() {
  const { keys, isLocked } = useWallet();
  const toast = useToast();
  const [selectedKeyId, setSelectedKeyId] = useState("");
  const [peerId, setPeerId] = useState("");
  const [remotePeerId, setRemotePeerId] = useState("");
  const [connection, setConnection] = useState<DataConnection | null>(null);
  const [peerPubKey, setPeerPubKey] = useState<{ n: string; e: string } | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputText, setInputText] = useState("");
  const [copied, setCopied] = useState(false);
  const [status, setStatus] = useState("Disconnected");

  const peerInstance = useRef<Peer | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const selectedKey = useMemo(
    () => keys.find((key) => key.id === selectedKeyId),
    [keys, selectedKeyId]
  );

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    return () => {
      peerInstance.current?.destroy();
    };
  }, []);

  const resetSession = (preserveIdentity = true) => {
    connection?.close();
    peerInstance.current?.destroy();
    peerInstance.current = null;
    setPeerId("");
    setRemotePeerId("");
    setConnection(null);
    setPeerPubKey(null);
    setMessages([]);
    setInputText("");
    setStatus("Disconnected");

    if (!preserveIdentity) {
      setSelectedKeyId("");
    }
  };

  const sendPublicKey = (conn: DataConnection) => {
    const publicKey = selectedKey?.keys.public;
    if (!publicKey) {
      return;
    }

    conn.send({ type: "PUB_KEY", key: publicKey } satisfies PeerPayload);
  };

  const receiveMessage = async (encryptedPayload?: { segments: string[]; oaep: boolean }) => {
    if (!encryptedPayload?.segments?.length || !selectedKey?.keys.private) {
      return;
    }

    try {
      const privJwk = dictToPrivJwk(selectedKey.keys.private);
      const decryptedSegments = await Promise.all(
        encryptedPayload.segments.map((segment) => decryptSegmentOAEP(segment, privJwk))
      );
      const failedSegments = decryptedSegments.filter((segment) =>
        segment.startsWith("[Decryption error:")
      );

      setMessages((current) => [
        ...current,
        {
          id: crypto.randomUUID(),
          sender: "peer",
          text:
            failedSegments.length > 0
              ? `${decryptedSegments
                  .filter((segment) => !segment.startsWith("[Decryption error:"))
                  .join("")}\n\n[One or more segments could not be decrypted.]`.trim()
              : decryptedSegments.join(""),
          timestamp: Date.now(),
        },
      ]);

      if (failedSegments.length > 0) {
        toast.error({
          title: "Incoming message was incomplete",
          description:
            "At least one encrypted segment could not be decrypted with the selected identity.",
        });
      }
    } catch (error) {
      setMessages((current) => [
        ...current,
        {
          id: crypto.randomUUID(),
          sender: "peer",
          text: "[Decryption failed]",
          timestamp: Date.now(),
        },
      ]);
      toast.error({
        title: "Incoming message failed",
        description:
          error instanceof Error ? error.message : "The payload could not be decrypted.",
      });
    }
  };

  const attachConnection = (conn: DataConnection, origin: "incoming" | "outgoing") => {
    setConnection(conn);
    setStatus(origin === "incoming" ? "Incoming peer detected..." : "Opening secure channel...");

    conn.on("open", () => {
      setStatus("Secure channel established");
      sendPublicKey(conn);
      toast.success({
        title: "Peer connected",
        description: "Public keys are now being exchanged for encrypted chat.",
      });
    });

    conn.on("data", async (raw) => {
      const data = raw as PeerPayload;

      if (data.type === "PUB_KEY" && data.key?.n && data.key?.e) {
        setPeerPubKey(data.key);
        setStatus("Peer key verified");
        return;
      }

      if (data.type === "MSG") {
        await receiveMessage(data.encrypted);
      }
    });

    conn.on("close", () => {
      setConnection(null);
      setPeerPubKey(null);
      setStatus("Disconnected");
      toast.info({
        title: "Peer disconnected",
        description: "The secure channel was closed.",
      });
    });

    conn.on("error", (error) => {
      setStatus(`Connection error: ${error.message}`);
      toast.error({
        title: "Connection error",
        description: error.message,
      });
    });
  };

  const initPeer = () => {
    if (!selectedKeyId) {
      toast.info({
        title: "Choose an identity first",
        description: "Select a saved key so the network tab can exchange your public key.",
      });
      return;
    }

    resetSession(true);
    setStatus("Initializing local node...");

    const peer = new Peer();
    peer.on("open", (id) => {
      setPeerId(id);
      setStatus("Waiting for peer...");
    });
    peer.on("connection", (conn) => attachConnection(conn, "incoming"));
    peer.on("disconnected", () => setStatus("Peer server disconnected"));
    peer.on("error", (error) => {
      setStatus(`Network error: ${error.message}`);
      toast.error({
        title: "Network error",
        description: error.message,
      });
    });

    peerInstance.current = peer;
  };

  const connectToPeer = () => {
    if (!peerInstance.current || !remotePeerId.trim()) {
      return;
    }

    const conn = peerInstance.current.connect(remotePeerId.trim());
    attachConnection(conn, "outgoing");
  };

  const sendMessage = async () => {
    if (!connection || !peerPubKey || !inputText.trim()) {
      return;
    }

    const plainText = inputText.trim();
    setInputText("");

    try {
      const pubJwk = dictToPubJwk(peerPubKey.n, peerPubKey.e);
      const modulus = BigInt(peerPubKey.n);
      const keyBits = modulus.toString(2).length;
      const keyBytes = Math.ceil(keyBits / 8);
      const maxSegBytes = keyBytes - 66;
      const segments = segmentMessage(plainText, maxSegBytes > 0 ? maxSegBytes : 32);
      const encryptedSegments = await Promise.all(
        segments.map((segment) => encryptSegmentOAEP(segment, pubJwk))
      );

      connection.send({
        type: "MSG",
        encrypted: { segments: encryptedSegments, oaep: true },
      } satisfies PeerPayload);

      setMessages((current) => [
        ...current,
        { id: crypto.randomUUID(), sender: "me", text: plainText, timestamp: Date.now() },
      ]);
    } catch (error) {
      toast.error({
        title: "Message failed",
        description: error instanceof Error ? error.message : "Encryption could not complete.",
      });
    }
  };

  const copyPeerId = async () => {
    if (!peerId) {
      return;
    }

    try {
      await navigator.clipboard.writeText(peerId);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
      toast.success({
        title: "Peer ID copied",
        description: "Share it with your partner to establish a secure channel.",
      });
    } catch {
      toast.error({
        title: "Copy failed",
        description: "Clipboard access was blocked by the browser.",
      });
    }
  };

  const statusTone = peerPubKey
    ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-200"
    : connection
      ? "border-amber-500/20 bg-amber-500/10 text-amber-100"
      : "border-white/10 bg-white/5 text-slate-300";

  return (
    <div className="space-y-6">
      <FadeIn className="grid grid-cols-1 gap-6 xl:grid-cols-[360px_minmax(0,1fr)]">
        <Card className="space-y-6 px-5 py-6">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
              Peer setup
            </p>
            <h2 className="mt-2 flex items-center gap-2 text-2xl font-semibold tracking-tight text-white">
              <Users className="h-5 w-5 text-cyan-300" />
              Secure channel
            </h2>
            <p className="mt-3 text-sm leading-7 text-slate-400">
              Choose an identity, initialize your peer node, then exchange IDs with a partner.
              CrypticComm shares public keys automatically after the connection opens.
            </p>
          </div>

          <div className="space-y-4">
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">
                1. Select identity
              </label>
              {isLocked ? (
                <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
                  Unlock your wallet to pick a saved identity for chat.
                </div>
              ) : keys.length === 0 ? (
                <div className="rounded-2xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
                  Save a generated key to the wallet before using the network tab.
                </div>
              ) : (
                <select
                  value={selectedKeyId}
                  onChange={(event) => setSelectedKeyId(event.target.value)}
                  disabled={!!peerId}
                  className="field-input"
                >
                  <option value="">Choose a wallet identity</option>
                  {keys.map((key) => (
                    <option key={key.id} value={key.id}>
                      {key.name}
                    </option>
                  ))}
                </select>
              )}
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <NeonButton
                onClick={initPeer}
                disabled={!selectedKeyId || isLocked}
                className="w-full"
              >
                <NetworkIcon className="h-4 w-4" />
                {peerId ? "Reinitialize node" : "Initialize node"}
              </NeonButton>
              <NeonButton
                variant="secondary"
                onClick={() => resetSession(false)}
                disabled={!peerId && !connection}
                className="w-full"
              >
                <RefreshCcw className="h-4 w-4" />
                Reset session
              </NeonButton>
            </div>

            <div className={`rounded-[24px] border px-4 py-4 ${statusTone}`}>
              <div className="flex items-center justify-between gap-3">
                <span className="text-[11px] font-semibold uppercase tracking-[0.26em]">
                  Status
                </span>
                {peerPubKey && (
                  <span className="status-badge border-emerald-500/20 bg-emerald-500/10 text-emerald-100">
                    <ShieldCheck className="h-3.5 w-3.5" />
                    Peer key verified
                  </span>
                )}
              </div>
              <p className="mt-3 text-sm font-medium">{status}</p>
            </div>

            {peerId && (
              <div className="rounded-[24px] border border-white/10 bg-white/5 p-4">
                <label className="mb-2 block text-sm font-medium text-slate-300">
                  2. Share your peer ID
                </label>
                <div className="flex gap-2">
                  <input readOnly value={peerId} className="field-input font-mono text-xs" />
                  <button
                    type="button"
                    onClick={copyPeerId}
                    className="icon-btn shrink-0"
                    aria-label="Copy peer ID"
                  >
                    {copied ? (
                      <Check className="h-4 w-4 text-emerald-300" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </button>
                </div>
              </div>
            )}

            {peerId && !connection && (
              <div className="rounded-[24px] border border-white/10 bg-white/5 p-4">
                <label className="mb-2 block text-sm font-medium text-slate-300">
                  3. Connect to a peer
                </label>
                <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_152px]">
                  <input
                    value={remotePeerId}
                    onChange={(event) => setRemotePeerId(event.target.value)}
                    placeholder="Paste the remote peer ID"
                    className="field-input font-mono text-xs"
                  />
                  <NeonButton onClick={connectToPeer} disabled={!remotePeerId.trim()} className="w-full">
                    Connect
                  </NeonButton>
                </div>
              </div>
            )}
          </div>
        </Card>

        <Card className="flex min-h-[620px] flex-col border-cyan-400/20 px-5 py-6">
          <div className="mb-5 flex flex-col gap-4 border-b border-white/10 pb-5 md:flex-row md:items-start md:justify-between">
            <div>
              <h2 className="flex items-center gap-2 text-2xl font-semibold tracking-tight text-white">
                <MessageSquare className="h-5 w-5 text-cyan-300" />
                Encrypted chat
              </h2>
              <p className="mt-2 max-w-2xl text-sm leading-7 text-slate-400">
                Every outgoing message is encrypted with the remote public key before it leaves
                your browser.
              </p>
            </div>
            <div className="inline-flex h-12 items-center rounded-2xl border border-white/10 bg-white/5 px-4 text-sm font-medium text-slate-300">
              {messages.length} message{messages.length === 1 ? "" : "s"}
            </div>
          </div>

          <div className="flex-1 overflow-y-auto pr-1">
            {messages.length === 0 ? (
              <div className="flex min-h-[320px] h-full flex-col items-center justify-center rounded-[28px] border border-dashed border-white/10 bg-white/5 px-6 text-center">
                <NetworkIcon className="h-10 w-10 text-slate-600" />
                <h3 className="mt-4 text-2xl font-semibold tracking-tight text-white">
                  No secure messages yet
                </h3>
                <p className="mt-3 max-w-md text-sm leading-7 text-slate-400">
                  Once both peers exchange IDs and public keys, messages will appear here in an
                  encrypted conversation timeline.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {messages.map((message) => (
                  <div
                    key={message.id}
                    className={`flex ${message.sender === "me" ? "justify-end" : "justify-start"}`}
                  >
                    <div
                      className={`max-w-[85%] rounded-[26px] border px-4 py-3 ${
                        message.sender === "me"
                          ? "border-cyan-400/20 bg-[linear-gradient(135deg,rgba(34,211,238,0.18),rgba(67,97,238,0.22))] text-cyan-50"
                          : "border-white/10 bg-white/5 text-slate-100"
                      }`}
                    >
                      <p className="whitespace-pre-wrap text-sm leading-7">{message.text}</p>
                      <p className="mt-2 text-[11px] uppercase tracking-[0.24em] text-white/50">
                        {message.sender === "me" ? "You" : "Peer"} ·{" "}
                        {new Date(message.timestamp).toLocaleTimeString()}
                      </p>
                    </div>
                  </div>
                ))}
                <div ref={messagesEndRef} />
              </div>
            )}
          </div>

          <div className="mt-5 border-t border-white/10 pt-5">
            <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <p className="text-sm text-slate-400">
                {peerPubKey
                  ? "Peer public key received. Messages are ready to encrypt."
                  : "Chat will unlock after the peer public key arrives."}
              </p>
              {peerPubKey && (
                <span className="status-badge border-emerald-500/20 bg-emerald-500/10 text-emerald-100">
                  Ready
                </span>
              )}
            </div>

            <div className="rounded-[28px] border border-white/10 bg-[rgba(5,9,21,0.78)] p-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
              <textarea
                value={inputText}
                onChange={(event) => setInputText(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void sendMessage();
                  }
                }}
                rows={4}
                disabled={!connection || !peerPubKey}
                placeholder={
                  connection
                    ? "Type an encrypted message. Press Enter to send, Shift+Enter for a new line."
                    : "Initialize and connect to a peer first."
                }
                className="min-h-[156px] w-full resize-none border-0 bg-transparent px-3 py-2 font-mono text-sm leading-7 text-slate-100 placeholder:text-slate-500 focus:outline-none"
              />
              <div className="mt-3 flex flex-col gap-3 border-t border-white/10 px-1 pt-3 sm:flex-row sm:items-center sm:justify-between">
                <p className="text-xs leading-6 text-slate-500">
                  Press Enter to send. Use Shift+Enter for a new line.
                </p>
                <NeonButton
                  onClick={sendMessage}
                  disabled={!connection || !peerPubKey || !inputText.trim()}
                  className="w-full sm:w-auto sm:min-w-[150px]"
                >
                  <Send className="h-4 w-4" />
                  Send
                </NeonButton>
              </div>
            </div>
          </div>
        </Card>
      </FadeIn>
    </div>
  );
}
