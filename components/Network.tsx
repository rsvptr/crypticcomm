"use client";

import { useEffect, useId, useRef, useState } from "react";
import { motion } from "framer-motion";
import {
  Check,
  ChevronDown,
  Copy,
  Fingerprint,
  MessageSquare,
  Play,
  RotateCcw,
  Send,
} from "lucide-react";
import { useNetwork } from "@/components/NetworkContext";
import { useToast } from "@/components/ToastContext";
import { useWallet } from "@/components/WalletContext";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  Collapse,
  EmptyState,
  FadeIn,
  IconButton,
  SPRING_SOFT,
} from "@/components/ui/Motion";
import { useCopy } from "@/components/ui/useCopy";

export default function NetworkTab() {
  const { keys, isLocked } = useWallet();
  const {
    selectedKeyId,
    setSelectedKeyId,
    peerId,
    remotePeerId,
    setRemotePeerId,
    connected,
    peerPubKey,
    myFingerprint,
    peerFingerprint,
    messages,
    status,
    chatState,
    clearUnread,
    initPeer,
    connectToPeer,
    sendMessage,
    resetSession,
  } = useNetwork();
  const toast = useToast();
  const { copied, copy } = useCopy();
  const identitySelectId = useId();
  const remoteIdInputId = useId();

  const [inputText, setInputText] = useState("");
  const [openCipherId, setOpenCipherId] = useState<string | null>(null);

  const messageListRef = useRef<HTMLDivElement>(null);
  const prevCountRef = useRef(messages.length);
  // Messages from before this tab was (re)opened render without an entrance
  // animation; only genuinely new ones spring in.
  const mountTimeRef = useRef(Date.now());

  // The session lives in NetworkContext, so this view marks messages as seen
  // whenever it is open.
  useEffect(() => {
    clearUnread();
  }, [clearUnread, messages.length]);

  useEffect(() => {
    const list = messageListRef.current;
    if (list) {
      list.scrollTop = list.scrollHeight;
    }
  }, []);

  useEffect(() => {
    const list = messageListRef.current;
    const added = messages.length > prevCountRef.current;
    prevCountRef.current = messages.length;
    if (!list || !added) {
      return;
    }

    // Follow the conversation unless the reader has scrolled up on purpose.
    const distanceFromBottom = list.scrollHeight - list.scrollTop - list.clientHeight;
    const lastMessage = messages[messages.length - 1];
    if (lastMessage?.sender === "me" || distanceFromBottom < 160) {
      list.scrollTop = list.scrollHeight;
    }
  }, [messages]);

  const handleSend = async () => {
    const ok = await sendMessage(inputText);
    if (ok) {
      setInputText("");
    }
  };

  const copyPeerId = async () => {
    if (!peerId) {
      return;
    }

    const ok = await copy(peerId, "peer-id");
    if (!ok) {
      toast.error({
        title: "Copy failed",
        description: "The browser blocked clipboard access.",
      });
    }
  };

  return (
    <FadeIn className="grid gap-4 xl:grid-cols-[340px_minmax(0,1fr)]">
      <Card className="self-start">
        <CardHeader
          title="Connection"
          description="Both sides start a node, then one of them enters the other's ID. The session stays alive while you use other tabs."
        />
        <CardBody className="space-y-4">
          <div>
            <label className="field-label" htmlFor={identitySelectId}>
              1. Choose an identity
            </label>
            {isLocked ? (
              <div className="notice-neutral">
                Unlock the wallet from the header to pick a saved identity.
              </div>
            ) : keys.length === 0 ? (
              <div className="notice-neutral">
                The wallet is empty. Generate a key pair in the Keys tab and save it first.
              </div>
            ) : (
              <select
                id={identitySelectId}
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

          <div>
            <span className="field-label">2. Start your node</span>
            <div className="grid grid-cols-[minmax(0,1fr)_auto] gap-2">
              <Button onClick={initPeer} disabled={!selectedKeyId || isLocked}>
                <Play className="h-4 w-4" />
                {peerId ? "Restart node" : "Start node"}
              </Button>
              <Button
                variant="secondary"
                onClick={() => resetSession(false)}
                disabled={!peerId && !connected}
              >
                <RotateCcw className="h-4 w-4" />
                Reset
              </Button>
            </div>
          </div>

          {peerId && (
            <div>
              <span className="field-label">3. Share your peer ID</span>
              <div className="flex gap-2">
                <input
                  readOnly
                  value={peerId}
                  aria-label="Your peer ID"
                  className="field-input font-mono !text-xs"
                />
                <IconButton label="Copy peer ID" onClick={copyPeerId} className="h-10 w-10 shrink-0">
                  {copied === "peer-id" ? (
                    <Check className="h-4 w-4 animate-pop text-emerald-400" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </IconButton>
              </div>
            </div>
          )}

          {peerId && !connected && (
            <div>
              <label className="field-label" htmlFor={remoteIdInputId}>
                4. Or connect to a peer
              </label>
              <div className="flex gap-2">
                <input
                  id={remoteIdInputId}
                  value={remotePeerId}
                  onChange={(event) => setRemotePeerId(event.target.value)}
                  placeholder="Paste the remote peer ID"
                  className="field-input font-mono !text-xs"
                />
                <Button
                  variant="secondary"
                  onClick={connectToPeer}
                  disabled={!remotePeerId.trim()}
                  className="shrink-0"
                >
                  Connect
                </Button>
              </div>
              <p className="mt-1.5 text-xs leading-4 text-zinc-600">
                Only one side needs to do this step.
              </p>
            </div>
          )}

          <div className="flex items-center justify-between gap-3 border-t border-white/[0.06] pt-3.5">
            <span className="text-xs text-zinc-500">Status</span>
            <span
              className={
                chatState === "ready"
                  ? "chip-success"
                  : chatState === "offline"
                    ? "chip-neutral"
                    : "chip-warning"
              }
            >
              {status}
            </span>
          </div>

          {myFingerprint && (
            <div className="rounded-lg border border-white/[0.06] bg-surface-inset px-3.5 py-3">
              <p className="flex items-center gap-1.5 text-xs font-medium text-zinc-400">
                <Fingerprint className="h-3.5 w-3.5" />
                Key fingerprints
              </p>
              <dl className="mt-2.5 space-y-1.5 font-mono text-[11px] leading-4">
                <div className="flex items-baseline justify-between gap-3">
                  <dt className="shrink-0 text-zinc-600">You</dt>
                  <dd className="truncate text-zinc-300">{myFingerprint}</dd>
                </div>
                <div className="flex items-baseline justify-between gap-3">
                  <dt className="shrink-0 text-zinc-600">Peer</dt>
                  <dd className={peerFingerprint ? "truncate text-zinc-300" : "text-zinc-600"}>
                    {peerFingerprint ?? "waiting for key"}
                  </dd>
                </div>
              </dl>
              {peerFingerprint && (
                <p className="mt-2.5 text-[11px] leading-4 text-zinc-600">
                  Read these to each other over a call or in person. Matching fingerprints
                  rule out a swapped key in the middle.
                </p>
              )}
            </div>
          )}
        </CardBody>
      </Card>

      <Card className="flex min-h-[30rem] flex-col xl:min-h-[36rem]">
        <CardHeader
          title="Conversation"
          description="Messages are encrypted with the peer's public key before they leave this browser."
          actions={
            messages.length > 0 ? (
              <span className="chip-neutral">
                {messages.length} message{messages.length === 1 ? "" : "s"}
              </span>
            ) : undefined
          }
        />

        <div ref={messageListRef} className="flex-1 overflow-y-auto px-4 py-4 sm:px-5">
          {messages.length === 0 ? (
            <div className="flex h-full items-center justify-center">
              <EmptyState
                icon={<MessageSquare className="h-4 w-4" />}
                title="No messages yet"
                className="w-full max-w-sm border-none bg-transparent"
              >
                {chatState === "ready"
                  ? "The encrypted channel is up. Say something."
                  : "Once both peers are connected and keys are exchanged, the conversation shows up here."}
              </EmptyState>
            </div>
          ) : (
            <div className="space-y-3">
              {messages.map((message) => {
                const isNew = message.timestamp >= mountTimeRef.current;
                const cipherOpen = openCipherId === message.id;
                return (
                  <motion.div
                    key={message.id}
                    initial={isNew ? { opacity: 0, y: 10, scale: 0.97 } : false}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    transition={SPRING_SOFT}
                    className={`flex ${message.sender === "me" ? "justify-end" : "justify-start"}`}
                  >
                    <div
                      className={`max-w-[85%] rounded-xl px-3.5 py-2.5 sm:max-w-[70%] ${
                        message.sender === "me"
                          ? "bg-indigo-600/25 text-zinc-100"
                          : "border border-white/[0.06] bg-white/[0.04] text-zinc-200"
                      }`}
                    >
                      <p className="whitespace-pre-wrap break-words text-sm leading-6">
                        {message.text}
                      </p>
                      <div className="mt-1 flex items-center justify-between gap-3">
                        <p className="text-[11px] text-zinc-500">
                          {message.sender === "me" ? "You" : "Peer"},{" "}
                          {new Date(message.timestamp).toLocaleTimeString([], {
                            hour: "2-digit",
                            minute: "2-digit",
                          })}
                        </p>
                        {message.segments && message.segments.length > 0 && (
                          <button
                            type="button"
                            onClick={() => setOpenCipherId(cipherOpen ? null : message.id)}
                            aria-expanded={cipherOpen}
                            className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] text-zinc-500 transition-colors duration-150 hover:bg-white/[0.06] hover:text-zinc-300"
                          >
                            Ciphertext
                            <ChevronDown
                              className={`h-3 w-3 transition-transform duration-200 ${
                                cipherOpen ? "rotate-180" : ""
                              }`}
                            />
                          </button>
                        )}
                      </div>
                      {message.segments && (
                        <Collapse open={cipherOpen}>
                          <div className="mt-2 max-h-36 overflow-y-auto rounded-lg border border-white/[0.06] bg-surface-inset px-2.5 py-2">
                            <p className="mb-1 text-[10px] font-medium uppercase text-zinc-600">
                              As sent over the wire ({message.segments.length} RSA segment
                              {message.segments.length === 1 ? "" : "s"})
                            </p>
                            <p className="break-all font-mono text-[10px] leading-4 text-zinc-500">
                              {message.segments.join("\n\n")}
                            </p>
                          </div>
                        </Collapse>
                      )}
                    </div>
                  </motion.div>
                );
              })}
            </div>
          )}
        </div>

        <div className="border-t border-white/[0.06] p-3 sm:p-4">
          <div className="flex items-end gap-2">
            <textarea
              value={inputText}
              onChange={(event) => setInputText(event.target.value)}
              onKeyDown={(event) => {
                if (
                  event.key === "Enter" &&
                  !event.shiftKey &&
                  !event.nativeEvent.isComposing
                ) {
                  event.preventDefault();
                  void handleSend();
                }
              }}
              rows={2}
              disabled={!connected || !peerPubKey}
              placeholder={
                chatState === "ready"
                  ? "Type a message"
                  : "Connect to a peer to start chatting"
              }
              aria-label="Chat message"
              className="field-input min-h-[3.5rem] flex-1 resize-none font-sans"
            />
            <Button
              onClick={handleSend}
              disabled={!connected || !peerPubKey || !inputText.trim()}
              aria-label="Send message"
              className="h-10 w-12 shrink-0 px-0"
            >
              <Send className="h-4 w-4" />
            </Button>
          </div>
          <p className="mt-2 hidden text-xs text-zinc-600 sm:block">
            Enter sends. Shift+Enter adds a line break.
          </p>
        </div>
      </Card>
    </FadeIn>
  );
}
