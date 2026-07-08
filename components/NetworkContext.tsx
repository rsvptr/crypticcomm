"use client";

import {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import Peer, { DataConnection } from "peerjs";
import {
  decryptSegmentOAEP,
  dictToPrivJwk,
  dictToPubJwk,
  encryptSegmentOAEP,
  keyFingerprint,
  segmentMessage,
} from "@/lib/rsa";
import { useToast } from "@/components/ToastContext";
import { StoredKey, useWallet } from "@/components/WalletContext";

export interface ChatMessage {
  id: string;
  sender: "me" | "peer";
  text: string;
  timestamp: number;
  /** The encrypted segments that actually crossed the wire, for inspection. */
  segments?: string[];
}

interface PeerPayload {
  type: "PUB_KEY" | "MSG";
  key?: { n: string; e: string };
  encrypted?: { segments: string[]; oaep: boolean };
}

export type ChatState = "offline" | "waiting" | "connecting" | "ready";

interface NetworkContextType {
  selectedKeyId: string;
  setSelectedKeyId: (id: string) => void;
  peerId: string;
  remotePeerId: string;
  setRemotePeerId: (value: string) => void;
  connected: boolean;
  peerPubKey: { n: string; e: string } | null;
  myFingerprint: string | null;
  peerFingerprint: string | null;
  messages: ChatMessage[];
  status: string;
  chatState: ChatState;
  unread: number;
  clearUnread: () => void;
  initPeer: () => void;
  connectToPeer: () => void;
  sendMessage: (text: string) => Promise<boolean>;
  resetSession: (preserveIdentity?: boolean) => void;
}

const NetworkContext = createContext<NetworkContextType | undefined>(undefined);

/**
 * Owns the PeerJS session for the whole app, so an open chat survives moving
 * between tabs. The Network tab is just a view over this state.
 */
export function NetworkProvider({ children }: { children: ReactNode }) {
  const { keys, isLocked } = useWallet();
  const toast = useToast();

  const [selectedKeyId, setSelectedKeyId] = useState("");
  const [peerId, setPeerId] = useState("");
  const [remotePeerId, setRemotePeerId] = useState("");
  const [connected, setConnected] = useState(false);
  const [peerPubKey, setPeerPubKey] = useState<{ n: string; e: string } | null>(null);
  const [myFingerprint, setMyFingerprint] = useState<string | null>(null);
  const [peerFingerprint, setPeerFingerprint] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [status, setStatus] = useState("Not started");
  const [unread, setUnread] = useState(0);

  const peerInstance = useRef<Peer | null>(null);
  const connectionRef = useRef<DataConnection | null>(null);
  // Handlers outlive renders, so they read the selected identity through a
  // ref instead of a captured (and possibly stale) closure value.
  const selectedKeyRef = useRef<StoredKey | undefined>(undefined);
  const manualCloseRef = useRef(false);

  const selectedKey = useMemo(
    () => keys.find((key) => key.id === selectedKeyId),
    [keys, selectedKeyId]
  );

  useEffect(() => {
    selectedKeyRef.current = selectedKey;
  }, [selectedKey]);

  useEffect(() => {
    let cancelled = false;
    if (!selectedKey) {
      setMyFingerprint(null);
      return;
    }
    keyFingerprint(selectedKey.keys.public.n).then((fp) => {
      if (!cancelled) setMyFingerprint(fp);
    });
    return () => {
      cancelled = true;
    };
  }, [selectedKey]);

  useEffect(() => {
    let cancelled = false;
    if (!peerPubKey) {
      setPeerFingerprint(null);
      return;
    }
    keyFingerprint(peerPubKey.n).then((fp) => {
      if (!cancelled) setPeerFingerprint(fp);
    });
    return () => {
      cancelled = true;
    };
  }, [peerPubKey]);

  const resetSession = useCallback((preserveIdentity = true) => {
    manualCloseRef.current = true;
    connectionRef.current?.close();
    peerInstance.current?.destroy();
    peerInstance.current = null;
    connectionRef.current = null;
    window.setTimeout(() => {
      manualCloseRef.current = false;
    }, 500);

    setPeerId("");
    setRemotePeerId("");
    setConnected(false);
    setPeerPubKey(null);
    setMessages([]);
    setUnread(0);
    setStatus("Not started");

    if (!preserveIdentity) {
      setSelectedKeyId("");
    }
  }, []);

  // Locking the wallet pulls the private key out from under the session, so
  // end the session cleanly rather than letting incoming messages fail.
  useEffect(() => {
    if (isLocked && (peerInstance.current || connectionRef.current)) {
      resetSession(false);
      setStatus("Ended, wallet locked");
      toast.info({
        title: "Peer session ended",
        description: "The wallet was locked, which removes the chat identity from memory.",
      });
    }
  }, [isLocked, resetSession, toast]);

  const sendPublicKey = useCallback((conn: DataConnection) => {
    const publicKey = selectedKeyRef.current?.keys.public;
    if (!publicKey) {
      return;
    }

    conn.send({
      type: "PUB_KEY",
      key: { n: publicKey.n, e: publicKey.e },
    } satisfies PeerPayload);
  }, []);

  const receiveMessage = useCallback(
    async (encryptedPayload?: { segments: string[]; oaep: boolean }) => {
      const privateKey = selectedKeyRef.current?.keys.private;
      if (!encryptedPayload?.segments?.length || !privateKey) {
        return;
      }

      try {
        const privJwk = dictToPrivJwk(privateKey);
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
                    .join("")}\n\n[Some segments could not be decrypted.]`.trim()
                : decryptedSegments.join(""),
            timestamp: Date.now(),
            segments: encryptedPayload.segments,
          },
        ]);
        setUnread((count) => count + 1);

        if (failedSegments.length > 0) {
          toast.error({
            title: "Message arrived incomplete",
            description: "Some segments could not be decrypted with the selected identity.",
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
            segments: encryptedPayload.segments,
          },
        ]);
        setUnread((count) => count + 1);
        toast.error({
          title: "Incoming message failed",
          description:
            error instanceof Error ? error.message : "The payload could not be decrypted.",
        });
      }
    },
    [toast]
  );

  const attachConnection = useCallback(
    (conn: DataConnection, origin: "incoming" | "outgoing") => {
      connectionRef.current = conn;
      setConnected(true);
      setStatus(origin === "incoming" ? "Peer connecting" : "Opening channel");

      conn.on("open", () => {
        if (connectionRef.current !== conn) return;
        setStatus("Connected, exchanging keys");
        sendPublicKey(conn);
        toast.success({
          title: "Peer connected",
          description: "Public keys are being exchanged now.",
        });
      });

      conn.on("data", async (raw) => {
        if (connectionRef.current !== conn) return;
        const data = raw as PeerPayload;

        if (data.type === "PUB_KEY" && data.key?.n && data.key?.e) {
          setPeerPubKey(data.key);
          setStatus("Encrypted channel ready");
          return;
        }

        if (data.type === "MSG") {
          await receiveMessage(data.encrypted);
        }
      });

      conn.on("close", () => {
        if (connectionRef.current !== conn) return;
        connectionRef.current = null;
        setConnected(false);
        setPeerPubKey(null);
        setStatus("Disconnected");
        if (!manualCloseRef.current) {
          toast.info({
            title: "Peer disconnected",
            description: "The channel was closed on the other side.",
          });
        }
      });

      conn.on("error", (error) => {
        if (connectionRef.current !== conn) return;
        setStatus("Connection error");
        toast.error({
          title: "Connection error",
          description: error.message,
        });
      });
    },
    [receiveMessage, sendPublicKey, toast]
  );

  const initPeer = useCallback(() => {
    if (!selectedKeyRef.current) {
      toast.info({
        title: "Pick an identity first",
        description: "The node needs a key pair to exchange with the other peer.",
      });
      return;
    }

    resetSession(true);
    setStatus("Starting node");

    const peer = new Peer();
    // Guard every handler: destroy() fires 'disconnected' on the old
    // instance, which would otherwise clobber the new session's status.
    peer.on("open", (id) => {
      if (peerInstance.current !== peer) return;
      setPeerId(id);
      setStatus("Waiting for a peer");
    });
    peer.on("connection", (conn) => {
      if (peerInstance.current !== peer) return;
      // One conversation at a time: a second incoming connection must not
      // silently replace the session that is already running.
      if (connectionRef.current) {
        conn.on("open", () => conn.close());
        toast.info({
          title: "Connection refused",
          description: "Another peer tried to connect while this session is active.",
        });
        return;
      }
      attachConnection(conn, "incoming");
    });
    peer.on("disconnected", () => {
      if (peerInstance.current !== peer) return;
      setStatus("Signaling server lost");
    });
    peer.on("error", (error) => {
      if (peerInstance.current !== peer) return;
      setStatus("Network error");
      toast.error({
        title: "Network error",
        description: error.message,
      });
    });

    peerInstance.current = peer;
  }, [attachConnection, resetSession, toast]);

  const connectToPeer = useCallback(() => {
    const target = remotePeerId.trim();
    if (!peerInstance.current || !target) {
      return;
    }

    const conn = peerInstance.current.connect(target);
    attachConnection(conn, "outgoing");
  }, [attachConnection, remotePeerId]);

  const sendMessage = useCallback(
    async (text: string) => {
      const conn = connectionRef.current;
      const plainText = text.trim();
      if (!conn || !peerPubKey || !plainText) {
        return false;
      }

      try {
        const pubJwk = dictToPubJwk(peerPubKey.n, peerPubKey.e);
        const modulus = BigInt(peerPubKey.n);
        const keyBits = modulus.toString(2).length;
        const keyBytes = Math.ceil(keyBits / 8);
        const maxSegBytes = keyBytes - 66;

        if (maxSegBytes <= 0) {
          throw new Error("The peer's key is too small for OAEP encryption.");
        }

        const segments = segmentMessage(plainText, maxSegBytes);
        const encryptedSegments = await Promise.all(
          segments.map((segment) => encryptSegmentOAEP(segment, pubJwk))
        );

        conn.send({
          type: "MSG",
          encrypted: { segments: encryptedSegments, oaep: true },
        } satisfies PeerPayload);

        setMessages((current) => [
          ...current,
          {
            id: crypto.randomUUID(),
            sender: "me",
            text: plainText,
            timestamp: Date.now(),
            segments: encryptedSegments,
          },
        ]);
        return true;
      } catch (error) {
        toast.error({
          title: "Message not sent",
          description: error instanceof Error ? error.message : "Encryption failed.",
        });
        return false;
      }
    },
    [peerPubKey, toast]
  );

  const clearUnread = useCallback(() => setUnread(0), []);

  const chatState: ChatState = peerPubKey
    ? "ready"
    : connected
      ? "connecting"
      : peerId
        ? "waiting"
        : "offline";

  const value = useMemo<NetworkContextType>(
    () => ({
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
      unread,
      clearUnread,
      initPeer,
      connectToPeer,
      sendMessage,
      resetSession,
    }),
    [
      selectedKeyId,
      peerId,
      remotePeerId,
      connected,
      peerPubKey,
      myFingerprint,
      peerFingerprint,
      messages,
      status,
      chatState,
      unread,
      clearUnread,
      initPeer,
      connectToPeer,
      sendMessage,
      resetSession,
    ]
  );

  return <NetworkContext.Provider value={value}>{children}</NetworkContext.Provider>;
}

export function useNetwork() {
  const context = useContext(NetworkContext);
  if (!context) {
    throw new Error("useNetwork must be used within a NetworkProvider");
  }
  return context;
}
