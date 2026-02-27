"use client";

import { useState, useEffect, useRef } from "react";
import Peer, { DataConnection } from "peerjs";
import { useWallet } from "@/components/WalletContext";
import { Card, NeonButton, FadeIn } from "@/components/ui/Motion";
import { Network as NetworkIcon, Send, Copy, Check, Users, MessageSquare } from "lucide-react";
import { 
  segmentMessage, 
  encryptSegmentOAEP, 
  decryptSegmentOAEP,
  dictToPubJwk,
  dictToPrivJwk,
  RSAKeyDict
} from "@/lib/rsa";

interface ChatMessage {
  id: string;
  sender: "me" | "peer";
  text: string;
  timestamp: number;
}

export default function NetworkTab() {
  const { keys, isLocked } = useWallet();
  const [selectedKeyId, setSelectedKeyId] = useState<string>("");
  const [peerId, setPeerId] = useState<string>("");
  const [remotePeerId, setRemotePeerId] = useState<string>("");
  const [connection, setConnection] = useState<DataConnection | null>(null);
  const [peerPubKey, setPeerPubKey] = useState<any>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputText, setInputText] = useState("");
  const [copied, setCopied] = useState(false);
  const [status, setStatus] = useState<string>("Disconnected");

  const peerInstance = useRef<Peer | null>(null);

  useEffect(() => {
    return () => {
      if (peerInstance.current) {
        peerInstance.current.destroy();
      }
    };
  }, []);

  const initPeer = () => {
    if (!selectedKeyId) return alert("Please select an identity first.");
    
    const peer = new Peer();
    peer.on("open", (id) => {
      setPeerId(id);
      setStatus("Waiting for connection...");
    });

    peer.on("connection", (conn) => {
      handleConnection(conn);
    });

    peer.on("error", (err) => {
      setStatus(`Error: ${err.message}`);
    });

    peerInstance.current = peer;
  };

  const handleConnection = (conn: DataConnection) => {
    setConnection(conn);
    setStatus("Connected!");

    conn.on("open", () => {
      // Send our public key
      const myKey = keys.find(k => k.id === selectedKeyId)?.keys.public;
      conn.send({ type: "PUB_KEY", key: myKey });
    });

    conn.on("data", async (data: any) => {
      if (data.type === "PUB_KEY") {
        setPeerPubKey(data.key);
      } else if (data.type === "MSG") {
        await receiveMessage(data.encrypted);
      }
    });

    conn.on("close", () => {
      setStatus("Disconnected");
      setConnection(null);
      setPeerPubKey(null);
    });
  };

  const connectToPeer = () => {
    if (!peerInstance.current || !remotePeerId) return;
    const conn = peerInstance.current.connect(remotePeerId);
    handleConnection(conn);
  };

  const sendMessage = async () => {
    if (!connection || !inputText.trim() || !peerPubKey) return;
    
    const plainText = inputText;
    setInputText("");

    try {
      // Encrypt with peer's public key
      const pubJwk = dictToPubJwk(peerPubKey.n, peerPubKey.e);
      // Determine max segments based on key size (assuming 2048 roughly if unknown, but better to calculate)
      const nBig = BigInt(peerPubKey.n);
      const keyBytes = Math.floor(nBig.toString(2).length / 8);
      const maxSegBytes = keyBytes - 2 * 32 - 2;

      const segments = segmentMessage(plainText, maxSegBytes > 0 ? maxSegBytes : 32);
      const encryptedSegments = await Promise.all(segments.map(seg => encryptSegmentOAEP(seg, pubJwk)));

      const encryptedData = { segments: encryptedSegments, oaep: true };
      
      connection.send({ type: "MSG", encrypted: encryptedData });

      setMessages(prev => [...prev, { id: crypto.randomUUID(), sender: "me", text: plainText, timestamp: Date.now() }]);
    } catch (e: any) {
      alert("Encryption error: " + e.message);
    }
  };

  const receiveMessage = async (encryptedData: any) => {
    const myKey = keys.find(k => k.id === selectedKeyId)?.keys.private;
    if (!myKey) return;

    try {
      const privJwk = dictToPrivJwk(myKey as any);
      const decryptedSegments = await Promise.all(
        encryptedData.segments.map((seg: string) => decryptSegmentOAEP(seg, privJwk))
      );
      
      const plainText = decryptedSegments.join("");
      setMessages(prev => [...prev, { id: crypto.randomUUID(), sender: "peer", text: plainText, timestamp: Date.now() }]);
    } catch (e: any) {
      setMessages(prev => [...prev, { id: crypto.randomUUID(), sender: "peer", text: "[Decryption Failed]", timestamp: Date.now() }]);
    }
  };

  return (
    <div className="space-y-6">
      <FadeIn className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Settings Panel */}
        <Card className="lg:col-span-1 space-y-6">
          <div className="flex items-center gap-2 mb-4">
            <Users className="w-5 h-5 text-indigo-400" />
            <h2 className="text-xl font-semibold text-slate-100">Connection</h2>
          </div>

          <div>
            <label className="block text-sm text-slate-400 mb-2">1. Select Identity</label>
            {isLocked ? (
              <div className="text-sm text-red-400 p-2 bg-red-500/10 rounded border border-red-500/20">
                Please unlock your wallet first.
              </div>
            ) : keys.length === 0 ? (
              <div className="text-sm text-amber-400 p-2 bg-amber-500/10 rounded border border-amber-500/20">
                Generate a key pair first.
              </div>
            ) : (
              <select
                value={selectedKeyId}
                onChange={(e) => setSelectedKeyId(e.target.value)}
                disabled={!!peerId}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-sm text-slate-300 focus:ring-2 focus:ring-indigo-500 disabled:opacity-50"
              >
                <option value="">-- Choose Key --</option>
                {keys.map(k => <option key={k.id} value={k.id}>{k.name}</option>)}
              </select>
            )}
          </div>

          {!peerId ? (
            <NeonButton onClick={initPeer} disabled={!selectedKeyId || isLocked} className="w-full">
              Initialize Node
            </NeonButton>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-slate-400 mb-1">Your Peer ID</label>
                <div className="flex gap-2">
                  <input readOnly value={peerId} className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs font-mono text-slate-300" />
                  <button onClick={() => { navigator.clipboard.writeText(peerId); setCopied(true); setTimeout(()=>setCopied(false), 2000); }} className="p-2 bg-slate-800 rounded hover:bg-slate-700 text-slate-300">
                    {copied ? <Check className="w-4 h-4 text-emerald-400"/> : <Copy className="w-4 h-4"/>}
                  </button>
                </div>
              </div>

              {!connection && (
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Connect to Peer</label>
                  <div className="flex gap-2">
                    <input 
                      value={remotePeerId} 
                      onChange={e => setRemotePeerId(e.target.value)} 
                      placeholder="Enter remote Peer ID"
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs font-mono text-slate-300" 
                    />
                    <NeonButton onClick={connectToPeer} disabled={!remotePeerId} className="px-3 py-2">
                      Connect
                    </NeonButton>
                  </div>
                </div>
              )}

              <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 text-sm flex items-center justify-between">
                <span className="text-slate-400">Status</span>
                <span className={status === "Connected!" ? "text-emerald-400" : "text-amber-400"}>{status}</span>
              </div>
              
              {peerPubKey && (
                <div className="text-xs text-emerald-400/80 bg-emerald-500/10 p-2 rounded border border-emerald-500/20">
                  <Check className="w-3 h-3 inline mr-1"/> Peer Public Key received
                </div>
              )}
            </div>
          )}
        </Card>

        {/* Chat Panel */}
        <Card className="lg:col-span-2 flex flex-col h-[500px] border-indigo-500/30">
          <div className="flex items-center gap-2 mb-4 border-b border-slate-800 pb-4">
            <MessageSquare className="w-5 h-5 text-indigo-400" />
            <h2 className="text-xl font-semibold text-slate-100">Encrypted Chat</h2>
          </div>

          <div className="flex-1 overflow-y-auto space-y-4 mb-4 pr-2 custom-scrollbar">
            {messages.length === 0 ? (
              <div className="h-full flex items-center justify-center text-slate-500 text-sm">
                No messages yet. Connect to a peer to start chatting.
              </div>
            ) : (
              messages.map(msg => (
                <div key={msg.id} className={`flex ${msg.sender === "me" ? "justify-end" : "justify-start"}`}>
                  <div className={`max-w-[80%] rounded-2xl px-4 py-2 text-sm ${msg.sender === "me" ? "bg-indigo-600 text-white rounded-tr-sm" : "bg-slate-800 text-slate-200 rounded-tl-sm"}`}>
                    {msg.text}
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="flex gap-2 pt-4 border-t border-slate-800">
            <input
              type="text"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && sendMessage()}
              disabled={!connection || !peerPubKey}
              placeholder={connection ? "Type an encrypted message..." : "Connect to a peer first..."}
              className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-4 py-2 text-sm text-slate-200 focus:ring-2 focus:ring-indigo-500 focus:outline-none disabled:opacity-50"
            />
            <NeonButton onClick={sendMessage} disabled={!connection || !peerPubKey || !inputText.trim()} className="px-4">
              <Send className="w-4 h-4" />
            </NeonButton>
          </div>
        </Card>

      </FadeIn>
    </div>
  );
}