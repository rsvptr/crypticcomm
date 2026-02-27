"use client";

import { useState } from "react";
import { generateRSAKey, RSAKeyDict, generateKeyName } from "@/lib/rsa";
import { Download, Copy, RefreshCw, Eye, EyeOff, Save, Check } from "lucide-react";
import { useWallet } from "@/components/WalletContext";
import { Card, NeonButton, FadeIn } from "@/components/ui/Motion";

export default function KeyGen() {
  const [keySize, setKeySize] = useState(2048);
  const [keys, setKeys] = useState<RSAKeyDict | null>(null);
  const [loading, setLoading] = useState(false);
  const [showPrivate, setShowPrivate] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [copied, setCopied] = useState<string | null>(null);
  
  const { saveKey } = useWallet();

  const handleGenerate = async () => {
    setLoading(true);
    setKeys(null);
    setKeyName("");
    try {
      const k = await generateRSAKey(keySize);
      const name = await generateKeyName(k.public);
      setKeyName(name);
      setKeys(k);
    } catch (e: any) {
      alert("Error generating keys: " + e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveToWallet = async () => {
    if (keys) {
      try {
        await saveKey(keys);
        alert("Key pair saved to browser wallet!");
      } catch (e: any) {
        alert("Could not save: " + e.message + ". Please unlock your wallet using the Wallet button in the header.");
      }
    }
  };

  const downloadJson = (data: object, suffix: string) => {
    const safeName = keyName.replace(/[^a-zA-Z0-9]/g, "_").replace(/_+/g, "_");
    const filename = `${safeName}_${suffix}.json`;
    
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const copyToClipboard = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopied(type);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="space-y-6">
      <FadeIn>
        <Card className="flex flex-col sm:flex-row gap-4 items-end bg-gradient-to-r from-slate-900 to-indigo-950/30">
          <div className="flex-1 w-full">
            <label className="block text-sm font-medium text-slate-400 mb-2">
              Key Strength (bits)
            </label>
            <select
              value={keySize}
              onChange={(e) => setKeySize(Number(e.target.value))}
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-colors"
            >
              <option value={1024}>1024 (Weak - Demo)</option>
              <option value={2048}>2048 (Standard Secure)</option>
              <option value={4096}>4096 (Military Grade)</option>
            </select>
          </div>
          
          <NeonButton
            onClick={handleGenerate}
            disabled={loading}
            className="w-full sm:w-auto h-[42px] relative"
          >
            {loading ? (
              <div className="flex items-center gap-2">
                <RefreshCw className="w-4 h-4 animate-spin" /> 
                Generating...
              </div>
            ) : (
              "Generate New Keys"
            )}
            {loading && keySize === 4096 && (
              <span className="absolute -bottom-6 left-1/2 -translate-x-1/2 whitespace-nowrap text-[10px] text-amber-400">
                This may take a few seconds...
              </span>
            )}
          </NeonButton>
        </Card>
      </FadeIn>

      {keys && (
        <FadeIn delay={0.2} className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="lg:col-span-2 flex justify-center">
              <div className="inline-flex items-center gap-2 px-4 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-sm animate-pulse">
                  <span>Identity Generated:</span>
                  <span className="font-bold text-white">{keyName}</span>
              </div>
          </div>

          {/* Public Key Card */}
          <Card className="flex flex-col h-full border-t-4 border-t-emerald-500">
            <div className="flex justify-between items-start mb-4">
              <div>
                <h3 className="text-lg font-medium text-emerald-400">Public Key</h3>
                <p className="text-xs text-slate-500 mt-1">Safe to share.</p>
              </div>
              <div className="flex gap-2">
                <button 
                    onClick={() => copyToClipboard(JSON.stringify(keys.public, null, 2), "public")} 
                    className="icon-btn" 
                    title="Copy JSON"
                >
                    {copied === "public" ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
                <button 
                    onClick={() => downloadJson(keys.public, "Public")} 
                    className="icon-btn" 
                    title="Download JSON"
                >
                    <Download className="w-4 h-4" /> <span className="text-[10px] ml-1">JSON</span>
                </button>
                {keys.public.pem && (
                  <button 
                      onClick={() => {
                        const blob = new Blob([keys.public.pem as string], { type: "text/plain" });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url;
                        a.download = `${keyName.replace(/[^a-zA-Z0-9]/g, "_").replace(/_+/g, "_")}_Public.pem`;
                        a.click();
                      }}
                      className="icon-btn" 
                      title="Download PEM"
                  >
                      <Download className="w-4 h-4" /> <span className="text-[10px] ml-1">PEM</span>
                  </button>
                )}
              </div>
            </div>
            <pre className="code-block text-emerald-100/80">
              {JSON.stringify(keys.public, null, 2)}
            </pre>
          </Card>

          {/* Private Key Card */}
          <Card className="flex flex-col h-full border-t-4 border-t-red-500">
            <div className="flex justify-between items-start mb-4">
              <div>
                <h3 className="text-lg font-medium text-red-400">Private Key</h3>
                <p className="text-xs text-slate-500 mt-1">Keep Secret!</p>
              </div>
              <div className="flex gap-2">
                <button onClick={() => setShowPrivate(!showPrivate)} className="icon-btn" title="Toggle Visibility">{showPrivate ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}</button>
                <button 
                    onClick={() => copyToClipboard(JSON.stringify(keys.private, null, 2), "private")} 
                    className="icon-btn"
                    title="Copy JSON"
                >
                    {copied === "private" ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
                <button 
                    onClick={() => downloadJson(keys.private, "Private")} 
                    className="icon-btn"
                    title="Download JSON"
                >
                    <Download className="w-4 h-4" /> <span className="text-[10px] ml-1">JSON</span>
                </button>
                {keys.private.pem && (
                  <button 
                      onClick={() => {
                        const blob = new Blob([keys.private.pem as string], { type: "text/plain" });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url;
                        a.download = `${keyName.replace(/[^a-zA-Z0-9]/g, "_").replace(/_+/g, "_")}_Private.pem`;
                        a.click();
                      }}
                      className="icon-btn" 
                      title="Download PEM"
                  >
                      <Download className="w-4 h-4" /> <span className="text-[10px] ml-1">PEM</span>
                  </button>
                )}
              </div>
            </div>
            
            <div className="relative flex-1 bg-slate-950 rounded-lg border border-slate-900 overflow-hidden min-h-[150px]">
              <pre className={`p-4 text-xs text-red-100/80 font-mono overflow-auto h-full max-h-[300px] ${!showPrivate ? 'blur-md select-none opacity-50' : ''}`}>
                {JSON.stringify(keys.private, null, 2)}
              </pre>
            </div>
          </Card>

          <div className="lg:col-span-2 flex justify-center mt-4">
              <NeonButton onClick={handleSaveToWallet} variant="secondary" className="w-full sm:w-auto">
                  <Save className="w-4 h-4" /> Save to Browser Wallet
              </NeonButton>
          </div>
        </FadeIn>
      )}
    </div>
  );
}
