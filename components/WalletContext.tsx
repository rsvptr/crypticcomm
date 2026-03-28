"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { RSAKeyDict, generateKeyName, encryptWalletData, decryptWalletData } from "@/lib/rsa";

export interface StoredKey {
  id: string;
  name: string;
  keys: RSAKeyDict;
  createdAt: number;
}

interface WalletContextType {
  keys: StoredKey[];
  isLocked: boolean;
  hasWallet: boolean;
  unlockWallet: (password: string) => Promise<number>;
  createWallet: (password: string) => Promise<void>;
  lockWallet: () => void;
  saveKey: (key: RSAKeyDict) => Promise<void>;
  deleteKey: (id: string) => Promise<void>;
  getKey: (id: string) => StoredKey | undefined;
}

const WalletContext = createContext<WalletContextType | undefined>(undefined);

export function WalletProvider({ children }: { children: ReactNode }) {
  const [keys, setKeys] = useState<StoredKey[]>([]);
  const [isLocked, setIsLocked] = useState(true);
  const [hasWallet, setHasWallet] = useState(false);
  const [password, setPassword] = useState<string | null>(null);

  const persistWallet = async (nextKeys: StoredKey[], pwd: string) => {
    const encrypted = await encryptWalletData(nextKeys, pwd);
    localStorage.setItem("cryptic_wallet_enc", encrypted);
  };

  useEffect(() => {
    const stored = localStorage.getItem("cryptic_wallet_enc");
    if (stored) {
      setHasWallet(true);
    } else {
      // Migrate old plain text wallet to new encrypted format
      const oldStored = localStorage.getItem("cryptic_wallet");
      if (oldStored) {
        setHasWallet(true);
        // We can't auto-migrate because we need a password, so we just treat it as having a wallet.
        // Actually, we could show a special migration screen, but for now we'll just ignore old for security
        // or let them create a new wallet which overwrites it.
      }
    }
  }, []);

  const createWallet = async (pwd: string) => {
    const emptyWallet = await encryptWalletData([], pwd);
    localStorage.setItem("cryptic_wallet_enc", emptyWallet);
    localStorage.removeItem("cryptic_wallet"); // clear old
    setHasWallet(true);
    setIsLocked(false);
    setPassword(pwd);
    setKeys([]);
  };

  const unlockWallet = async (pwd: string): Promise<number> => {
    try {
      const stored = localStorage.getItem("cryptic_wallet_enc");
      if (stored) {
        const decryptedKeys = await decryptWalletData(stored, pwd);
        if (!Array.isArray(decryptedKeys)) {
          throw new Error("Wallet data is corrupted.");
        }
        setKeys(decryptedKeys);
        setIsLocked(false);
        setPassword(pwd);
        return decryptedKeys.length;
      }
      throw new Error("No encrypted wallet was found in this browser.");
    } catch {
      throw new Error("Incorrect password or unreadable wallet data.");
    }
  };

  const lockWallet = () => {
    setKeys([]);
    setIsLocked(true);
    setPassword(null);
  };

  const saveKey = async (keyData: RSAKeyDict) => {
    if (isLocked || !password) throw new Error("Wallet is locked");

    const existing = keys.find((key) => key.keys.public.n === keyData.public.n);
    if (existing) {
      throw new Error(`This identity is already saved as "${existing.name}".`);
    }

    const name = await generateKeyName(keyData.public);
    const newKey: StoredKey = {
      id: crypto.randomUUID(),
      name,
      keys: keyData,
      createdAt: Date.now(),
    };
    
    const updated = [newKey, ...keys];
    setKeys(updated);
    await persistWallet(updated, password);
  };

  const deleteKey = async (id: string) => {
    if (isLocked || !password) throw new Error("Wallet is locked");
    const updated = keys.filter((k) => k.id !== id);
    setKeys(updated);
    await persistWallet(updated, password);
  };

  const getKey = (id: string) => keys.find((k) => k.id === id);

  return (
    <WalletContext.Provider
      value={{
        keys,
        isLocked,
        hasWallet,
        unlockWallet,
        createWallet,
        lockWallet,
        saveKey,
        deleteKey,
        getKey,
      }}
    >
      {children}
    </WalletContext.Provider>
  );
}

export function useWallet() {
  const context = useContext(WalletContext);
  if (context === undefined) {
    throw new Error("useWallet must be used within a WalletProvider");
  }
  return context;
}
