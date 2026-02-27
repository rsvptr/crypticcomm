"use client";

import { createContext, useContext, useState, ReactNode } from "react";

export interface HistoryItem {
  id: string;
  type: "Encrypt" | "Decrypt" | "Sign" | "Verify";
  timestamp: number;
  details: {
    message?: string;
    output?: string;
    keyName?: string;
    status?: string;
  };
}

interface HistoryContextType {
  history: HistoryItem[];
  addHistory: (item: Omit<HistoryItem, "id" | "timestamp">) => void;
  clearHistory: () => void;
}

const HistoryContext = createContext<HistoryContextType | undefined>(undefined);

export function HistoryProvider({ children }: { children: ReactNode }) {
  const [history, setHistory] = useState<HistoryItem[]>([]);

  const addHistory = (item: Omit<HistoryItem, "id" | "timestamp">) => {
    const newItem: HistoryItem = {
      ...item,
      id: crypto.randomUUID(),
      timestamp: Date.now(),
    };
    setHistory((prev) => [newItem, ...prev].slice(0, 50)); // Keep last 50
  };

  const clearHistory = () => setHistory([]);

  return (
    <HistoryContext.Provider value={{ history, addHistory, clearHistory }}>
      {children}
    </HistoryContext.Provider>
  );
}

export function useHistory() {
  const context = useContext(HistoryContext);
  if (context === undefined) {
    throw new Error("useHistory must be used within a HistoryProvider");
  }
  return context;
}