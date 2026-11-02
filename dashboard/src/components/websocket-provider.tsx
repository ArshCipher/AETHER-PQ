import React, { createContext, useContext } from "react";
import { useWebSocket, type AuthState } from "@/hooks/use-websocket";

interface WebSocketContextType {
  data: any;
  status: "connecting" | "open" | "closed";
  authState: AuthState;
  sendCommand: (command: string, extra?: any) => void;
  login: (username: string, passwordPlain: string) => void;
  logout: () => void;
}

const WebSocketContext = createContext<WebSocketContextType | null>(null);

export function WebSocketProvider({ children }: { children: React.ReactNode }) {
  const wsUrl = typeof window !== "undefined" ? `ws://${window.location.hostname}:3001` : "ws://localhost:3001";
  const ws = useWebSocket(wsUrl);

  return (
    <WebSocketContext.Provider value={ws}>
      {children}
    </WebSocketContext.Provider>
  );
}

export function useWebSocketContext() {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error("useWebSocketContext must be used within a WebSocketProvider");
  }
  return context;
}
