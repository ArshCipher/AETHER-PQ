import { useEffect, useRef, useState, useCallback } from "react";

export interface AuthState {
  authenticated: boolean;
  username: string | null;
  role: string | null;
  error: string | null;
  loading: boolean;
}

export function useWebSocket(url: string) {
  const [data, setData] = useState<any>(null);
  const [status, setStatus] = useState<"connecting" | "open" | "closed">("closed");
  const [authState, setAuthState] = useState<AuthState>({
    authenticated: false,
    username: null,
    role: null,
    error: null,
    loading: false
  });
  
  const ws = useRef<WebSocket | null>(null);
  const reconnectTimeout = useRef<number | null>(null);
  // Monotonic sequence counter — guarantees a new object reference every WS message
  const seqRef = useRef(0);

  const connect = useCallback(() => {
    if (ws.current) return;

    setStatus("connecting");
    const socket = new WebSocket(url);

    socket.onopen = () => {
      setStatus("open");
      console.log("[WS] Connected to AETHER-PQ Gateway");
      
      // Auto reconnect session if token exists
      const token = localStorage.getItem("aether_session_token");
      if (token) {
        setAuthState(prev => ({ ...prev, loading: true, error: null }));
        socket.send(JSON.stringify({ type: "session_auth", token }));
      }
    };

    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        const seq = ++seqRef.current;
        
        if (payload.type === "state") {
          setData((prev: any) => ({ ...prev, ...payload.data }));
        } else if (payload.type === "query_result") {
          setData((prev: any) => ({ ...prev, queryResult: { ...payload.data, _seq: seq } }));
        } else if (payload.type === "benchmark_result") {
          setData((prev: any) => ({ ...prev, benchmark: payload.data }));
        } else if (payload.type === "file_list") {
          // Wrap in new object with seq so useEffect always sees a changed reference
          setData((prev: any) => ({ ...prev, fileList: { ...payload.data, _seq: seq } }));
        } else if (payload.type === "file_transfer_progress") {
          setData((prev: any) => ({ ...prev, fileTransferProgress: { ...payload.data, _seq: seq } }));
        } else if (payload.type === "file_transfer_complete") {
          setData((prev: any) => ({ ...prev, fileTransferComplete: { ...payload.data, _seq: seq }, fileTransferProgress: null }));
        } else if (payload.type === "video_frame") {
          setData((prev: any) => ({ ...prev, videoFrame: { ...payload.data, _seq: seq } }));
        } else if (payload.type === "recording_status") {
          setData((prev: any) => ({ ...prev, recordingStatus: payload.data }));
        } else if (payload.type === "auth_result") {
          setAuthState(prev => ({ ...prev, loading: false }));
          if (payload.success) {
            localStorage.setItem("aether_session_token", payload.token);
            setAuthState({
              authenticated: true,
              username: payload.username,
              role: payload.role,
              error: null,
              loading: false
            });
          } else {
            setAuthState(prev => ({
              ...prev,
              authenticated: false,
              error: payload.error || "Authentication failed"
            }));
          }
        } else if (payload.type === "session_auth_result") {
          setAuthState(prev => ({ ...prev, loading: false }));
          if (payload.success) {
            setAuthState({
              authenticated: true,
              username: payload.username,
              role: payload.role,
              error: null,
              loading: false
            });
          } else {
            localStorage.removeItem("aether_session_token");
            setAuthState({
              authenticated: false,
              username: null,
              role: null,
              error: payload.error || "Session expired",
              loading: false
            });
          }
        } else if (payload.type === "logout_result") {
          if (payload.success) {
            localStorage.removeItem("aether_session_token");
            setAuthState({
              authenticated: false,
              username: null,
              role: null,
              error: null,
              loading: false
            });
          }
        }
      } catch (err) {
        console.error("[WS] Message parse error:", err);
      }
    };

    socket.onclose = () => {
      setStatus("closed");
      ws.current = null;
      console.log("[WS] Disconnected. Reconnecting in 3s...");
      reconnectTimeout.current = window.setTimeout(connect, 3000);
    };

    socket.onerror = (err) => {
      console.error("[WS] Error:", err);
      socket.close();
    };

    ws.current = socket;
  }, [url]);

  useEffect(() => {
    connect();
    return () => {
      if (ws.current) {
        ws.current.close();
      }
      if (reconnectTimeout.current) {
        clearTimeout(reconnectTimeout.current);
      }
    };
  }, [connect]);

  const sendCommand = useCallback((command: string, extra = {}) => {
    if (ws.current && status === "open") {
      const token = localStorage.getItem("aether_session_token");
      ws.current.send(JSON.stringify({ type: "command", command, token, ...extra }));
    } else {
      console.error("[WS] Cannot send command, socket not open");
    }
  }, [status]);

  const login = useCallback((username: string, passwordPlain: string) => {
    if (ws.current && status === "open") {
      setAuthState(prev => ({ ...prev, loading: true, error: null }));
      ws.current.send(JSON.stringify({ type: "auth", username, password: passwordPlain }));
    }
  }, [status]);

  const logout = useCallback(() => {
    if (ws.current && status === "open") {
      const token = localStorage.getItem("aether_session_token");
      ws.current.send(JSON.stringify({ type: "logout", token }));
    } else {
      localStorage.removeItem("aether_session_token");
      setAuthState({
        authenticated: false,
        username: null,
        role: null,
        error: null,
        loading: false
      });
    }
  }, [status]);

  return { data, status, authState, sendCommand, login, logout };
}
