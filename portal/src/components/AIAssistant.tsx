"use client";

import { useEffect, useRef, useState } from "react";
import { Bot, X, Send } from "lucide-react";
import { apiPost } from "@/lib/api";

type Msg = { role: "user" | "assistant"; content: string };

export default function AIAssistant() {
  const [open, setOpen] = useState(false);
  const [msgs, setMsgs] = useState<Msg[]>([
    { role: "assistant", content: "Hello! I'm **Fides**, your compliance & audit assistant. Try: `list flows`, `find failing trails`, or `create flow frontend-service`." },
  ]);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [msgs, open]);

  const send = async () => {
    const message = text.trim();
    if (!message || busy) return;
    const history = msgs;
    setMsgs([...msgs, { role: "user", content: message }]);
    setText("");
    setBusy(true);
    try {
      const r = await apiPost<{ response: string }>("/api/v1/ai/chat", { message, history });
      setMsgs((m) => [...m, { role: "assistant", content: r.response || "(no response)" }]);
    } catch (e) {
      setMsgs((m) => [...m, { role: "assistant", content: "Error contacting the assistant: " + String((e as Error).message || e) }]);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      {open && (
        <div className="fixed bottom-24 right-6 z-50 flex h-[28rem] w-96 flex-col rounded-xl border border-border bg-card shadow-2xl">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <div className="flex items-center gap-2 text-sm font-semibold"><Bot className="size-4 text-primary" /> Fides Assistant</div>
            <button onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground"><X className="size-4" /></button>
          </div>
          <div className="flex-1 space-y-3 overflow-auto p-3 text-sm">
            {msgs.map((m, i) => (
              <div key={i} className={m.role === "user" ? "text-right" : ""}>
                <span className={`inline-block max-w-[85%] whitespace-pre-wrap rounded-lg px-3 py-2 text-left ${m.role === "user" ? "bg-primary/15 text-foreground" : "bg-muted text-foreground"}`}>
                  {m.content}
                </span>
              </div>
            ))}
            {busy && <div className="text-xs text-muted-foreground">Thinking…</div>}
            <div ref={endRef} />
          </div>
          <div className="flex items-center gap-2 border-t border-border p-3">
            <input
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") send(); }}
              placeholder="Ask about flows, trails, compliance…"
              className="flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm"
            />
            <button onClick={send} disabled={busy} className="rounded-md bg-primary px-3 py-2 text-primary-foreground disabled:opacity-50"><Send className="size-4" /></button>
          </div>
        </div>
      )}
      <button
        onClick={() => setOpen((o) => !o)}
        aria-label="Fides AI assistant"
        className="fixed bottom-6 right-6 z-50 flex size-14 items-center justify-center rounded-full bg-primary text-primary-foreground shadow-lg transition-transform hover:scale-105"
      >
        {open ? <X className="size-6" /> : <Bot className="size-6" />}
      </button>
    </>
  );
}
