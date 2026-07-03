"use client";

import { useEffect, useRef, useState } from "react";
import { Bot, X, Send, Mic, Volume2, VolumeX } from "lucide-react";
import { apiPost } from "@/lib/api";
import Md from "@/components/Md";

type Msg = { role: "user" | "assistant"; content: string };

/* Minimal Web Speech typings (not in lib.dom for all TS configs). */
type SpeechRecognitionResult = { isFinal: boolean; 0: { transcript: string } };
type SpeechRecognitionEvent = { results: ArrayLike<SpeechRecognitionResult> };
interface SpeechRecognitionLike {
  lang: string; interimResults: boolean; continuous: boolean;
  start: () => void; stop: () => void;
  onresult: ((e: SpeechRecognitionEvent) => void) | null;
  onend: (() => void) | null;
  onerror: (() => void) | null;
}
type SRCtor = new () => SpeechRecognitionLike;
function getSR(): SRCtor | undefined {
  if (typeof window === "undefined") return undefined;
  const w = window as unknown as { SpeechRecognition?: SRCtor; webkitSpeechRecognition?: SRCtor };
  return w.SpeechRecognition || w.webkitSpeechRecognition;
}

// Strip markdown so speech synthesis reads clean prose.
function stripMd(s: string): string {
  return s
    .replace(/```[\s\S]*?```/g, " code block ")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[*_#>]/g, "")
    .replace(/^\s*[-•]\s*/gm, "")
    .replace(/\s+/g, " ")
    .trim();
}

// Prepare text for speech: strip markdown, then replace long opaque identifiers
// (SHA hashes, UUIDs, build IDs) with a short placeholder so the voice doesn't
// spell out 40 characters. Display text is unaffected.
function forSpeech(s: string): string {
  return stripMd(s)
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "an ID") // UUID
    .replace(/\b(?:sha256:|sha1:)?[0-9a-f]{12,}\b/gi, "an ID")                                // hex hashes
    .replace(/\b(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])[a-z0-9]{16,}\b/gi, "an ID")              // long mixed tokens
    .replace(/\ban ID\b(?:[\s,·:/-]+\ban ID\b)+/gi, "an ID")                                  // collapse repeats
    .replace(/\s+/g, " ")
    .trim();
}

export default function AIAssistant() {
  const [open, setOpen] = useState(false);
  const [msgs, setMsgs] = useState<Msg[]>([
    { role: "assistant", content: "Hello! I'm **Fides**, your compliance & audit assistant. Try: `list flows`, `find failing trails`, or `create flow frontend-service`." },
  ]);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [listening, setListening] = useState(false);
  const [voiceOut, setVoiceOut] = useState(false);
  const [sttOK, setSttOK] = useState(false);
  const [ttsOK, setTtsOK] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);
  const recRef = useRef<SpeechRecognitionLike | null>(null);
  const spokenRef = useRef(0); // # of msgs already considered for speaking

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [msgs, open]);

  useEffect(() => {
    setSttOK(!!getSR());
    setTtsOK(typeof window !== "undefined" && !!window.speechSynthesis);
    spokenRef.current = 1; // don't speak the initial greeting retroactively
  }, []);

  // Speak new assistant replies when voice output is on.
  useEffect(() => {
    if (!voiceOut || typeof window === "undefined" || !window.speechSynthesis) return;
    if (msgs.length <= spokenRef.current) return;
    spokenRef.current = msgs.length;
    const last = msgs[msgs.length - 1];
    if (last?.role === "assistant") {
      window.speechSynthesis.cancel();
      window.speechSynthesis.speak(new SpeechSynthesisUtterance(forSpeech(last.content)));
    }
  }, [msgs, voiceOut]);

  // Cleanup on unmount: stop mic + any speech.
  useEffect(() => () => {
    recRef.current?.stop();
    if (typeof window !== "undefined") window.speechSynthesis?.cancel();
  }, []);

  const send = async (override?: string) => {
    const message = (override ?? text).trim();
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

  const toggleMic = () => {
    if (listening) { recRef.current?.stop(); return; }
    const SR = getSR();
    if (!SR) return;
    const rec = new SR();
    rec.lang = "en-US";
    rec.interimResults = true;
    rec.continuous = false;
    rec.onresult = (e) => {
      let interim = "", final = "";
      for (let i = 0; i < e.results.length; i++) {
        const res = e.results[i];
        if (res.isFinal) final += res[0].transcript; else interim += res[0].transcript;
      }
      setText(final || interim);
      if (final.trim()) { rec.stop(); send(final); } // auto-send when the phrase completes
    };
    rec.onend = () => { setListening(false); recRef.current = null; };
    rec.onerror = () => { setListening(false); recRef.current = null; };
    recRef.current = rec;
    setListening(true);
    rec.start();
  };

  const toggleVoiceOut = () => {
    setVoiceOut((v) => {
      const next = !v;
      if (!next && typeof window !== "undefined") window.speechSynthesis?.cancel();
      else spokenRef.current = msgs.length; // only speak future replies
      return next;
    });
  };

  return (
    <>
      {open && (
        <div className="fixed bottom-24 right-6 z-50 flex h-[28rem] w-96 flex-col rounded-xl border border-border bg-card shadow-2xl">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <div className="flex items-center gap-2 text-sm font-semibold"><Bot className="size-4 text-primary" /> Fides Assistant</div>
            <div className="flex items-center gap-1">
              {ttsOK && (
                <button onClick={toggleVoiceOut} title={voiceOut ? "Turn off voice replies" : "Read replies aloud"}
                  className={`rounded p-1 ${voiceOut ? "text-primary" : "text-muted-foreground hover:text-foreground"}`}>
                  {voiceOut ? <Volume2 className="size-4" /> : <VolumeX className="size-4" />}
                </button>
              )}
              <button onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground"><X className="size-4" /></button>
            </div>
          </div>
          <div className="flex-1 space-y-3 overflow-auto p-3 text-sm">
            {msgs.map((m, i) => (
              <div key={i} className={m.role === "user" ? "text-right" : ""}>
                <span className={`inline-block max-w-[90%] break-words [overflow-wrap:anywhere] rounded-lg px-3 py-2 text-left [&_code]:whitespace-pre-wrap [&_code]:break-all [&_pre]:overflow-x-auto [&_pre]:whitespace-pre-wrap ${m.role === "user" ? "whitespace-pre-wrap bg-primary/15 text-foreground" : "bg-muted text-foreground [&_p]:my-1 [&_p:first-child]:mt-0 [&_p:last-child]:mb-0"}`}>
                  {m.role === "assistant" ? <Md>{m.content}</Md> : m.content}
                </span>
              </div>
            ))}
            {busy && <div className="text-xs text-muted-foreground">Thinking…</div>}
            <div ref={endRef} />
          </div>
          <div className="flex items-center gap-2 border-t border-border p-3">
            {sttOK && (
              <button onClick={toggleMic} title={listening ? "Stop listening" : "Speak"} aria-pressed={listening}
                className={`shrink-0 rounded-md border px-3 py-2 ${listening ? "animate-pulse border-red-500/50 bg-red-500/15 text-red-400" : "border-border text-muted-foreground hover:text-foreground"}`}>
                <Mic className="size-4" />
              </button>
            )}
            <input
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") send(); }}
              placeholder={listening ? "Listening…" : "Ask about flows, trails, compliance…"}
              className="flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm"
            />
            <button onClick={() => send()} disabled={busy} className="shrink-0 rounded-md bg-primary px-3 py-2 text-primary-foreground disabled:opacity-50"><Send className="size-4" /></button>
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
