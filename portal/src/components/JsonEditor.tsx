"use client";

// Self-hosted Monaco JSON editor. The portal is a static export served under a
// strict CSP (script-src 'self'), so Monaco is loaded at runtime from the
// same-origin AMD build at /monaco/vs (copied into public/ by the prebuild
// script) rather than from the default CDN. Loading via Monaco's own AMD loader
// (not webpack) also sidesteps Next's "global CSS" import restriction.
//
// We run without Monaco's background language workers (CSP-safe on this custom
// Next build); JSON is validated and formatted in plain JS by the caller.
import Editor, { loader } from "@monaco-editor/react";
import type { Monaco } from "@monaco-editor/react";

const VS = (process.env.NEXT_PUBLIC_BASE_PATH || "") + "/monaco/vs";

let configured = false;
function configureMonaco() {
  if (configured) return;
  configured = true;
  // Point Monaco's worker loader at the same-origin worker script (no blob:, no
  // CDN — CSP-safe). Language features that need the worker simply no-op.
  (self as unknown as { MonacoEnvironment?: unknown }).MonacoEnvironment = {
    getWorkerUrl: () => `${VS}/base/worker/workerMain.js`,
  };
  loader.config({ paths: { vs: VS } });
}

export default function JsonEditor({
  value,
  onChange,
  height = "24rem",
}: {
  value: string;
  onChange: (v: string) => void;
  height?: string;
}) {
  configureMonaco();
  // Vertically resizable container (drag the bottom edge); Monaco's automaticLayout
  // re-fits on resize. The editor fills the container height.
  return (
    <div className="resize-y overflow-hidden rounded-md border border-border" style={{ height, minHeight: "12rem" }}>
      <Editor
        height="100%"
        defaultLanguage="json"
        theme="vs-dark"
        value={value}
        onChange={(v) => onChange(v ?? "")}
        loading={<div className="p-4 text-sm text-muted-foreground">Loading editor…</div>}
        beforeMount={(monaco: Monaco) => {
          // We validate in JS; turn off the worker-backed JSON diagnostics.
          monaco.languages.json.jsonDefaults.setDiagnosticsOptions({ validate: false, allowComments: false });
        }}
        options={{
          minimap: { enabled: false },
          fontSize: 13,
          lineNumbers: "on",
          scrollBeyondLastLine: false,
          tabSize: 2,
          automaticLayout: true,
          wordWrap: "on",
          renderLineHighlight: "none",
        }}
      />
    </div>
  );
}
