"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { login } from "@/lib/api";

export default function Login() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      await login(username, password);
      router.replace("/");
    } catch (ex) {
      setErr("Invalid username or password.");
    } finally {
      setBusy(false);
    }
  };

  const input = "w-full rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm";

  return (
    <div className="m-auto w-full max-w-sm p-8">
      <div className="mb-6 text-center">
        <div className="font-mono text-lg font-semibold tracking-wide">FIDES</div>
        <div className="mt-1 text-sm text-neutral-500">Compliance Portal Sign-In</div>
      </div>
      <form onSubmit={submit} className="rounded-xl border border-neutral-800 bg-neutral-900 p-6">
        <label className="mb-3 block text-sm">
          <span className="text-neutral-500">Username / Email</span>
          <input className={input} value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        </label>
        <label className="mb-4 block text-sm">
          <span className="text-neutral-500">Password</span>
          <input className={input} type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <button type="submit" disabled={busy} className="w-full rounded-md bg-purple-600 px-4 py-2 text-sm font-semibold text-white disabled:opacity-60">
          {busy ? "Signing in…" : "Sign In"}
        </button>
        {err && <p className="mt-3 text-sm text-red-400">{err}</p>}
      </form>
    </div>
  );
}
