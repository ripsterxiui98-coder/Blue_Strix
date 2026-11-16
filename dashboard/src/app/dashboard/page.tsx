"use client";

import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import {
  AlertTriangle,
  ArrowUp,
  Bot,
  Check,
  ChevronDown,
  Github,
  GitBranch,
  Laptop,
  Plus,
  Sparkles,
  Terminal,
  type LucideIcon,
} from "lucide-react";
import { GatewayShell } from "@/components/GatewayShell";

/** Dummy data — wire to the API when repo/branch endpoints are exposed. */
const REPOS = ["zixzax141298-ui/BlueStrix", "zixzax141298-ui/gateway-sandbox", "zixzax141298-ui/web3-audits"];
const BRANCHES = ["No branch", "main", "feat/ai-gateway-foundation", "fix/redaction-rules"];

const MAX_TEXTAREA_HEIGHT = 240;

function Dropdown({
  icon: Icon,
  label,
  value,
  options,
  onChange,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={ref} className="relative min-w-0">
      <button
        type="button"
        aria-label={label}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="flex max-w-full items-center gap-2 rounded-lg border border-slate-800 bg-black/40 px-3 py-1.5 font-mono text-xs text-slate-200 transition hover:border-blue-500/60"
      >
        <Icon className="h-3.5 w-3.5 shrink-0 text-blue-400" aria-hidden="true" />
        <span className="truncate">{value}</span>
        <ChevronDown
          className={`h-3.5 w-3.5 shrink-0 text-slate-500 transition-transform ${open ? "rotate-180" : ""}`}
          aria-hidden="true"
        />
      </button>

      <AnimatePresence>
        {open && (
          <motion.ul
            role="listbox"
            aria-label={label}
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.12 }}
            className="absolute left-0 z-20 mt-2 w-max min-w-full max-w-[80vw] overflow-hidden rounded-lg border border-blue-900/50 bg-slate-950/95 p-1 shadow-xl backdrop-blur-xl"
          >
            {options.map((option) => (
              <li key={option} role="option" aria-selected={option === value}>
                <button
                  type="button"
                  onClick={() => {
                    onChange(option);
                    setOpen(false);
                  }}
                  className="flex w-full items-center justify-between gap-4 rounded-md px-3 py-1.5 text-left font-mono text-xs text-slate-300 transition hover:bg-blue-950/70 hover:text-blue-200"
                >
                  <span className="truncate">{option}</span>
                  {option === value && <Check className="h-3.5 w-3.5 shrink-0 text-blue-400" aria-hidden="true" />}
                </button>
              </li>
            ))}
          </motion.ul>
        )}
      </AnimatePresence>
    </div>
  );
}

function Hero() {
  const reduce = useReducedMotion();
  return (
    <div className="relative mx-auto flex h-36 w-36 items-center justify-center">
      <motion.div
        aria-hidden="true"
        className="absolute inset-4 rounded-full bg-blue-500/40 blur-2xl"
        animate={reduce ? undefined : { opacity: [0.35, 0.8, 0.35], scale: [1, 1.2, 1] }}
        transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
      />
      <motion.div
        className="relative flex h-20 w-20 items-center justify-center rounded-3xl border border-blue-500/40 bg-gradient-to-br from-blue-600/30 to-slate-900/80 shadow-[0_0_15px_rgba(59,130,246,0.5)] backdrop-blur-xl"
        animate={reduce ? undefined : { scale: [1, 1.05, 1] }}
        transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
      >
        <Bot className="h-10 w-10 text-blue-400" aria-hidden="true" />
        <Sparkles className="absolute -right-2 -top-2 h-5 w-5 text-blue-300" aria-hidden="true" />
      </motion.div>
    </div>
  );
}

export default function AgentsPage() {
  const [repo, setRepo] = useState(REPOS[0]);
  const [branch, setBranch] = useState(BRANCHES[0]);
  const [prompt, setPrompt] = useState("");
  const [yolo, setYolo] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const noticeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Auto-resize the textarea to fit its content (up to a max height).
  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, MAX_TEXTAREA_HEIGHT)}px`;
  }, [prompt]);

  useEffect(
    () => () => {
      if (noticeTimer.current) clearTimeout(noticeTimer.current);
    },
    [],
  );

  const canSubmit = prompt.trim().length > 0;

  function submit() {
    if (!canSubmit) return;
    // Demo only: no backend call yet.
    setNotice(`Task queued for ${repo} (${branch}) — demo only, agent backend not connected.`);
    setPrompt("");
    if (noticeTimer.current) clearTimeout(noticeTimer.current);
    noticeTimer.current = setTimeout(() => setNotice(null), 5000);
  }

  function onKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault();
      submit();
    }
  }

  return (
    <GatewayShell>
      <div className="space-y-8">
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
          <h1 className="text-2xl font-semibold tracking-tight text-white">Agents</h1>
          <p className="mt-1 text-sm text-slate-400">
            Describe a task and let BlueStrix agents analyze, review, and propose fixes for your repository.
          </p>
        </motion.div>

        <Hero />

        {/* Input box */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, delay: 0.05 }}
          className="rounded-2xl border border-blue-500/40 bg-slate-900/60 shadow-[0_0_25px_rgba(59,130,246,0.12)] backdrop-blur-xl transition-shadow focus-within:shadow-[0_0_15px_rgba(59,130,246,0.5)]"
        >
          <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 px-4 py-3">
            <Dropdown icon={Github} label="Repository" value={repo} options={REPOS} onChange={setRepo} />
            <Dropdown icon={GitBranch} label="Branch" value={branch} options={BRANCHES} onChange={setBranch} />
          </div>

          <div className="px-4 pt-4">
            <textarea
              ref={textareaRef}
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              onKeyDown={onKeyDown}
              rows={2}
              placeholder="Describe what you want to build..."
              aria-label="Task description"
              className="block max-h-60 w-full resize-none bg-transparent text-sm leading-relaxed text-slate-100 placeholder:text-slate-500 focus:outline-none"
            />
          </div>

          <div className="flex items-center justify-between gap-3 px-4 pb-4 pt-3">
            <div className="flex items-center gap-2">
              <button
                type="button"
                aria-label="Add attachment"
                className="rounded-lg border border-slate-800 p-2 text-slate-400 transition hover:border-blue-500/60 hover:text-blue-400"
              >
                <Plus className="h-4 w-4" aria-hidden="true" />
              </button>
              <button
                type="button"
                aria-label="Connect GitHub"
                className="rounded-lg border border-slate-800 p-2 text-slate-400 transition hover:border-blue-500/60 hover:text-blue-400"
              >
                <Github className="h-4 w-4" aria-hidden="true" />
              </button>

              <button
                type="button"
                role="switch"
                aria-checked={yolo}
                onClick={() => setYolo((v) => !v)}
                title="Auto-approve agent actions (UI preview only)"
                className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-xs text-slate-400 transition hover:text-slate-200"
              >
                <span
                  className={`relative h-5 w-9 rounded-full transition-colors ${
                    yolo ? "bg-blue-500 shadow-[0_0_15px_rgba(59,130,246,0.5)]" : "bg-slate-700"
                  }`}
                >
                  <motion.span
                    className="absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-white"
                    animate={{ x: yolo ? 16 : 0 }}
                    transition={{ type: "spring", stiffness: 500, damping: 30 }}
                  />
                </span>
                <span className={`font-mono font-medium tracking-wide ${yolo ? "text-blue-300" : ""}`}>YOLO</span>
              </button>
            </div>

            <motion.button
              type="button"
              onClick={submit}
              disabled={!canSubmit}
              aria-label="Submit task"
              whileHover={canSubmit ? { scale: 1.08 } : undefined}
              whileTap={canSubmit ? { scale: 0.92 } : undefined}
              className="flex h-9 w-9 items-center justify-center rounded-full bg-gradient-to-br from-blue-500 to-blue-600 text-white transition-shadow enabled:hover:shadow-[0_0_15px_rgba(59,130,246,0.5)] disabled:cursor-not-allowed disabled:opacity-40"
            >
              <ArrowUp className="h-4 w-4" aria-hidden="true" />
            </motion.button>
          </div>
        </motion.div>

        <div aria-live="polite" className="min-h-0">
          <AnimatePresence>
            {notice && (
              <motion.p
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="rounded-lg border border-blue-900/50 bg-blue-950/30 px-4 py-2 font-mono text-xs text-blue-200"
              >
                {notice}
              </motion.p>
            )}
          </AnimatePresence>
        </div>

        {/* Credits warning */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, delay: 0.1 }}
          className="flex flex-col gap-4 rounded-xl border border-amber-500/30 bg-slate-900/60 p-4 backdrop-blur-xl sm:flex-row sm:items-center sm:justify-between"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" aria-hidden="true" />
            <p className="text-sm text-slate-300">
              You&rsquo;re out of credits. Use a free model, or add credits to keep running agents.
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              type="button"
              className="rounded-lg border border-amber-500/40 px-3 py-1.5 text-sm text-amber-300 transition hover:bg-amber-500/10"
            >
              Get BlueStrix Pass
            </button>
            <button
              type="button"
              className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-blue-500 hover:shadow-[0_0_15px_rgba(59,130,246,0.5)]"
            >
              Add credits
            </button>
          </div>
        </motion.div>

        {/* Footer */}
        <div className="flex flex-col items-center gap-3 border-t border-slate-800 pt-6 text-center">
          <p className="text-xs text-slate-500">Want to develop locally?</p>
          <div className="flex flex-wrap justify-center gap-2">
            <button
              type="button"
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-1.5 font-mono text-xs text-slate-300 transition hover:border-blue-500 hover:text-blue-300 hover:shadow-[0_0_15px_rgba(59,130,246,0.5)]"
            >
              <Terminal className="h-3.5 w-3.5" aria-hidden="true" />
              Install BlueStrix CLI
            </button>
            <button
              type="button"
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-1.5 font-mono text-xs text-slate-300 transition hover:border-blue-500 hover:text-blue-300 hover:shadow-[0_0_15px_rgba(59,130,246,0.5)]"
            >
              <Laptop className="h-3.5 w-3.5" aria-hidden="true" />
              Install in your IDEs
            </button>
          </div>
        </div>
      </div>
    </GatewayShell>
  );
}
