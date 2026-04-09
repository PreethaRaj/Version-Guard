import { useState } from "react";

type Props = { onSearch: (query: string) => Promise<void> | void; loading: boolean; };

export default function SearchBox({ onSearch, loading }: Props) {
  const [value, setValue] = useState("express 4.17.1");
  return (
    <div className="w-full rounded-3xl border border-slate-800 bg-slate-900/70 p-4 shadow-xl">
      <label className="mb-2 block text-sm text-slate-300">Package and version</label>
      <div className="flex flex-col gap-3 sm:flex-row">
        <input
          className="flex-1 rounded-2xl border border-slate-700 bg-slate-950 px-4 py-3 text-slate-100 outline-none focus:border-cyan-400"
          placeholder="express 4.17.1"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !loading) void onSearch(value); }}
        />
        <button
          className="rounded-2xl bg-cyan-500 px-5 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
          onClick={() => void onSearch(value)}
          disabled={loading}
        >
          {loading ? "Checking..." : "Check"}
        </button>
      </div>
    </div>
  );
}
