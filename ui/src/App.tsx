import { useState } from "react";
import SearchBox from "./components/SearchBox";
import ResultsCard from "./components/ResultsCard";
import { queryAPI, type QueryResponse } from "./api";

export default function App() {
  const [result, setResult] = useState<QueryResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSearch(query: string) {
    setLoading(true);
    setError("");
    try {
      const data = await queryAPI(query);
      setResult(data);
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 px-4 py-10 text-slate-100">
      <div className="mx-auto max-w-4xl">
        <header className="mb-8">
          <p className="text-sm uppercase tracking-[0.3em] text-cyan-300">VersionGuard</p>
          <h1 className="mt-2 text-4xl font-bold">Agentic RAG CVE Advisor</h1>
          <p className="mt-3 max-w-2xl text-slate-300">
            Ask whether a package version is vulnerable. VersionGuard checks indexed NVD data, falls back to live NVD when needed, and explains results in plain English.
          </p>
        </header>

        <SearchBox onSearch={handleSearch} loading={loading} />
        {error ? <div className="mt-6 rounded-3xl border border-rose-800 bg-rose-950/40 p-4 text-sm text-rose-200">{error}</div> : null}
        {result ? <ResultsCard result={result} /> : null}
      </div>
    </main>
  );
}
