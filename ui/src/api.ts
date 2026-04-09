export type QueryResponse = {
  vulnerable: boolean;
  cves: { id: string; severity: number | null; fix: string; summary?: string | null }[];
  explanation: string;
  sources: string[];
  package?: string;
  version?: string;
  meta?: Record<string, unknown>;
};

const API_BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://127.0.0.1:8000";
const API_KEY = (import.meta.env.VITE_API_KEY as string | undefined) ?? "changeme";

export async function queryAPI(query: string): Promise<QueryResponse> {
  const response = await fetch(`${API_BASE}/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-api-key": API_KEY },
    body: JSON.stringify({ query })
  });
  if (!response.ok) throw new Error(await response.text() || "Query failed");
  return response.json();
}
