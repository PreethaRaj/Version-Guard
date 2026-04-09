import type { QueryResponse } from "../api";

type Props = { result: QueryResponse };

export default function ResultsCard({ result }: Props) {
  if (!result) return null;

  const statusText = result.vulnerable ? "VULNERABLE" : "NOT VULNERABLE";

  return (
    <div className="bg-gray-900 text-white p-4 rounded-xl shadow-md mt-4">
      <div
        className={`text-xl font-bold mb-2 ${
          result.vulnerable ? "text-red-400" : "text-green-400"
        }`}
      >
        {statusText}
      </div>

      <div className="text-sm text-gray-300 mb-3">
        {result.package} {result.version}
      </div>

      <div className="text-sm whitespace-pre-wrap">
        {result.explanation}
      </div>

      <div className="mt-3 p-3 bg-gray-800 rounded-lg border border-gray-700">        
        <div className="text-sm">{result.solution}</div>
      </div>

      {result.cves?.length > 0 && (
        <div className="mt-3">
          <div className="font-semibold">CVE Matches:</div>
          <ul className="list-disc ml-5 text-sm">
            {result.cves.map((cve) => (
              <li key={cve.id}>
                {cve.id} (severity: {cve.severity}) → fix: {cve.fix}
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.sources?.length > 0 && (
        <div className="mt-3 text-sm">
          <div className="font-semibold">Sources:</div>
          {result.sources.map((src) => (
            <div key={src}>
              <a href={src} target="_blank" rel="noreferrer" className="text-blue-400 underline">
                {src}
              </a>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}