import React, { useState } from "react";

type ProviderResult = {
  provider: string;
  is_malicious: boolean;
  score: number;
};

type AggregatedResult = {
  query: string;
  verdict: "Malicious" | "Clean" | "Unknown";
  score: number;
  providers: Record<string, ProviderResult>;
  reasons: string[];
};

export const App: React.FC = () => {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AggregatedResult | null>(null);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const resp = await fetch("/api/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "Request failed");
      setResult(data);
    } catch (err: any) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container glass">
      <h1>Cyber Threat Intelligence</h1>
      <p className="subtitle">Check IP or Domain reputation</p>

      <form onSubmit={onSubmit} className="form">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Enter IP or Domain"
          required
        />
        <button type="submit" disabled={loading}>{loading ? "Checking..." : "Check"}</button>
      </form>

      {error && <div className="card error">{error}</div>}

      {result && (
        <div className="card">
          <div className={`verdict ${result.verdict === "Malicious" ? "bad" : (result.verdict === "Clean" ? "good" : "")}`}>
            Verdict: {result.verdict} (score {result.score})
          </div>
          <div className="providers">
            {Object.values(result.providers || {}).map((p) => (
              <div className="provider-row" key={p.provider}>
                <div className="provider-name">{p.provider}</div>
                <div className={`provider-score ${p.is_malicious ? "bad" : "good"}`}>
                  {p.is_malicious ? "Malicious" : "Clean"} · Score {p.score}
                </div>
              </div>
            ))}
          </div>
          {!!result.reasons?.length && (
            <div className="reasons">Reasons: {result.reasons.join(", ")}</div>
          )}
        </div>
      )}
    </div>
  );
};
