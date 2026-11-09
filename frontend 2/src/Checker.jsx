// ---------- Imports ----------
import { useState } from "react";
import {
  BarChart, Bar, LineChart, Line, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend, ResponsiveContainer, ReferenceLine,
} from "recharts";


// ---------- Settings ----------
// Backend address. Change it with VITE_API_URL in a .env file.
const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const MAX_URL_LENGTH = 2048; // same limit as the backend
const AXIS_COLOUR = "#000000"; // black chart text so it is easy to read
const AXIS_TICK = { fill: AXIS_COLOUR };


// ---------- Validation (mirrors the backend rules; the backend is the real check) ----------
function validate(raw) {
  const v = raw.trim();
  if (!v) return "Enter a URL to check.";
  if (v.length > MAX_URL_LENGTH) return "That URL is too long (maximum 2048 characters).";
  if (/\s/.test(v)) return "URLs can't contain spaces.";
  let u;
  try { u = new URL(v); } catch { return "Enter a full URL starting with http:// or https://"; }
  const okScheme = ["http:", "https:"].includes(u.protocol);
  const okHost = u.hostname.includes(".");
  if (!okScheme) {
    return "Enter a full web address, for example https://example.com";
  }
  if (!okHost) {
    return "Enter a full website URL starting with http:// or https://";
  }
  return "";
}


// ---------- API call: POST /predict ----------
// Sends the URL to the backend and returns a simple result object.
// Backend reply: { url, prediction, confidence, malicious_probability }
// Backend errors: { detail: "message" }
async function checkUrl(url) {
  let res;
  try {
    res = await fetch(`${API_URL}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
  } catch {
    throw new Error("Couldn't reach the checker. Check your connection and try again.");
  }
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const msg = data?.detail ?? data?.error?.message;
    throw new Error(typeof msg === "string" ? msg : "Something went wrong. Please try again.");
  }
  return {
    url: data.url,
    isPhishing: data.prediction === "MALICIOUS",
    confidence: data.confidence,
    phishingProb: data.malicious_probability,
  };
}


// ---------- Page ----------
export default function Checker() {
  // State: "status" decides what the screen shows
  const [input, setInput] = useState("");
  const [status, setStatus] = useState("idle"); // idle | loading | success | error
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [filter, setFilter] = useState("all"); // all | phishing | legitimate
  const [selected, setSelected] = useState(null); // check number picked on chart 2 or the table

  // Runs when the form is submitted: validate, call the API, update the screen
  async function onSubmit(e) {
    e.preventDefault();
    const problem = validate(input);
    if (problem) {
      setError(problem);
      setStatus("error");
      return;
    }
    setStatus("loading");
    try {
      const r = await checkUrl(input.trim());
      setResult(r);
      setHistory([
        ...history,
        { check: history.length + 1, url: r.url, isPhishing: r.isPhishing, probability: Math.round(r.phishingProb * 100) },
      ]);
      setSelected(null);
      setStatus("success");
    } catch (err) {
      setError(err.message);
      setStatus("error");
    }
  }

  // Data for chart 1: the current result
  const phishingPct = result ? Math.round(result.phishingProb * 100) : 0;
  const probs = [
    { name: "Phishing", Phishing: phishingPct },
    { name: "Legitimate", Legitimate: 100 - phishingPct },
  ];

  // Data for chart 2: session history, narrowed by the filter
  let shown = history;
  if (filter !== "all") {
    shown = history.filter((h) => (filter === "phishing") === h.isPhishing);
  }

  // Clicking a point on chart 2 picks that check
  function onDotClick(a, b) {
    const point = a?.payload ?? b?.payload;
    if (point) setSelected(point.check);
  }
  const selectedItem = history.find((h) => h.check === selected);

  return (
    <main>
      <h1>Phishing URL checker</h1>

      {/* Input form: the error message sits right under the field */}
      <form onSubmit={onSubmit} noValidate className="card">
        <label htmlFor="url">URL to check</label>
        <input
          id="url" type="text" inputMode="url" autoComplete="off"
          value={input} onChange={(e) => setInput(e.target.value)}
          aria-invalid={status === "error"}
          aria-describedby={status === "error" ? "url-error" : "url-hint"}
        />
        {status === "error" ? (
          <p id="url-error" className="error" role="alert">{error}</p>
        ) : (
          <p id="url-hint" className="hint">
            Paste a full link starting with http:// or https://. The checker never opens it.
          </p>
        )}
        <button type="submit" disabled={status === "loading"}>
          {status === "loading" ? "Checking..." : "Check URL"}
        </button>
      </form>

      {/* Loading and result (announced to screen readers) */}
      <div aria-live="polite">
        {status === "loading" && <p className="hint">Checking this URL...</p>}
        {status === "success" && (
          <section className={`result ${result.isPhishing ? "bad" : "good"}`}>
            <h2>{result.isPhishing ? "PHISHING" : "LEGITIMATE"}</h2>
            <p>Confidence: <strong>{Math.round(result.confidence * 100)}%</strong></p>
            {/* React escapes this text, so user input is never rendered as HTML */}
            <p className="url">Checked: {result.url}</p>
            <p>This is an estimate, not a guarantee. When in doubt, don't click the link or enter any details.</p>
          </section>
        )}
      </div>

      {/* Chart 1: class probabilities for the latest check, against the 50% decision line */}
      {status === "success" && (
        <section className="card">
          <h3>Current result: class probabilities</h3>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={probs} margin={{ top: 10, bottom: 20, left: 20, right: 50 }} accessibilityLayer>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" tick={AXIS_TICK} label={{ value: "Class", position: "insideBottom", offset: -10, fill: AXIS_COLOUR }} />
              <YAxis domain={[0, 100]} unit="%" width={76} tick={AXIS_TICK} label={{ value: "Probability (%)", angle: -90, position: "insideLeft", fill: AXIS_COLOUR }} />
              <Tooltip formatter={(v) => v + "%"} />
              <Legend verticalAlign="top" />
              <ReferenceLine y={50} stroke="#111827" strokeDasharray="6 4" label={{ value: "50%", position: "right", fill: AXIS_COLOUR }} />
              <Bar dataKey="Phishing" stackId="class" fill="#b42318" />
              <Bar dataKey="Legitimate" stackId="class" fill="#067647" />
            </BarChart>
          </ResponsiveContainer>
          <p>Text version: Phishing {phishingPct}%, Legitimate {100 - phishingPct}%.</p>
        </section>
      )}

      {/* Chart 2: session history with a filter, point details, and a table version */}
      {history.length > 0 && (
        <section className="card">
          <h3>This session: phishing probability for each URL checked</h3>
          <label htmlFor="filter">Show</label>
          <select id="filter" value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="all">All checks</option>
            <option value="phishing">Phishing only</option>
            <option value="legitimate">Legitimate only</option>
          </select>
          <p className="hint">Click a point on the line to see that check's details.</p>
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={shown} margin={{ top: 10, bottom: 20, left: 20, right: 50 }} accessibilityLayer>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="check" allowDecimals={false} tick={AXIS_TICK} label={{ value: "Check number", position: "insideBottom", offset: -10, fill: AXIS_COLOUR }} />
              <YAxis domain={[0, 100]} unit="%" width={76} tick={AXIS_TICK} label={{ value: "Probability (%)", angle: -90, position: "insideLeft", fill: AXIS_COLOUR }} />
              <Tooltip formatter={(v) => v + "%"} labelFormatter={(n) => `Check ${n}`} />
              <Legend verticalAlign="top" />
              <Line type="monotone" dataKey="probability" name="Phishing probability" stroke="#b42318" strokeWidth={2}
                dot={{ r: 5, onClick: onDotClick, style: { cursor: "pointer" } }}
                activeDot={{ r: 8, onClick: onDotClick, style: { cursor: "pointer" } }} />
            </LineChart>
          </ResponsiveContainer>

          {selectedItem && (
            <div className="detail" aria-live="polite">
              <h4>Check {selectedItem.check}</h4>
              <p className="url">{selectedItem.url}</p>
              <p>
                {selectedItem.isPhishing ? "Phishing" : "Legitimate"}, phishing probability {selectedItem.probability}%
              </p>
            </div>
          )}

          <details>
            <summary>View as a table</summary>
            <div className="table-wrap">
            <table>
              <caption>URLs checked this session</caption>
              <thead>
                <tr>
                  <th scope="col">Check</th><th scope="col">URL</th><th scope="col">Result</th>
                  <th scope="col">Phishing probability</th><th scope="col">Details</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((h) => (
                  <tr key={h.check}>
                    <td>{h.check}</td>
                    <td>{h.url}</td>
                    <td>{h.isPhishing ? "Phishing" : "Legitimate"}</td>
                    <td>{h.probability}%</td>
                    <td>
                      <button type="button" className="small" aria-label={`View details for check ${h.check}`} onClick={() => setSelected(h.check)}>
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          </details>
        </section>
      )}
    </main>
  );
}