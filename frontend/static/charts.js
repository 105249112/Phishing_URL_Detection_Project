const data = JSON.parse(document.getElementById("data").textContent);
const cfg = { responsive: true, displaylogo: false };
const layoutBase = { margin: { t: 40, r: 10, b: 50, l: 55 }, legend: { orientation: "h", y: -0.3 } };

// Loading state
document.getElementById("form").addEventListener("submit", () => {
  document.getElementById("btn").disabled = true;
  document.getElementById("loading").textContent = "Checking...";
});

// Chart 1: class probabilities for the current check
if (data.current !== null && document.getElementById("chart1")) {
  const p = data.current;
  Plotly.newPlot("chart1", [
    { type: "bar", name: "Phishing", x: ["Phishing"], y: [p], marker: { color: "#b42318" }, hovertemplate: "Phishing: %{y:.1%}<extra></extra>" },
    { type: "bar", name: "Legitimate", x: ["Legitimate"], y: [1 - p], marker: { color: "#067647" }, hovertemplate: "Legitimate: %{y:.1%}<extra></extra>" },
  ], { ...layoutBase, title: "Class probabilities (latest check)", yaxis: { title: "Probability", range: [0, 1], tickformat: ".0%" }, xaxis: { title: "Class" } }, cfg);
}

// Chart 2: phishing probability per check, filterable
function drawHistory(filter) {
  let rows = data.history;
  if (filter !== "all") {
    rows = data.history.filter(h => h.label === filter);
  }
  Plotly.newPlot("chart2", [{
    type: "scatter", mode: "lines+markers", name: "Phishing probability",
    x: rows.map(h => h.n), y: rows.map(h => h.phishing_prob),
    text: rows.map(h => h.url), line: { color: "#1d4ed8" },
    hovertemplate: "Check %{x}<br>%{y:.1%}<br>%{text}<extra></extra>",
  }], { ...layoutBase, title: "Phishing probability per check", yaxis: { title: "Phishing probability", range: [0, 1], tickformat: ".0%" }, xaxis: { title: "Check number", dtick: 1 } }, cfg);
}
if (document.getElementById("chart2")) {
  drawHistory("all");
  document.getElementById("filter").addEventListener("change", e => drawHistory(e.target.value));
}
