const $ = (id) => document.getElementById(id);
const defang = (s) => s.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
const CIRC = 2 * Math.PI * 54; // matches the r=54 circle in index.html

// Bands come from the server so thresholds are defined in one place (app.py).
function buildScale(bands) {
  const scale = $("scale"), legend = $("legend");
  scale.querySelectorAll(".seg").forEach((s) => s.remove());
  legend.replaceChildren();
  bands.forEach((b, i) => {
    const next = i + 1 < bands.length ? bands[i + 1].min : 100;
    const seg = el("div", "", "seg " + b.level);
    seg.style.flexGrow = next - b.min;
    scale.insertBefore(seg, $("marker"));
    legend.append(el("li", `${b.label} ${b.min}\u2013${i + 1 < bands.length ? next - 1 : 100}%`, b.level));
  });
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text) e.textContent = text;       // textContent only, never innerHTML
  if (cls) e.className = cls;
  return e;
}

async function init() {
  try {
    const m = await (await fetch("/api/mode")).json();
    $("mode").textContent = m.redirect_tracing
      ? "Redirect tracing is on: the server will contact the link to follow its redirects."
      : "Static analysis only: this site never contacts the link you enter.";
  } catch { /* mode banner is optional */ }
}

function show(d) {
  $("error").hidden = true;
  $("result").hidden = false;
  $("result").dataset.level = d.level;
  $("score-num").textContent = d.score;
  const label = (d.bands.find((b) => b.level === d.level) || {}).label || "";
  $("level").textContent = label;
  $("gauge").setAttribute("aria-label", `Risk score ${d.score} percent: ${label}`);
  $("arc").style.strokeDashoffset = CIRC * (1 - d.score / 100);
  $("marker").style.left = d.score + "%";
  buildScale(d.bands);
  $("checked-url").textContent = d.url;

  const list = $("findings");
  list.replaceChildren();
  if (!d.findings.length) list.append(el("li", "No suspicious indicators found."));
  for (const f of d.findings) {
    const li = el("li");
    li.append(el("strong", f.message));
    if (f.why) li.append(el("span", f.why));
    list.append(li);
  }

  const chain = d.redirect_chain;
  $("chain-wrap").hidden = !(chain && chain.length > 1);
  $("chain").replaceChildren();
  if (chain && chain.length > 1) {
    for (const hop of chain) {
      const li = el("li");
      li.append(el("code", defang(hop)));
      $("chain").append(li);
    }
  }
}

$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("go");
  btn.disabled = true;
  btn.textContent = "Checking...";
  try {
    const r = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: $("url").value.trim() }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Enter a valid URL.");
    show(data);
  } catch (err) {
    $("result").hidden = true;
    $("error").textContent = err.message;
    $("error").hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = "Check link";
  }
});

init();
