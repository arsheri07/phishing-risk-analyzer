// SECURITY NOTE: this extension never sends anything to any server
// except the one YOU configure below (your own deployed Phishing Risk Analyzer
// backend). It has no hardcoded server, no API keys, and no analytics.
// The only permission it requests is reading the active tab's URL.

let currentUrl = "";

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentUrl = tab.url || "";
  document.getElementById("current-url").textContent = currentUrl || "(no URL detected)";

  const stored = await chrome.storage.sync.get("backendUrl");
  if (stored.backendUrl) {
    document.getElementById("backend-url").value = stored.backendUrl;
  } else {
    document.getElementById("settings-form").style.display = "block";
  }
}

document.getElementById("settings-link").addEventListener("click", () => {
  const form = document.getElementById("settings-form");
  form.style.display = form.style.display === "block" ? "none" : "block";
});

document.getElementById("backend-url").addEventListener("change", async (e) => {
  await chrome.storage.sync.set({ backendUrl: e.target.value.trim() });
});

document.getElementById("analyze-btn").addEventListener("click", async () => {
  const errorBox = document.getElementById("error");
  const resultBox = document.getElementById("result");
  errorBox.style.display = "none";
  resultBox.style.display = "none";

  const stored = await chrome.storage.sync.get("backendUrl");
  const backendUrl = (stored.backendUrl || "").replace(/\/$/, "");

  if (!backendUrl) {
    errorBox.textContent = "Set your Phishing Risk Analyzer server URL below first (⚙ configure).";
    errorBox.style.display = "block";
    document.getElementById("settings-form").style.display = "block";
    return;
  }

  if (!currentUrl || !currentUrl.startsWith("http")) {
    errorBox.textContent = "This tab doesn't have a checkable URL.";
    errorBox.style.display = "block";
    return;
  }

  const btn = document.getElementById("analyze-btn");
  btn.disabled = true;
  btn.textContent = "Analyzing…";

  try {
    const response = await fetch(`${backendUrl}/api/analyze/website`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl }),
    });
    const data = await response.json();

    if (!response.ok) {
      errorBox.textContent = data.error || "Something went wrong.";
      errorBox.style.display = "block";
      return;
    }

    document.getElementById("stamp").textContent = data.verdict;
    document.getElementById("stamp").className = "stamp " + data.verdict.toLowerCase();
    document.getElementById("score").textContent = `${data.score}/100`;

    const reasonsList = document.getElementById("reasons");
    if (data.reasons.length === 0) {
      reasonsList.innerHTML = "<li>No suspicious signals found.</li>";
    } else {
      reasonsList.innerHTML = data.reasons
        .map(r => `<li>+${r.points}: ${escapeHtml(r.reason)}</li>`)
        .join("");
    }
    resultBox.style.display = "block";
  } catch (err) {
    errorBox.textContent = "Could not reach your Phishing Risk Analyzer server. Check the URL in settings.";
    errorBox.style.display = "block";
  } finally {
    btn.disabled = false;
    btn.textContent = "Analyze this site";
  }
});

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

init();
