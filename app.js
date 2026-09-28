const $ = id => document.getElementById(id);
let currentUser = null;

function toast(message) {
  const box = $("toast");
  box.textContent = message;
  box.style.display = "block";
  clearTimeout(window.toastTimer);
  window.toastTimer = setTimeout(() => box.style.display = "none", 3000);
}

function showAuth() {
  currentUser = null;
  localStorage.removeItem("reviewUser");
  $("authScreen").classList.remove("hidden");
  $("appScreen").classList.add("hidden");
}

function showApp(user) {
  currentUser = user;
  localStorage.setItem("reviewUser", JSON.stringify(user));
  $("userName").textContent = user.name;
  $("authScreen").classList.add("hidden");
  $("appScreen").classList.remove("hidden");
  loadHistory();
}

$("loginTab").onclick = () => {
  $("loginTab").classList.add("active");
  $("registerTab").classList.remove("active");
  $("loginForm").classList.remove("hidden");
  $("registerForm").classList.add("hidden");
};

$("registerTab").onclick = () => {
  $("registerTab").classList.add("active");
  $("loginTab").classList.remove("active");
  $("registerForm").classList.remove("hidden");
  $("loginForm").classList.add("hidden");
};

$("loginForm").onsubmit = async e => {
  e.preventDefault();
  const res = await fetch("/api/login", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      email: $("loginEmail").value,
      password: $("loginPassword").value
    })
  });
  const data = await res.json();
  if (!res.ok) return toast(data.message);
  showApp(data);
};

$("registerForm").onsubmit = async e => {
  e.preventDefault();
  const res = await fetch("/api/register", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      name: $("regName").value,
      email: $("regEmail").value,
      password: $("regPassword").value
    })
  });
  const data = await res.json();
  if (!res.ok) return toast(data.message);
  toast("Account created. You are logged in.");
  showApp(data);
};

$("logoutBtn").onclick = showAuth;

$("code").addEventListener("input", () => {
  const n = $("code").value.split(/\r?\n/).length;
  $("lineCount").textContent = `${n} line${n === 1 ? "" : "s"}`;
});

$("language").addEventListener("change", () => {
  $("code").value = "";
  $("lineCount").textContent = "1 line";
  $("emptyResult").classList.remove("hidden");
  $("result").classList.add("hidden");
  $("scoreBadge").textContent = "—";
  $("scoreBadge").className = "score";
});

$("sampleBtn").onclick = () => {
  const lang = $("language").value;

  if (lang === "python") {
    $("code").value =
`password = "mySecret123"
user_input = input("Enter code: ")
result = eval(user_input)
print(result)
try:
    print("done")
except:
    pass`;
  } else if (lang === "java") {
    $("code").value =
`public class Demo {
    public static void main(String[] args) {
        String password = "admin123";
        String a = "hello";
        String b = "hello";
        if (a == b) {
            System.out.println(password);
        }
    }
}`;
  } else if (lang === "cpp") {
    $("code").value =
`#include <bits/stdc++.h>
using namespace std;

int main() {
    string password = "admin123";
    cout << password << endl;
    return 0;
}`;
  } else {
    $("code").value =
`const apiKey = "my-secret-key";
var userInput = prompt("Enter code");
eval(userInput);
console.log(apiKey);`;
  }

  $("code").dispatchEvent(new Event("input"));
};

$("reviewBtn").onclick = async () => {
  const code = $("code").value;
  if (!code.trim()) return toast("Please paste some code first.");

  $("reviewBtn").disabled = true;
  $("reviewBtn").textContent = "Analyzing...";

  try {
    const res = await fetch("/api/review", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        code,
        language: $("language").value,
        userEmail: currentUser.email
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Review failed");
    renderResult(data);
    loadHistory();
  } catch (err) {
    toast(err.message);
  } finally {
    $("reviewBtn").disabled = false;
    $("reviewBtn").textContent = "Analyze Code";
  }
};

function renderResult(data) {
  $("emptyResult").classList.add("hidden");
  $("result").classList.remove("hidden");
  $("bigScore").textContent = data.score;
  $("summary").textContent = data.summary;

  const badge = $("scoreBadge");
  badge.textContent = data.score + "/100";
  badge.className = "score " + (data.score >= 80 ? "good" : data.score >= 60 ? "warn" : "bad");

  const box = $("findings");
  box.innerHTML = "";

  if (!data.findings.length) {
    box.innerHTML = `<div class="finding clean"><strong>No findings 🎉</strong><p>Your submitted code passed the current demo checks.</p></div>`;
    return;
  }

  data.findings.forEach(f => {
    const div = document.createElement("div");
    div.className = "finding";
    div.innerHTML = `
      <div class="finding-top">
        <div>
          <strong>${escapeHtml(f.title)}</strong>
          <span class="line-badge">Line ${f.line}</span>
        </div>
        <span class="sev sev-${escapeHtml(f.severity)}">${escapeHtml(f.kind === "suggestion" ? "Suggestion" : f.severity)}</span>
      </div>
      <div class="code-location">
        <span class="line-number">${f.line}</span>
        <code>${escapeHtml(f.code || "(line content unavailable)")}</code>
      </div>
      <p><b>Why:</b> ${escapeHtml(f.detail)}</p>
      <p class="fix"><b>Fix:</b> ${escapeHtml(f.fix)}</p>
    `;
    box.appendChild(div);
  });
}

async function loadHistory() {
  if (!currentUser) return;
  const res = await fetch("/api/reviews?email=" + encodeURIComponent(currentUser.email));
  const data = await res.json();
  const box = $("history");

  if (!data.length) {
    box.className = "history-empty";
    box.textContent = "No reviews yet.";
    return;
  }

  box.className = "";
  box.innerHTML = data.map(item => `
    <div class="history-item">
      <div>
        <strong>${escapeHtml(item.language)}</strong>
        <div class="muted">${escapeHtml(item.summary)}</div>
      </div>
      <div class="history-score">${item.score}/100</div>
    </div>
  `).join("");
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#039;"
  }[ch]));
}

const saved = localStorage.getItem("reviewUser");
if (saved) {
  try { showApp(JSON.parse(saved)); }
  catch { showAuth(); }
} else {
  showAuth();
}
