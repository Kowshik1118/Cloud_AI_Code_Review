const express = require("express");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { spawnSync } = require("child_process");

const app = express();
const PORT = 5000;

const users = [
  { name: "Demo User", email: "demo@demo.com", password: "demo123" }
];
const reviews = [];

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

function addFinding(findings, lines, line, severity, title, detail, fix, kind = "issue") {
  const safeLine = Math.max(1, Math.min(Number(line) || 1, lines.length || 1));
  findings.push({
    line: safeLine,
    code: lines[safeLine - 1] || "",
    severity,
    title,
    detail,
    fix,
    kind
  });
}

function checkBracketBalance(text, lines, findings) {
  const pairs = { "(": ")", "[": "]", "{": "}" };
  const opening = new Set(Object.keys(pairs));
  const closing = new Set(Object.values(pairs));
  const stack = [];
  let quote = null;
  let escaped = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];

    if (quote) {
      if (escaped) { escaped = false; continue; }
      if (ch === "\\") { escaped = true; continue; }
      if (ch === quote) quote = null;
      continue;
    }

    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      continue;
    }

    if (opening.has(ch)) {
      stack.push({ ch, index: i });
    } else if (closing.has(ch)) {
      const expected = stack.length ? pairs[stack[stack.length - 1].ch] : null;
      if (ch !== expected) {
        const line = text.slice(0, i).split(/\r?\n/).length;
        addFinding(
          findings, lines, line, "High",
          "Mismatched or unexpected bracket",
          `Found "${ch}" but the nearest opening bracket does not expect it.`,
          "Check the opening and closing brackets on this line and nearby lines."
        );
        return;
      }
      stack.pop();
    }
  }

  if (quote) {
    const line = text.split(/\r?\n/).length;
    addFinding(
      findings, lines, line, "High",
      "Unclosed string",
      `A ${quote}-quoted string appears to continue to the end of the submitted code.`,
      "Close the string with the matching quote."
    );
  }

  if (stack.length) {
    const last = stack[stack.length - 1];
    const line = text.slice(0, last.index).split(/\r?\n/).length;
    addFinding(
      findings, lines, line, "High",
      "Unclosed bracket or brace",
      `The "${last.ch}" opened on this line does not have a matching closing bracket.`,
      "Add the missing closing bracket/brace or correct the surrounding block."
    );
  }
}

function hasTrailingSemicolon(line) {
  const t = line.trim();
  return t.endsWith(";") || t.endsWith("{") || t.endsWith("}") || t.endsWith(":") ||
         t.startsWith("//") || t.startsWith("#") || t === "";
}

function analyzeJavaScript(lines, findings) {
  lines.forEach((line, i) => {
    const n = i + 1;
    const t = line.trim();

    if (/\bvar\s+[A-Za-z_$]/.test(line)) {
      addFinding(findings, lines, n, "Low", "Prefer let or const",
        "var is function-scoped and can make modern JavaScript code harder to reason about.",
        "Use const when the variable is not reassigned, otherwise use let.", "suggestion");
    }

    if (/\binnerHTML\s*=/.test(line)) {
      addFinding(findings, lines, n, "High", "Potential XSS risk",
        "Direct innerHTML assignment can be unsafe when the value contains untrusted input.",
        "Use textContent for plain text or sanitize HTML with a trusted sanitizer.");
    }

    if (/\beval\s*\(/.test(line)) {
      addFinding(findings, lines, n, "High", "Use of eval()",
        "eval() can execute unexpected code and is dangerous with untrusted input.",
        "Avoid eval(); parse and validate the expected data instead.");
    }

    if (/^\s*(if|for|while)\s*\(.*\)\s*[^({]/.test(line) && !line.includes("{")) {
      addFinding(findings, lines, n, "Low", "Missing braces",
        "A control statement without braces is easier to break during later edits.",
        "Use { } around the control-statement body.", "suggestion");
    }

    if (/^\s*(const|let)\s+[A-Za-z_$][\w$]*\s*=/.test(line) &&
        !line.trim().endsWith(";") && !line.trim().endsWith("{")) {
      addFinding(findings, lines, n, "Medium", "Possible missing semicolon",
        "This variable declaration appears to end without a semicolon.",
        "Add ';' at the end of the declaration.");
    }
  });
}

function analyzePython(lines, findings) {
  let previousIndent = 0;

  lines.forEach((line, i) => {
    const n = i + 1;
    const t = line.trim();
    if (!t || t.startsWith("#")) return;

    const indent = line.match(/^\s*/)[0].replace(/\t/g, "    ").length;

    if (/^\s*except\s*:\s*$/.test(line)) {
      addFinding(findings, lines, n, "Medium", "Broad exception handling",
        "Catching every exception can hide unexpected failures.",
        "Catch the specific exceptions you expect.", "suggestion");
    }

    if (/\binput\s*\(.*\)\s*\)?\s*.*\beval\s*\(/.test(line) || /\beval\s*\(\s*input\s*\(/.test(line)) {
      addFinding(findings, lines, n, "Critical", "Unsafe input evaluation",
        "User input is being passed to eval(), allowing arbitrary Python expressions to execute.",
        "Never eval untrusted input. Parse and validate the expected data type instead.");
    }

    if (/^\s*(def|if|elif|else|for|while|class|try|except|finally|with)\b/.test(line) &&
        !t.endsWith(":") && !t.endsWith("#")) {
      addFinding(findings, lines, n, "High", "Missing colon",
        "This Python block statement does not end with ':'.",
        "Add ':' at the end of the block statement.");
    }

    if (/^\s*def\s+\w+\s*\([^)]*\)\s*$/.test(line)) {
      addFinding(findings, lines, n, "High", "Missing colon",
        "A Python function declaration must end with ':'.",
        "Add ':' after the function signature.");
    }

    if (indent > 0 && i > 0 && previousIndent === 0 &&
        /^(return|pass|break|continue|print)\b/.test(t) &&
        !/^(def|if|elif|else|for|while|class|try|except|finally|with)\b/.test(lines[i - 1].trim())) {
      // Do not report normal indented code; only a very obvious top-level indentation case.
      if (/^\s{1,3}\S/.test(line) && !/^\s{4,}/.test(line)) {
        addFinding(findings, lines, n, "Medium", "Unexpected indentation",
          "This line is indented even though the previous line does not open a block.",
          "Remove the indentation or place the line inside the correct block.");
      }
    }

    previousIndent = indent;
  });
}

function analyzeJava(lines, findings) {
  lines.forEach((line, i) => {
    const n = i + 1;
    const t = line.trim();

    if (/\bString\s+(password|apiKey|secret|token)\s*=\s*"/i.test(line)) {
      addFinding(findings, lines, n, "Critical", "Hard-coded credential",
        "A credential-like value is stored directly in a Java string.",
        "Read secrets from environment variables or a secure secret manager.");
    }

    if (/\b==\s*".*"|".*"\s*==/.test(line)) {
      addFinding(findings, lines, n, "High", "String comparison with ==",
        "Java String values should normally be compared by value with equals(), not ==.",
        "Use value.equals(other) or Objects.equals(a, b).");
    }

    if (/^\s*(System\.out\.|System\.err\.)/.test(line)) {
      // Informational only: normal console output is not a correctness error.
    }

    if (/^\s*(int|double|float|long|boolean|String|char)\s+\w+\s*=/.test(line) &&
        !t.endsWith(";") && !t.endsWith("{")) {
      addFinding(findings, lines, n, "High", "Possible missing semicolon",
        "This Java declaration appears to end without a semicolon.",
        "Add ';' at the end of the statement.");
    }
  });
}

function analyzeCpp(lines, findings) {
  lines.forEach((line, i) => {
    const n = i + 1;
    const t = line.trim();

    if (/#include\s*<bits\/stdc\+\+\.h>/.test(line)) {
      addFinding(findings, lines, n, "Low", "Non-standard convenience header",
        "bits/stdc++.h is common in competitive programming but is not a standard C++ header.",
        "Include only the standard headers your program actually needs.", "suggestion");
    }

    if (/\bgets\s*\(/.test(line)) {
      addFinding(findings, lines, n, "Critical", "Unsafe gets()",
        "gets() cannot safely limit input size and is removed from modern C++ standards.",
        "Use std::getline or another bounded input method.");
    }

    if (/^\s*(int|double|float|long|bool|char|string)\s+\w+\s*=/.test(line) &&
        !t.endsWith(";") && !t.endsWith("{")) {
      addFinding(findings, lines, n, "High", "Possible missing semicolon",
        "This C++ declaration appears to end without a semicolon.",
        "Add ';' at the end of the statement.");
    }
  });
}


function addSyntaxFinding(findings, lines, line, message, fix) {
  addFinding(
    findings, lines, line, "Critical",
    "Syntax error detected by compiler/interpreter",
    message,
    fix
  );
}

function parseCompilerLine(output, language, lines) {
  const text = String(output || "");
  let m;

  if (language === "javascript") {
    m = text.match(/:(\d+)\s*\n.*?SyntaxError:\s*(.+)/s);
    if (m) return { line: Number(m[1]), message: m[2].trim() };
    m = text.match(/:(\d+)\n/);
    if (m) return { line: Number(m[1]), message: text.trim().split("\n").slice(-1)[0] };
  }

  if (language === "python") {
    m = text.match(/File ".*?", line (\d+)\s*\n(?:.*\n)*?\s*\^\s*\n([^\n]+)/);
    if (m) return { line: Number(m[1]), message: m[2].trim() };
    m = text.match(/File ".*?", line (\d+)/);
    if (m) return { line: Number(m[1]), message: text.trim().split("\n").slice(-1)[0] };
  }

  if (language === "java") {
    m = text.match(/\.java:(\d+):\s*(?:error:\s*)?(.+)/);
    if (m) return { line: Number(m[1]), message: m[2].trim() };
  }

  if (language === "cpp") {
    m = text.match(/:(\d+):\d+:\s*(?:error|fatal error):\s*(.+)/);
    if (m) return { line: Number(m[1]), message: m[2].trim() };
  }

  return null;
}

function runRealSyntaxCheck(code, language, lines, findings) {
  const lang = String(language || "").toLowerCase();
  let command, args, cwd = os.tmpdir(), filePath;

  try {
    if (lang === "javascript") {
      filePath = path.join(os.tmpdir(), `code_review_${process.pid}_${Date.now()}.js`);
      fs.writeFileSync(filePath, code, "utf8");
      command = process.execPath;
      args = ["--check", filePath];
    } else if (lang === "python") {
      filePath = path.join(os.tmpdir(), `code_review_${process.pid}_${Date.now()}.py`);
      fs.writeFileSync(filePath, code, "utf8");
      command = process.platform === "win32" ? "python" : "python3";
      args = ["-m", "py_compile", filePath];
    } else if (lang === "java") {
      const match = code.match(/\bpublic\s+class\s+([A-Za-z_$][\w$]*)/);
      const className = match ? match[1] : "CodeReviewTemp";
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "code-review-java-"));
      cwd = dir;
      filePath = path.join(dir, `${className}.java`);
      fs.writeFileSync(filePath, code, "utf8");
      command = "javac";
      args = ["-Xlint:none", filePath];
    } else if (lang === "cpp") {
      filePath = path.join(os.tmpdir(), `code_review_${process.pid}_${Date.now()}.cpp`);
      fs.writeFileSync(filePath, code, "utf8");
      command = process.platform === "win32" ? "g++" : "g++";
      args = ["-std=c++17", "-fsyntax-only", filePath];
    } else {
      return;
    }

    const result = spawnSync(command, args, {
      cwd,
      encoding: "utf8",
      timeout: 10000,
      windowsHide: true
    });

    if (result.error && result.error.code === "ENOENT") {
      // Tool not installed on the machine. Static checks still run.
      return;
    }

    if (result.status !== 0) {
      const output = `${result.stderr || ""}\n${result.stdout || ""}`.trim();
      const parsed = parseCompilerLine(output, lang, lines);
      if (parsed) {
        addSyntaxFinding(
          findings,
          lines,
          parsed.line,
          parsed.message || "The compiler/interpreter reported invalid syntax.",
          "Fix the reported syntax error on this line, then analyze the code again."
        );
      } else {
        addSyntaxFinding(
          findings,
          lines,
          1,
          output.split(/\r?\n/).filter(Boolean).slice(-1)[0] ||
            "The compiler/interpreter rejected the submitted code.",
          "Read the compiler/interpreter message and correct the reported syntax."
        );
      }
    }
  } catch (err) {
    // Never make the web app fail because an optional local compiler is unavailable.
  } finally {
    if (filePath) {
      try { fs.rmSync(filePath, { force: true }); } catch {}
    }
    // Java compilation can create .class files and the temporary directory.
    if (cwd && cwd !== os.tmpdir() && cwd.startsWith(os.tmpdir())) {
      try { fs.rmSync(cwd, { recursive: true, force: true }); } catch {}
    }
  }
}


function checkLanguageMismatch(lines, language, findings) {
  const lang = String(language || "").toLowerCase();
  const text = lines.join("\n");

  const patterns = {
    javascript: [
      { re: /\b(const|let|var)\s+[A-Za-z_$][\w$]*\s*=/, line: "declaration" },
      { re: /\bconsole\.(log|error|warn)\s*\(/, line: "console.log()" },
      { re: /\b(prompt|alert|confirm)\s*\(/, line: "browser API" },
      { re: /\beval\s*\(/, line: "eval()" },
      { re: /=>/, line: "arrow function" }
    ],
    python: [
      { re: /^\s*(def|elif|except|print)\b/m, line: "Python statement" },
      { re: /\bimport\s+[A-Za-z_][\w.]*(\s+as\s+\w+)?\s*$/m, line: "Python import" },
      { re: /\bTrue\b|\bFalse\b|\bNone\b/, line: "Python literal" }
    ],
    java: [
      { re: /\bpublic\s+class\s+\w+/, line: "Java class declaration" },
      { re: /\bSystem\.out\.println\s*\(/, line: "System.out.println()" },
      { re: /\bpublic\s+static\s+void\s+main\s*\(/, line: "Java main method" },
      { re: /\bString\s+\w+\s*=/, line: "Java String declaration" }
    ],
    cpp: [
      { re: /^\s*#include\s*<[^>]+>/m, line: "#include" },
      { re: /\bstd::(cout|cin|string|vector)\b/, line: "std:: usage" },
      { re: /\busing\s+namespace\s+std\s*;/, line: "using namespace std" },
      { re: /\bint\s+main\s*\(/, line: "C++ main()" }
    ]
  };

  // Strong cross-language signatures. These are deliberately conservative.
  const strong = {
    javascript: [/\bconsole\.log\s*\(/, /\b(prompt|alert|confirm)\s*\(/, /=>/],
    python: [/^\s*def\s+\w+\s*\(/m, /^\s*print\s*\(/m, /^\s*elif\b/m],
    java: [/\bpublic\s+class\s+\w+/, /\bSystem\.out\.println\s*\(/, /\bpublic\s+static\s+void\s+main\s*\(/],
    cpp: [/^\s*#include\s*</m, /\bstd::(cout|cin|string|vector)\b/, /\busing\s+namespace\s+std\s*;/]
  };

  let detected = null;
  let hits = 0;
  for (const [candidate, regs] of Object.entries(strong)) {
    const count = regs.filter(r => r.test(text)).length;
    if (count > hits) {
      hits = count;
      detected = candidate;
    }
  }

  if (detected && detected !== lang && hits >= 1) {
    const display = { javascript: "JavaScript", python: "Python", java: "Java", cpp: "C++" };
    let line = 1;

    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      const matched = (strong[detected] || []).some(r => {
        try { return r.test(lineText); } catch { return false; }
      });
      if (matched) { line = i + 1; break; }
    }

    addFinding(
      findings, lines, line, "Critical",
      "Possible language mismatch",
      `The selected language is ${display[lang] || lang}, but the submitted code contains a strong ${display[detected]}-style pattern (${detected === "javascript" ? "console.log/prompt/arrow syntax" : detected === "python" ? "def/print/elif syntax" : detected === "java" ? "Java class/System.out syntax" : "#include/std:: syntax"}).`,
      `Select ${display[detected]} in the language dropdown, or rewrite the code using ${display[lang] || lang} syntax.`
    );
  }
}

function analyzeCode(code, language) {
  const text = String(code || "");
  const lines = text.split(/\r?\n/);
  const findings = [];
  const lang = String(language || "javascript").toLowerCase();

  if (!text.trim()) {
    return {
      score: 0,
      summary: "No code was submitted.",
      findings: [{
        line: 1, code: "", severity: "Critical",
        title: "Empty code",
        detail: "Paste source code and run the review.",
        fix: "Paste the code you want to review.",
        kind: "issue"
      }]
    };
  }

  // First check whether the selected language matches the code.
  checkLanguageMismatch(lines, lang, findings);

  // Use the installed language compiler/interpreter when available.
  // This makes real syntax errors show up at their actual line when the tool exists.
  runRealSyntaxCheck(text, lang, lines, findings);

  // Security/correctness checks common to multiple languages.
  lines.forEach((line, i) => {
    const n = i + 1;

    if (/(password|api[_-]?key|secret|token)\s*[:=]\s*["'][^"']+["']/i.test(line)) {
      addFinding(findings, lines, n, "Critical", "Possible hard-coded secret",
        "A password, API key, secret or token appears directly in the source code.",
        "Move secrets to environment variables or a secure secret manager.");
    }

    if (/\b(SELECT|INSERT|UPDATE|DELETE)\b.*\+/.test(line)) {
      addFinding(findings, lines, n, "High", "Possible SQL injection pattern",
        "SQL appears to be constructed using string concatenation.",
        "Use parameterized queries or prepared statements.");
    }

    if (line.length > 140) {
      addFinding(findings, lines, n, "Low", "Long line",
        "This line is longer than 140 characters and may be harder to maintain.",
        "Split the expression into smaller readable parts.", "suggestion");
    }
  });

  if (lang === "javascript") analyzeJavaScript(lines, findings);
  else if (lang === "python") analyzePython(lines, findings);
  else if (lang === "java") analyzeJava(lines, findings);
  else if (lang === "cpp") analyzeCpp(lines, findings);

  checkBracketBalance(text, lines, findings);

  const unique = [];
  const seen = new Set();
  for (const f of findings) {
    const key = `${f.line}|${f.title}|${f.detail}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(f);
    }
  }

  // Suggestions are displayed but do not reduce the quality score.
  const deductions = { Critical: 35, High: 20, Medium: 10, Low: 0 };
  const score = Math.max(0, Math.min(100,
    100 - unique
      .filter(f => f.kind !== "suggestion")
      .reduce((sum, f) => sum + (deductions[f.severity] || 0), 0)
  ));

  let summary;
  if (!unique.filter(f => f.kind !== "suggestion").length) {
    summary = unique.length
      ? "No correctness or security errors were detected. Minor suggestions are shown below."
      : "No issues were detected in the submitted code.";
  } else if (score >= 80) {
    summary = "Good code, but a few important issues should be fixed.";
  } else if (score >= 60) {
    summary = "Several issues were detected. Review the line-by-line findings.";
  } else {
    summary = "Important issues were detected. Fix the critical and high findings first.";
  }

  return {
    score,
    summary,
    findings: unique.sort((a, b) => a.line - b.line)
  };
}

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u =>
    u.email.toLowerCase() === String(email || "").toLowerCase() &&
    u.password === password
  );
  if (!user) return res.status(401).json({ message: "Invalid email or password." });
  res.json({ name: user.name, email: user.email });
});

app.post("/api/register", (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ message: "All fields are required." });
  if (users.some(u => u.email.toLowerCase() === String(email).toLowerCase()))
    return res.status(409).json({ message: "Email already registered." });

  const user = { name, email, password };
  users.push(user);
  res.json({ name: user.name, email: user.email });
});

app.post("/api/review", (req, res) => {
  const { code, language, userEmail } = req.body;
  const result = analyzeCode(code, language || "javascript");

  const item = {
    id: Date.now(),
    language: language || "javascript",
    score: result.score,
    summary: result.summary,
    findings: result.findings,
    createdAt: new Date().toISOString()
  };

  reviews.unshift({ ...item, userEmail: userEmail || "demo@demo.com" });
  res.json(item);
});

app.get("/api/reviews", (req, res) => {
  const email = String(req.query.email || "demo@demo.com");
  res.json(reviews.filter(r => r.userEmail === email).slice(0, 20));
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true, database: false, message: "Running without a database." });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Cloud AI Code Review Platform running at http://localhost:${PORT}`);
  console.log("Database: NONE");
  console.log("Demo login: demo@demo.com / demo123");
});
