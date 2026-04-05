import { useMemo, useState } from "react";

const DEFAULT_HASH =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

function pretty(data) {
  return JSON.stringify(data, null, 2);
}

function bytesToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function requestJson(url, options = {}) {
  const res = await fetch(url, options);
  const contentType = res.headers.get("content-type") || "";
  const payload = contentType.includes("application/json")
    ? await res.json()
    : await res.text();

  if (!res.ok) {
    const error = new Error(`HTTP ${res.status}`);
    error.payload = payload;
    throw error;
  }
  return payload;
}

export default function App() {
  const [baseUrl, setBaseUrl] = useState("http://localhost:8080");
  const [dkgId, setDkgId] = useState(`session_${Date.now()}`);
  const [threshold, setThreshold] = useState(2);
  const [keyType, setKeyType] = useState("ETH");
  const [docHash, setDocHash] = useState(DEFAULT_HASH);
  const [hashingFile, setHashingFile] = useState(false);
  const [selectedFileName, setSelectedFileName] = useState("");
  const [busy, setBusy] = useState(false);
  const [lastAction, setLastAction] = useState("idle");
  const [output, setOutput] = useState({
    health: null,
    dkg: null,
    timestamp: null,
    error: null,
  });

  const cleanBaseUrl = useMemo(() => baseUrl.replace(/\/$/, ""), [baseUrl]);

  function setError(action, error) {
    setOutput((prev) => ({
      ...prev,
      error: {
        action,
        message: error.message,
        payload: error.payload || null,
      },
    }));
  }

  async function hashSelectedFile(event) {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    setHashingFile(true);
    setSelectedFileName(file.name);
    try {
      const fileBuffer = await file.arrayBuffer();
      const digest = await crypto.subtle.digest("SHA-256", fileBuffer);
      const computedHash = bytesToHex(digest);
      setDocHash(computedHash);
      setOutput((prev) => ({ ...prev, error: null }));
    } catch (error) {
      setError("hash", error);
    } finally {
      setHashingFile(false);
    }
  }

  async function runHealth() {
    setBusy(true);
    setLastAction("health");
    try {
      const data = await requestJson(`${cleanBaseUrl}/health`);
      setOutput((prev) => ({ ...prev, health: data, error: null }));
    } catch (error) {
      setError("health", error);
    } finally {
      setBusy(false);
    }
  }

  async function runDkg(event) {
    event.preventDefault();
    setBusy(true);
    setLastAction("dkg");
    try {
      const payload = {
        dkg_id: dkgId,
        threshold: Number(threshold),
        key_type: keyType,
      };
      const data = await requestJson(`${cleanBaseUrl}/public/dkg/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      setOutput((prev) => ({ ...prev, dkg: data, error: null }));
    } catch (error) {
      setError("dkg", error);
    } finally {
      setBusy(false);
    }
  }

  async function runTimestamp(event) {
    event.preventDefault();
    setBusy(true);
    setLastAction("timestamp");
    try {
      const payload = {
        document_hash: docHash.trim(),
        key_type: keyType,
      };
      const data = await requestJson(`${cleanBaseUrl}/public/timestamp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      setOutput((prev) => ({ ...prev, timestamp: data, error: null }));
    } catch (error) {
      setError("timestamp", error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <div className="backdrop" />
      <header className="hero">
        <p className="eyebrow">PV204 Threshold Signing</p>
        <h1>GigaTimestamp</h1>
        <p className="subtitle">
          Control your node cluster, initialize DKG sessions, and mint trusted
          timestamp signatures from one dashboard.
        </p>
      </header>

      <main className="grid">
        <section className="panel">
          <h2>Connection</h2>
          <label>
            Base URL
            <input
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="http://localhost:8080"
            />
          </label>
          <button disabled={busy} onClick={runHealth}>
            {busy && lastAction === "health" ? "Checking..." : "Check /health"}
          </button>
        </section>

        <section className="panel">
          <h2>Distributed Key Generation</h2>
          <form onSubmit={runDkg}>
            <label>
              DKG ID
              <input value={dkgId} onChange={(e) => setDkgId(e.target.value)} />
            </label>

            <div className="split">
              <label>
                Threshold
                <input
                  type="number"
                  min="2"
                  value={threshold}
                  onChange={(e) => setThreshold(e.target.value)}
                />
              </label>

              <label>
                Key Type
                <select value={keyType} onChange={(e) => setKeyType(e.target.value)}>
                  <option value="ETH">ETH</option>
                  <option value="BTC">BTC</option>
                </select>
              </label>
            </div>

            <button disabled={busy} type="submit">
              {busy && lastAction === "dkg" ? "Initializing..." : "Run DKG"}
            </button>
          </form>
        </section>

        <section className="panel">
          <h2>Timestamp Request</h2>
          <form onSubmit={runTimestamp}>
            <label>
              File Upload (local hash only)
              <input type="file" onChange={hashSelectedFile} />
            </label>
            {selectedFileName ? (
              <p>
                {hashingFile
                  ? `Hashing ${selectedFileName}...`
                  : `Loaded ${selectedFileName} and updated document hash.`}
              </p>
            ) : null}

            <label>
              Document Hash (64 hex chars)
              <textarea
                rows={3}
                value={docHash}
                onChange={(e) => setDocHash(e.target.value)}
              />
            </label>
            <button disabled={busy} type="submit">
              {busy && lastAction === "timestamp" ? "Signing..." : "Create Timestamp"}
            </button>
          </form>
        </section>
      </main>

      <section className="panel output">
        <h2>Output</h2>
        {output.error ? (
          <div className="errorbox">
            <strong>{output.error.action} failed:</strong>
            <pre>{pretty(output.error)}</pre>
          </div>
        ) : null}

        <div className="output-grid">
          <article>
            <h3>Health</h3>
            <pre>{output.health ? pretty(output.health) : "No data yet"}</pre>
          </article>
          <article>
            <h3>DKG</h3>
            <pre>{output.dkg ? pretty(output.dkg) : "No data yet"}</pre>
          </article>
          <article>
            <h3>Timestamp</h3>
            <pre>{output.timestamp ? pretty(output.timestamp) : "No data yet"}</pre>
          </article>
        </div>
      </section>
    </div>
  );
}
