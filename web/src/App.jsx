import { useMemo, useState } from "react";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

const DEFAULT_HASH =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

function pretty(data) {
  return JSON.stringify(data, null, 2);
}

function bytesToHex(bufferOrUint8) {
  const bytes = bufferOrUint8 instanceof Uint8Array ? bufferOrUint8 : new Uint8Array(bufferOrUint8);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  const h = hex.replace(/^0x/, "");
  const padded = h.length % 2 === 0 ? h : "0" + h;
  const result = new Uint8Array(padded.length / 2);
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  return result;
}

/**
 * Verify a pyfrost Schnorr signature in the browser.
 *
 * ETH challenge (from pyfrost eth_utils.py):
 *   e = SHA256(abi.encodePacked(pubkey_x_bytes32, y_parity_uint8, message_bytes32, nonce_address_20bytes))
 *
 * Verification:
 *   P_check = s·G + e·PK
 *   valid = keccak256(P_check_x || P_check_y)[12:] == signature.nonce
 *
 * @param {object} sigObj  - Signature object from the API (signature field is "0x..." hex string)
 * @param {string} docHash - 64-char hex document hash
 * @param {string} ts      - ISO 8601 timestamp string
 * @returns {{ valid: boolean, reason: string }}
 */
function verifyEthSchnorr(sigObj, docHash, ts) {
  try {
    // 1. Reconstruct and check binding
    const encoder = new TextEncoder();
    const binding = `${docHash}|${ts}`;
    const expectedMsg = bytesToHex(sha256(encoder.encode(binding)));
    if (expectedMsg !== sigObj.message) {
      return { valid: false, reason: "Binding mismatch: timestamp or document hash does not match the signed message." };
    }

    // 2. Parse inputs
    const pubkeyX = sigObj.public_key.x.replace(/^0x/, "").padStart(64, "0");
    const yParity = sigObj.public_key.y_parity; // 0 = even (02), 1 = odd (03)
    const messageHex = sigObj.message.replace(/^0x/, "").padStart(64, "0");
    const nonceAddr = sigObj.nonce; // Ethereum address "0x..."

    // 3. Compute ETH challenge: SHA256(abi.encodePacked(bytes32, uint8, bytes32, address))
    //    Layout: 32 + 1 + 32 + 20 = 85 bytes
    const packed = new Uint8Array(85);
    packed.set(hexToBytes(pubkeyX), 0);                        // bytes32 pubkey_x
    packed[32] = yParity;                                      // uint8 y_parity
    packed.set(hexToBytes(messageHex), 33);                    // bytes32 message
    packed.set(hexToBytes(nonceAddr.slice(2).padStart(40, "0")), 65); // address (20 bytes)
    const challenge = sha256(packed);
    const eBig = BigInt("0x" + bytesToHex(challenge));

    // 4. Reconstruct public key point (compressed SEC1 format: 02/03 + x)
    const prefix = yParity === 0 ? "02" : "03";
    const PK = secp256k1.Point.fromHex(prefix + pubkeyX);

    // 5. Parse signature scalar s (stored as hex string "0x..." to avoid JS float precision loss)
    const sBig = BigInt(sigObj.signature);

    // 6. P_check = s·G + e·PK
    const sG = secp256k1.Point.BASE.multiply(sBig);
    const ePK = PK.multiply(eBig);
    const P_check = sG.add(ePK);

    // 7. Derive Ethereum address: keccak256(uncompressed_x || uncompressed_y)[12:]
    //    getAffine() returns {x, y} as BigInts
    const aff = P_check.toAffine();
    const xBytes = hexToBytes(aff.x.toString(16).padStart(64, "0"));
    const yBytes = hexToBytes(aff.y.toString(16).padStart(64, "0"));
    const xyBytes = new Uint8Array(64);
    xyBytes.set(xBytes, 0);
    xyBytes.set(yBytes, 32);
    const pkHash = keccak_256(xyBytes);
    const derivedAddr = "0x" + bytesToHex(pkHash.slice(12));

    const valid = derivedAddr.toLowerCase() === nonceAddr.toLowerCase();
    return {
      valid,
      reason: valid
        ? "Signature is valid."
        : `Address mismatch. Derived: ${derivedAddr}, expected: ${nonceAddr}`,
    };
  } catch (err) {
    return { valid: false, reason: `Verification error: ${err.message}` };
  }
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
  const [baseUrl, setBaseUrl] = useState(
    import.meta.env.VITE_API_URL || "http://localhost:8080"
  );
  const [dkgId, setDkgId] = useState(`session_${Date.now()}`);
  const [threshold, setThreshold] = useState(
    import.meta.env.VITE_THRESHOLD || 2
  );
  const [keyType, setKeyType] = useState(
    import.meta.env.VITE_KEY_TYPE || "ETH"
  );
  const [docHash, setDocHash] = useState(DEFAULT_HASH);
  const [hashingFile, setHashingFile] = useState(false);
  const [selectedFileName, setSelectedFileName] = useState("");
  const [busy, setBusy] = useState(false);
  const [lastAction, setLastAction] = useState("idle");
  const [output, setOutput] = useState({
    health: null,
    dkg: null,
    timestamp: null,
    verify: null,
    error: null,
  });

  // Verify panel state — pre-filled from the last timestamp response when possible
  const [verifyDocHash, setVerifyDocHash] = useState("");
  const [verifyTimestamp, setVerifyTimestamp] = useState("");
  const [verifySignature, setVerifySignature] = useState("");
  const [verifyHashingFile, setVerifyHashingFile] = useState(false);
  const [verifyFileName, setVerifyFileName] = useState("");

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

  async function syncThresholdToNode() {
    setBusy(true);
    setLastAction("sync-threshold");
    try {
      await requestJson(`${cleanBaseUrl}/public/state/threshold`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ threshold: Number(threshold) }),
      });
      // Volitelná zpětná vazba pro uživatele
      setOutput((prev) => ({ 
        ...prev, 
        error: null,
        health: { ...prev.health, info: `Threshold updated to ${threshold} in node memory.` } 
      }));
    } catch (error) {
      setError("threshold-sync", error);
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
      // Auto-fill the verify panel from the response
      if (data.document_hash) setVerifyDocHash(data.document_hash);
      if (data.timestamp) setVerifyTimestamp(data.timestamp);
      if (data.signature) setVerifySignature(JSON.stringify(data.signature, null, 2));
    } catch (error) {
      setError("timestamp", error);
    } finally {
      setBusy(false);
    }
  }

  async function hashVerifyFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    setVerifyHashingFile(true);
    setVerifyFileName(file.name);
    try {
      const fileBuffer = await file.arrayBuffer();
      const digest = await crypto.subtle.digest("SHA-256", fileBuffer);
      setVerifyDocHash(bytesToHex(new Uint8Array(digest)));
      setOutput((prev) => ({ ...prev, error: null }));
    } catch (error) {
      setError("verify-hash", error);
    } finally {
      setVerifyHashingFile(false);
    }
  }

  function runVerify(event) {
    event.preventDefault();
    setBusy(true);
    setLastAction("verify");
    try {
      let sigObj;
      try {
        sigObj = JSON.parse(verifySignature);
      } catch {
        setError("verify", Object.assign(new Error("Invalid JSON in signature field"), { payload: null }));
        return;
      }
      // All verification is done client-side — no API call, no node trust required.
      const result = verifyEthSchnorr(sigObj, verifyDocHash.trim(), verifyTimestamp.trim());
      setOutput((prev) => ({ ...prev, verify: result, error: null }));
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
          Control your node cluster, initialize DKG sessions, mint trusted
          timestamp signatures, and verify them — all from one dashboard.
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

            <div className="button-group" style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
              <button disabled={busy} type="submit" style={{ flex: 2 }}>
                {busy && lastAction === "dkg" ? "Initializing..." : "Run DKG Session"}
              </button>
              
              <button 
                type="button" 
                onClick={syncThresholdToNode} 
                disabled={busy}
                className="secondary-button"
                style={{ 
                  flex: 1, 
                  background: 'linear-gradient(135deg, #4b5563, #374151)',
                  fontSize: '0.8rem' 
                }}
              >
                {busy && lastAction === "sync-threshold" ? "Syncing..." : "Update Node Config"}
              </button>
            </div>
          </form>
          <p className="panel-note" style={{ marginTop: '10px' }}>
            ✦ Use <strong>Update Node Config</strong> to change threshold in node memory without starting a new DKG.
          </p>
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

        <section className="panel">
          <h2>Verify Timestamp</h2>
          <p className="panel-note">
            ✦ Verification runs entirely in your browser using{" "}
            <code>@noble/curves</code> — no node is contacted and no trust in any
            node is required.
          </p>
          <form onSubmit={runVerify}>
            <label>
              File Upload (local hash only)
              <input type="file" onChange={hashVerifyFile} />
            </label>
            {verifyFileName ? (
              <p>
                {verifyHashingFile
                  ? `Hashing ${verifyFileName}...`
                  : `Loaded ${verifyFileName} and updated document hash.`}
              </p>
            ) : null}

            <label>
              Document Hash (64 hex chars)
              <textarea
                rows={2}
                value={verifyDocHash}
                onChange={(e) => setVerifyDocHash(e.target.value)}
                placeholder="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
              />
            </label>

            <label>
              Timestamp (ISO 8601 from signing response)
              <input
                value={verifyTimestamp}
                onChange={(e) => setVerifyTimestamp(e.target.value)}
                placeholder="2026-03-20T14:36:41.335377+00:00"
              />
            </label>

            <label>
              Signature JSON <span className="label-hint">(auto-filled after Create Timestamp)</span>
              <textarea
                rows={6}
                value={verifySignature}
                onChange={(e) => setVerifySignature(e.target.value)}
                placeholder={'{\n  "message": "...",\n  "signature": "0x...",\n  "nonce": "0x...",\n  ...\n}'}
              />
            </label>

            {verifySignature && (() => {
              try {
                const s = JSON.parse(verifySignature);
                if (s?.public_key?.x) {
                  return (
                    <div className="pubkey-box">
                      <span className="label-hint">Public key in this signature:</span>
                      <code>{s.public_key.x}</code>
                      <span className="label-hint"> (y_parity: {s.public_key.y_parity})</span>
                      <br />
                      <span className="label-hint">Cross-check this against your DKG output.</span>
                    </div>
                  );
                }
              } catch { /* ignore parse errors while typing */ }
              return null;
            })()}

            <button disabled={busy} type="submit">
              {busy && lastAction === "verify" ? "Verifying..." : "Verify Signature"}
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
          <article>
            <h3>Verify</h3>
            {output.verify ? (
              <div className={output.verify.valid ? "verify-ok" : "verify-fail"}>
                <span className="verify-badge">
                  {output.verify.valid ? "✓ Valid" : "✗ Invalid"}
                </span>
                <pre>{pretty(output.verify)}</pre>
              </div>
            ) : (
              <pre>No data yet</pre>
            )}
          </article>
        </div>
      </section>
    </div>
  );
}
