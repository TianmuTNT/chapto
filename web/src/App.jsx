import { useEffect, useMemo, useRef, useState } from "react";

const PACKET_PREFIX = "CT1";
const VERSION = 1;
const STORAGE_PREFIX = "chapto.web.v1";
const ACTIVE_KEY = `${STORAGE_PREFIX}.active`;
const STATE_PREFIX = `${STORAGE_PREFIX}.state.`;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const nowIso = () => new Date().toISOString().replace(".000Z", "Z");

const b64urlEncode = (bytes) => {
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const b64urlDecode = (text) => {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (padded.length % 4)) % 4);
  const binary = atob(padded + pad);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
};

const encodePacket = (payload) => {
  const raw = JSON.stringify(payload);
  const compressed = window.pako.deflate(raw, { level: 9 });
  const packed = b64urlEncode(compressed);
  return `${PACKET_PREFIX}.${packed}`;
};

const decodePacket = (text) => {
  if (!text.startsWith(`${PACKET_PREFIX}.`)) {
    throw new Error("Not a chapto packet");
  }
  const packed = text.split(".", 2)[1];
  const compressed = b64urlDecode(packed);
  const raw = window.pako.inflate(compressed, { to: "string" });
  const data = JSON.parse(raw);
  if (!data || typeof data !== "object") {
    throw new Error("Packet payload must be an object");
  }
  return data;
};

const sessionCard = (profile, sessionId, sessionName, note) => {
  const payload = {
    v: VERSION,
    t: "S",
    s: sessionId,
    d: sessionName,
    u: profile.username,
    i: profile.uuid,
    k: profile.public_key,
  };
  if (note) payload.m = note;
  return encodePacket(payload);
};

const sessionAck = (profile, sessionId, sessionName) => {
  const payload = {
    v: VERSION,
    t: "A",
    s: sessionId,
    u: profile.username,
    i: profile.uuid,
    k: profile.public_key,
  };
  if (sessionName) payload.d = sessionName;
  return encodePacket(payload);
};

const messagePacket = (sessionId, senderUuid, recipientUuid, nonce, ciphertext) =>
  encodePacket({
    v: VERSION,
    t: "M",
    s: sessionId,
    f: senderUuid,
    r: recipientUuid,
    n: nonce,
    c: ciphertext,
  });

const stateKey = (uuid) => `${STATE_PREFIX}${uuid}`;

const listAccounts = () => {
  const accounts = [];
  for (let i = 0; i < localStorage.length; i += 1) {
    const key = localStorage.key(i);
    if (!key || !key.startsWith(STATE_PREFIX)) continue;
    try {
      const raw = localStorage.getItem(key);
      if (!raw) continue;
      const data = JSON.parse(raw);
      if (data && data.profile) accounts.push(data.profile);
    } catch (err) {
      continue;
    }
  }
  return accounts;
};

const loadState = (uuid) => {
  let selectedKey = uuid ? stateKey(uuid) : null;
  if (!selectedKey) {
    const active = localStorage.getItem(ACTIVE_KEY);
    if (active) selectedKey = stateKey(active);
  }
  if (selectedKey) {
    const raw = localStorage.getItem(selectedKey);
    if (raw) return ensureState(JSON.parse(raw));
  }
  const candidates = [];
  for (let i = 0; i < localStorage.length; i += 1) {
    const key = localStorage.key(i);
    if (!key || !key.startsWith(STATE_PREFIX)) continue;
    try {
      const raw = localStorage.getItem(key);
      if (!raw) continue;
      const data = JSON.parse(raw);
      if (data) candidates.push(data);
    } catch (err) {
      continue;
    }
  }
  if (candidates.length > 0) {
    candidates.sort((a, b) => (b.savedAt || 0) - (a.savedAt || 0));
    return ensureState(candidates[0]);
  }
  return createAccount();
};

const saveState = (nextState) => {
  nextState.savedAt = Date.now();
  localStorage.setItem(stateKey(nextState.profile.uuid), JSON.stringify(nextState));
  localStorage.setItem(ACTIVE_KEY, nextState.profile.uuid);
};

const deleteAccount = (uuid) => {
  localStorage.removeItem(stateKey(uuid));
  const active = localStorage.getItem(ACTIVE_KEY);
  if (active === uuid) localStorage.removeItem(ACTIVE_KEY);
};

const generateKeypair = () => {
  const privateKey = window.sodium.randombytes_buf(32);
  const publicKey = window.sodium.crypto_scalarmult_base(privateKey);
  return {
    public_key: b64urlEncode(publicKey),
    private_key: b64urlEncode(privateKey),
  };
};

const generateProfile = (username) => {
  const name = username && username.trim() ? username.trim() : `user-${window.sodium.to_hex(window.sodium.randombytes_buf(3))}`;
  const keypair = generateKeypair();
  return {
    username: name,
    uuid: crypto.randomUUID(),
    public_key: keypair.public_key,
    private_key: keypair.private_key,
  };
};

const ensureState = (raw) => {
  const profile = raw.profile || {};
  if (!profile.public_key || !profile.private_key) {
    const keypair = generateKeypair();
    profile.public_key = keypair.public_key;
    profile.private_key = keypair.private_key;
    raw.profile = profile;
  }
  raw.sessions = raw.sessions || {};
  raw.messages = raw.messages || {};
  return raw;
};

const createAccount = (username) => {
  const profile = generateProfile(username);
  const nextState = {
    profile,
    sessions: {},
    messages: {},
    savedAt: Date.now(),
  };
  saveState(nextState);
  return nextState;
};

const sessionSalt = (sessionId) => encoder.encode(sessionId);

const deriveSessionKey = async (sharedSecret, saltBytes) => {
  const key = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltBytes,
      info: encoder.encode("chapto-session-v2"),
    },
    key,
    256
  );
  return new Uint8Array(bits);
};

const encryptMessage = async (plaintext, sharedKey) => {
  const nonce = window.sodium.randombytes_buf(12);
  const cipher = window.sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
    encoder.encode(plaintext),
    null,
    null,
    nonce,
    sharedKey
  );
  return { nonce: b64urlEncode(nonce), ciphertext: b64urlEncode(cipher) };
};

const decryptMessage = async (nonceB64, cipherB64, sharedKey) => {
  const nonce = b64urlDecode(nonceB64);
  const data = b64urlDecode(cipherB64);
  const plaintext = window.sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
    null,
    data,
    null,
    nonce,
    sharedKey
  );
  return decoder.decode(plaintext);
};

const x25519SharedSecret = async (privateB64, peerPublicB64) => {
  const privateKey = b64urlDecode(privateB64);
  const publicKey = b64urlDecode(peerPublicB64);
  return window.sodium.crypto_scalarmult(privateKey, publicKey);
};

const copyText = async (text) => {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (err) {
    // fallback
  }
  const helper = document.createElement("textarea");
  helper.value = text;
  helper.style.position = "fixed";
  helper.style.opacity = "0";
  document.body.appendChild(helper);
  helper.select();
  try {
    document.execCommand("copy");
    return true;
  } catch (err) {
    return false;
  } finally {
    document.body.removeChild(helper);
  }
};

const getPreview = (encoded) => (encoded.length > 64 ? `${encoded.slice(0, 64)}...` : encoded);

const sortSessions = (sessions) =>
  Object.values(sessions).sort((a, b) => (a.created_at || "").localeCompare(b.created_at || ""));

export default function App() {
  const [appState, setAppState] = useState(null);
  const appStateRef = useRef(null);
  const [currentSessionId, setCurrentSessionId] = useState(null);
  const [status, setStatus] = useState("");
  const [selectedAccountUuid, setSelectedAccountUuid] = useState(null);
  const [showSessionModal, setShowSessionModal] = useState(false);
  const [showAccountsModal, setShowAccountsModal] = useState(false);
  const [showCopyModal, setShowCopyModal] = useState(false);
  const [showIdentityModal, setShowIdentityModal] = useState(false);
  const [copyMessage, setCopyMessage] = useState(null);

  const sessionInputRef = useRef(null);
  const messageInputRef = useRef(null);
  const sessionNameRef = useRef(null);
  const accountUsernameRef = useRef(null);
  const messageListRef = useRef(null);

  useEffect(() => {
    appStateRef.current = appState;
  }, [appState]);

  useEffect(() => {
    const init = async () => {
      await window.sodium.ready;
      const loaded = loadState();
      saveState(loaded);
      setAppState(loaded);
    };
    init();
  }, []);

  useEffect(() => {
    if (!messageListRef.current) return;
    messageListRef.current.scrollTop = messageListRef.current.scrollHeight;
  }, [appState, currentSessionId]);

  const updateState = (nextState, nextSessionId) => {
    setAppState(nextState);
    if (typeof nextSessionId !== "undefined") {
      setCurrentSessionId(nextSessionId);
    }
    saveState(nextState);
  };

  const sessions = appState ? sortSessions(appState.sessions) : [];
  const currentSession = appState && currentSessionId ? appState.sessions[currentSessionId] : null;
  const messages = currentSessionId && appState ? appState.messages[currentSessionId] || [] : [];

  const accountList = useMemo(() => listAccounts().sort((a, b) => a.username.localeCompare(b.username)), [appState]);

  const handleCreateSession = async () => {
    const name = sessionNameRef.current?.value.trim();
    if (!name || !appStateRef.current) return;
    const sessionId = crypto.randomUUID();
    const nextState = { ...appStateRef.current };
    nextState.sessions = { ...nextState.sessions };
    nextState.sessions[sessionId] = {
      session_id: sessionId,
      name,
      status: "pending",
      created_at: nowIso(),
    };
    nextState.messages = { ...nextState.messages };
    updateState(nextState, sessionId);
    setShowSessionModal(false);
    const packet = sessionCard(nextState.profile, sessionId, name);
    const copied = await copyText(packet);
    setStatus(copied ? "Session request packet copied" : "Session request packet generated (clipboard unavailable)");
  };

  const handleRemoveSession = (sessionId, name) => {
    if (!appStateRef.current) return;
    const nextState = { ...appStateRef.current };
    nextState.sessions = { ...nextState.sessions };
    nextState.messages = { ...nextState.messages };
    delete nextState.sessions[sessionId];
    delete nextState.messages[sessionId];
    updateState(nextState, currentSessionId === sessionId ? null : currentSessionId);
    setStatus(`Removed session ${name}`);
  };

  const handleAcceptSession = async () => {
    const input = sessionInputRef.current;
    if (!input) return;
    const packet = input.value.trim();
    input.value = "";
    if (!packet) {
      setStatus("Paste a session packet first");
      return;
    }
    if (!packet.startsWith("CT1.")) {
      setStatus("Session input expects a CT1 packet");
      return;
    }
    await decodePacketText(packet, true);
  };

  const handleSendMessage = async () => {
    const input = messageInputRef.current;
    if (!input) return;
    const text = input.value.trim();
    input.value = "";
    if (!text) return;
    if (text.startsWith("CT1.")) {
      await decodePacketText(text, false);
    } else {
      await encodeAndStore(text);
    }
  };

  const encodeAndStore = async (plaintext) => {
    const current = appStateRef.current;
    if (!current) return;
    const session = currentSessionId ? current.sessions[currentSessionId] : null;
    if (!session) {
      setStatus("Select a session first");
      return;
    }
    if (session.status !== "active" || !session.peer_uuid || !session.peer_public_key) {
      setStatus("Session pending. Paste the ack packet to activate it.");
      return;
    }
    const shared = await x25519SharedSecret(current.profile.private_key, session.peer_public_key);
    const key = await deriveSessionKey(shared, sessionSalt(session.session_id));
    const { nonce, ciphertext } = await encryptMessage(plaintext, key);
    const packet = messagePacket(
      session.session_id,
      current.profile.uuid,
      session.peer_uuid,
      nonce,
      ciphertext
    );
    const message = {
      sender_uuid: current.profile.uuid,
      recipient_uuid: session.peer_uuid,
      body: plaintext,
      encoded: packet,
      timestamp: nowIso(),
    };
    const nextState = { ...current };
    nextState.messages = { ...nextState.messages };
    nextState.messages[session.session_id] = [...(nextState.messages[session.session_id] || []), message];
    updateState(nextState, currentSessionId);
    const copied = await copyText(packet);
    setStatus(copied ? "Encoded packet copied to clipboard" : "Encoded packet ready (clipboard unavailable)");
  };

  const decodePacketText = async (packet, allowSession) => {
    let payload;
    try {
      payload = decodePacket(packet);
    } catch (err) {
      setStatus(`Decode failed: ${err.message}`);
      return;
    }
    const current = appStateRef.current;
    if (!current) return;
    const packetType = payload.t;
    if (packetType === "S" || packetType === "A") {
      if (!allowSession) {
        setStatus("Paste session packets in the session box");
        return;
      }
      const sessionId = payload.s;
      if (!sessionId) {
        setStatus("Session packet missing session id");
        return;
      }
      const sessionName = payload.d;
      const peerUuid = payload.i;
      const peerUsername = payload.u;
      const peerPublic = payload.k;
      if (!peerUuid || !peerUsername || !peerPublic) {
        setStatus("Session packet missing fields");
        return;
      }
      if (peerUuid === current.profile.uuid) {
        setStatus("Cannot accept your own session packet");
        return;
      }
      const nextState = { ...current };
      nextState.sessions = { ...nextState.sessions };
      let session = nextState.sessions[sessionId];
      if (session) {
        if (sessionName) session.name = sessionName;
      } else {
        session = {
          session_id: sessionId,
          name: sessionName || `session-${sessionId.slice(0, 8)}`,
          status: "active",
          created_at: nowIso(),
        };
      }
      session.peer_uuid = peerUuid;
      session.peer_username = peerUsername;
      session.peer_public_key = peerPublic;
      session.status = "active";
      nextState.sessions[sessionId] = session;
      updateState(nextState, sessionId);
      if (packetType === "S") {
        const ack = sessionAck(nextState.profile, sessionId, session.name);
        const copied = await copyText(ack);
        setStatus(copied ? "Session accept packet copied" : "Session accept packet generated (clipboard unavailable)");
        return;
      }
      setStatus("Session confirmed");
      return;
    }
    if (packetType !== "M") {
      setStatus("Unknown packet type");
      return;
    }
    const sessionId = payload.s;
    const senderUuid = payload.f;
    const recipientUuid = payload.r;
    const nonce = payload.n;
    const ciphertext = payload.c;
    if (!sessionId || !senderUuid || !recipientUuid || !nonce || !ciphertext) {
      setStatus("Message packet missing fields");
      return;
    }
    if (recipientUuid !== current.profile.uuid) {
      setStatus("Packet not addressed to this user");
      return;
    }
    let plaintext = "";
    try {
      const knownSession = current.sessions?.[sessionId];
      if (!knownSession?.peer_public_key) {
        setStatus("Missing session key for this message");
        return;
      }
      const shared = await x25519SharedSecret(current.profile.private_key, knownSession.peer_public_key);
      const key = await deriveSessionKey(shared, sessionSalt(sessionId));
      plaintext = await decryptMessage(nonce, ciphertext, key);
    } catch (err) {
      setStatus(`Decryption failed: ${err.message}`);
      return;
    }
    const nextState = { ...current };
    nextState.sessions = { ...nextState.sessions };
    nextState.messages = { ...nextState.messages };
    let session = nextState.sessions[sessionId];
    if (!session) {
      setStatus("Session missing for this message");
      return;
    }
    session.peer_uuid = senderUuid;
    if (!session.peer_username) {
      session.peer_username = `user-${senderUuid.slice(0, 8)}`;
    }
    session.status = "active";
    nextState.sessions[sessionId] = session;
    nextState.messages[sessionId] = [
      ...(nextState.messages[sessionId] || []),
      {
        sender_uuid: senderUuid,
        recipient_uuid: current.profile.uuid,
        body: plaintext,
        encoded: packet,
        timestamp: nowIso(),
      },
    ];
    updateState(nextState, sessionId);
  };

  const handleSwitchAccount = () => {
    const statusNode = document.getElementById("account-status");
    if (!selectedAccountUuid) {
      if (statusNode) statusNode.textContent = "Select an account to switch";
      return;
    }
    if (selectedAccountUuid === appState.profile.uuid) {
      if (statusNode) statusNode.textContent = "Already using this account";
      return;
    }
    const nextState = loadState(selectedAccountUuid);
    saveState(nextState);
    setAppState(nextState);
    setCurrentSessionId(null);
    setShowAccountsModal(false);
    setStatus(`Switched to ${nextState.profile.username}`);
  };

  const handleCreateAccount = () => {
    const username = accountUsernameRef.current?.value || "";
    const nextState = createAccount(username);
    setAppState(nextState);
    setCurrentSessionId(null);
    if (accountUsernameRef.current) accountUsernameRef.current.value = "";
    setShowAccountsModal(false);
    setStatus(`Switched to ${nextState.profile.username}`);
  };

  const handleRemoveAccount = () => {
    const statusNode = document.getElementById("account-status");
    if (!selectedAccountUuid) {
      if (statusNode) statusNode.textContent = "Select an account to remove";
      return;
    }
    if (selectedAccountUuid === appState.profile.uuid) {
      if (statusNode) statusNode.textContent = "Cannot remove active account";
      return;
    }
    deleteAccount(selectedAccountUuid);
    setSelectedAccountUuid(null);
    if (statusNode) statusNode.textContent = "Account removed";
  };

  if (!appState) {
    return (
      <div className="loading">
        <div className="loading-card">Loading chapto��</div>
      </div>
    );
  }

  return (
    <>
      <header className="topbar">
        <div className="brand">
          <span className="brand-dot" />
          <span>Chapto</span>
        </div>
        <div className="topbar-actions">
          <button className="account-pill" onClick={() => setShowIdentityModal(true)} type="button">
            {`${appState.profile.username} (${appState.profile.uuid.slice(0, 8)})`}
          </button>
          <button className="btn ghost" onClick={() => { setShowAccountsModal(true); setSelectedAccountUuid(null); }}>
            Accounts
          </button>
        </div>
      </header>

      <main className="layout">
        <aside className="panel sidebar">
          <div className="panel-header">
            <div>
              <div className="panel-title">Sessions</div>
              <div className="panel-subtitle">One-time encrypted channels</div>
            </div>
            <button className="btn" onClick={() => setShowSessionModal(true)}>New Session</button>
          </div>
          <div className="session-list">
            {sessions.length === 0 && <div className="empty">No sessions yet</div>}
            {sessions.map((session) => (
              <div
                key={session.session_id}
                className={`session-item ${currentSessionId === session.session_id ? "active" : ""}`}
                onClick={() => setCurrentSessionId(session.session_id)}
                role="button"
                tabIndex={0}
              >
                <div>
                  <div className="session-name">
                    {session.status === "active" ? session.name : `${session.name} [pending]`}
                  </div>
                  <div className="session-meta">{session.peer_username || "unknown"}</div>
                </div>
                <button
                  className="session-remove"
                  type="button"
                  title="Remove session"
                  onClick={(event) => {
                    event.stopPropagation();
                    handleRemoveSession(session.session_id, session.name);
                  }}
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
          <section className="receive-card">
            <div className="card-title">Receive Session</div>
            <textarea ref={sessionInputRef} placeholder="Paste session card (CT1...)" rows={3} />
            <button className="btn" onClick={handleAcceptSession}>Accept Session</button>
          </section>
        </aside>

        <section className="panel chat">
          <div className="chat-header">
            <div>
              {currentSession
                ? `${currentSession.name}${currentSession.status === "active" ? "" : " [pending]"}`
                : "Select a session"}
            </div>
            <div id="chat-subtitle">{currentSession ? currentSession.peer_username || "unknown" : ""}</div>
          </div>
          <div className="chat-messages" ref={messageListRef}>
            {messages.map((message) => {
              const outgoing = message.sender_uuid === appState.profile.uuid;
              const peerName = currentSession?.peer_username || "unknown";
              return (
                <div key={`${message.timestamp}-${message.encoded}`} className={`message-card ${outgoing ? "" : "incoming"}`}>
                  <div>
                    <div className="message-header">{`${outgoing ? "You" : peerName} [${message.timestamp}]`}</div>
                    <div className="message-body">{message.body}</div>
                    <div className="message-packet">{getPreview(message.encoded)}</div>
                  </div>
                  <div className="message-actions">
                    <button
                      className="btn ghost"
                      onClick={() => {
                        setCopyMessage(message);
                        setShowCopyModal(true);
                      }}
                    >
                      Copy
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
          <div className="status">{status}</div>
          <div className="composer">
            <textarea
              ref={messageInputRef}
              placeholder="Paste CT1 message or type plaintext"
              rows={2}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault();
                  handleSendMessage();
                }
              }}
            />
            <div className="composer-actions">
              <button className="btn" onClick={handleSendMessage}>Send</button>
            </div>
          </div>
        </section>
      </main>

      {showSessionModal && (
        <div className="modal open" aria-hidden="false">
          <div className="modal-card">
            <div className="modal-title">New Session</div>
            <label className="field-label" htmlFor="session-name">Session name</label>
            <input id="session-name" ref={sessionNameRef} type="text" placeholder="Session 1" />
            <div className="modal-actions">
              <button className="btn" onClick={handleCreateSession}>Create</button>
              <button className="btn ghost" onClick={() => setShowSessionModal(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {showAccountsModal && (
        <div className="modal open" aria-hidden="false">
          <div className="modal-card wide">
            <div className="modal-title">Accounts</div>
            <div className="accounts-grid">
              <div className="accounts-list">
                {accountList.map((account) => (
                  <div
                    key={account.uuid}
                    className={`account-item ${selectedAccountUuid === account.uuid || account.uuid === appState.profile.uuid ? "active" : ""}`}
                    onClick={() => setSelectedAccountUuid(account.uuid)}
                    role="button"
                    tabIndex={0}
                  >
                    {`${account.username} (${account.uuid.slice(0, 8)})${account.uuid === appState.profile.uuid ? " *" : ""}`}
                  </div>
                ))}
              </div>
              <div className="accounts-controls">
                <label className="field-label" htmlFor="account-username">New account username (optional)</label>
                <input id="account-username" ref={accountUsernameRef} type="text" placeholder="user-xxxx" />
                <div className="stack">
                  <button className="btn" onClick={handleCreateAccount}>Create Account</button>
                  <button className="btn" onClick={handleSwitchAccount}>Switch</button>
                  <button className="btn danger" onClick={handleRemoveAccount}>Remove</button>
                  <button className="btn ghost" onClick={() => setSelectedAccountUuid(null)}>Refresh</button>
                </div>
                <div className="status inline" id="account-status" />
                <div className="modal-actions right">
                  <button className="btn ghost" onClick={() => setShowAccountsModal(false)}>Cancel</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {showCopyModal && copyMessage && (
        <div className="modal open" aria-hidden="false">
          <div className="modal-card wide">
            <div className="modal-title">Copy Message</div>
            <label className="field-label">Plaintext</label>
            <pre className="copy-box">{copyMessage.body}</pre>
            <label className="field-label">Packet</label>
            <pre className="copy-box">{copyMessage.encoded}</pre>
            <div className="modal-actions">
              <button className="btn" onClick={() => copyText(copyMessage.body)}>Copy Plaintext</button>
              <button className="btn" onClick={() => copyText(copyMessage.encoded)}>Copy Packet</button>
              <button className="btn ghost" onClick={() => setShowCopyModal(false)}>Close</button>
            </div>
          </div>
        </div>
      )}

      {showIdentityModal && (
        <div className="modal open" aria-hidden="false">
          <div className="modal-card">
            <div className="modal-title">Current Identity</div>
            <pre className="copy-box">{`${appState.profile.username}\n${appState.profile.uuid}`}</pre>
            <div className="modal-actions">
              <button className="btn ghost" onClick={() => setShowIdentityModal(false)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
