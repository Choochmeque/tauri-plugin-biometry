<script lang="ts">
  import {
    BiometryType,
    authenticate,
    checkStatus,
    getData,
    hasData,
    removeData,
    setData,
    type Status,
  } from "@choochmeque/tauri-plugin-biometry-api";

  const DOMAIN = "com.choochmeque.biometry-demo";

  let status = $state<Status | null>(null);
  let log = $state<string[]>([]);

  let authReason = $state("Confirm your identity");

  let setName = $state("api-token");
  let setValue = $state("secret-token-123");

  let getName = $state("api-token");
  let getReason = $state("Unlock saved data");

  let probeName = $state("api-token");

  let removeName = $state("api-token");

  function logLine(line: string) {
    const ts = new Date().toLocaleTimeString();
    log = [`[${ts}] ${line}`, ...log].slice(0, 100);
  }

  async function refreshStatus() {
    try {
      status = await checkStatus();
      logLine(
        `status: available=${status.isAvailable}, type=${BiometryType[status.biometryType]}` +
          (status.errorCode ? `, code=${status.errorCode}` : ""),
      );
    } catch (err) {
      logLine(`status error: ${err}`);
    }
  }

  async function runAuthenticate() {
    try {
      await authenticate(authReason, { allowDeviceCredential: true });
      logLine("authenticate: verified");
    } catch (err) {
      logLine(`authenticate error: ${err}`);
    }
  }

  async function runSetData() {
    try {
      await setData({ domain: DOMAIN, name: setName, data: setValue });
      logLine(`setData: stored "${setName}"`);
    } catch (err) {
      logLine(`setData error: ${err}`);
    }
  }

  async function runGetData() {
    try {
      const res = await getData({
        domain: DOMAIN,
        name: getName,
        reason: getReason,
      });
      logLine(`getData "${res.name}": ${res.data}`);
    } catch (err) {
      logLine(`getData error: ${err}`);
    }
  }

  async function runHasData() {
    try {
      const present = await hasData({ domain: DOMAIN, name: probeName });
      logLine(`hasData "${probeName}": ${present}`);
    } catch (err) {
      logLine(`hasData error: ${err}`);
    }
  }

  async function runRemoveData() {
    try {
      await removeData({ domain: DOMAIN, name: removeName });
      logLine(`removeData: removed "${removeName}"`);
    } catch (err) {
      logLine(`removeData error: ${err}`);
    }
  }
</script>

<main class="container">
  <h1>tauri-plugin-biometry demo</h1>

  <section>
    <div class="row">
      <button onclick={refreshStatus}>Check status</button>
      {#if status}
        <span class="pill" class:ok={status.isAvailable}>
          {status.isAvailable ? "available" : "unavailable"} ·
          {BiometryType[status.biometryType]}
        </span>
      {/if}
    </div>
    {#if status?.error}
      <p class="error">{status.error}</p>
    {/if}
  </section>

  <section>
    <h2>authenticate</h2>
    <div class="row">
      <input bind:value={authReason} placeholder="reason" />
      <button onclick={runAuthenticate}>Authenticate</button>
    </div>
  </section>

  <section>
    <h2>setData</h2>
    <div class="row">
      <input bind:value={setName} placeholder="name" />
      <input bind:value={setValue} placeholder="value" />
      <button onclick={runSetData}>Save</button>
    </div>
  </section>

  <section>
    <h2>getData</h2>
    <div class="row">
      <input bind:value={getName} placeholder="name" />
      <input bind:value={getReason} placeholder="reason" />
      <button onclick={runGetData}>Get</button>
    </div>
  </section>

  <section>
    <h2>hasData</h2>
    <div class="row">
      <input bind:value={probeName} placeholder="name" />
      <button onclick={runHasData}>Check</button>
    </div>
  </section>

  <section>
    <h2>removeData</h2>
    <div class="row">
      <input bind:value={removeName} placeholder="name" />
      <button onclick={runRemoveData}>Remove</button>
    </div>
  </section>

  <section>
    <h2>log</h2>
    <pre>{log.join("\n")}</pre>
  </section>
</main>

<style>
  :root {
    font-family: Inter, Avenir, Helvetica, Arial, sans-serif;
    color: #0f0f0f;
    background-color: #f6f6f6;
  }

  .container {
    max-width: 720px;
    margin: 0 auto;
    padding: 2rem 1.5rem 3rem;
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }

  h1 {
    margin: 0;
    font-size: 1.4rem;
  }

  h2 {
    margin: 0 0 0.4rem;
    font-size: 0.95rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #555;
  }

  section {
    background: white;
    border: 1px solid #e6e6e6;
    border-radius: 10px;
    padding: 0.9rem 1rem 1rem;
  }

  .row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: center;
  }

  input {
    flex: 1 1 9rem;
    min-width: 7rem;
    padding: 0.4rem 0.6rem;
    border-radius: 6px;
    border: 1px solid #d0d0d0;
    background: white;
    font-family: inherit;
    font-size: 0.9rem;
  }

  button {
    padding: 0.45rem 0.9rem;
    border-radius: 6px;
    border: 1px solid #d0d0d0;
    background: #fff;
    cursor: pointer;
    font-size: 0.9rem;
  }

  button:hover {
    border-color: #888;
  }

  .pill {
    padding: 0.15rem 0.55rem;
    border-radius: 999px;
    font-size: 0.8rem;
    background: #eee;
    color: #444;
  }

  .pill.ok {
    background: #d9f7d9;
    color: #1a6b1a;
  }

  .error {
    color: #b00020;
    margin: 0.5rem 0 0;
    font-size: 0.85rem;
  }

  pre {
    margin: 0;
    padding: 0.6rem 0.75rem;
    background: #111;
    color: #d9ffd9;
    border-radius: 6px;
    font-size: 0.78rem;
    line-height: 1.35;
    max-height: 18rem;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
  }

  @media (prefers-color-scheme: dark) {
    :root {
      color: #f6f6f6;
      background-color: #1c1c1c;
    }

    section {
      background: #2a2a2a;
      border-color: #3a3a3a;
    }

    input,
    button {
      background: #1a1a1a;
      color: #f6f6f6;
      border-color: #444;
    }

    button:hover {
      border-color: #888;
    }

    .pill {
      background: #3a3a3a;
      color: #ddd;
    }

    .pill.ok {
      background: #1f4d1f;
      color: #c8ffc8;
    }

    h2 {
      color: #bbb;
    }

    .error {
      color: #ff7676;
    }
  }
</style>
