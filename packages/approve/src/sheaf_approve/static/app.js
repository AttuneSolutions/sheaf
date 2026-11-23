// Sheaf approvals: sign in with the authorisation code flow and PKCE, then read and approve
// staged mandate changes. The access token is held in memory only. Every value shown is set as
// text, never as markup: a mandate's words are data.
"use strict";

(() => {
  const page = { config: null, token: null, me: null, shown: null };
  const PKCE = "sheaf.approve.pkce";
  const CODE = /^[a-z_]{1,64}$/;
  const $ = (id) => document.getElementById(id);

  // -- small helpers ---------------------------------------------------------------------------

  function node(tag, text, className) {
    const element = document.createElement(tag);
    if (text !== undefined && text !== null) element.textContent = String(text);
    if (className) element.className = className;
    return element;
  }

  function show(id, visible) {
    $(id).hidden = !visible;
  }

  function say(id, text) {
    $(id).textContent = text || "";
    show(id, Boolean(text));
  }

  // A sign-in error is shown as a fixed sentence and, if it looks like one, Entra ID's code.
  // Its description comes back in the address and is never shown.
  function signInFailed(code) {
    const known = typeof code === "string" && CODE.test(code) ? ` (${code})` : "";
    return new Error(`Sign-in did not complete${known}. Sign in again.`);
  }

  function when(iso) {
    return iso ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : "";
  }

  function base64url(bytes) {
    let text = "";
    bytes.forEach((b) => { text += String.fromCharCode(b); });
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function random(count) {
    const bytes = new Uint8Array(count);
    crypto.getRandomValues(bytes);
    return base64url(bytes);
  }

  async function challenge(verifier) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return base64url(new Uint8Array(digest));
  }

  // -- signing in ------------------------------------------------------------------------------

  async function signIn() {
    const config = page.config;
    const verifier = random(32);
    const state = random(16);
    sessionStorage.setItem(PKCE, JSON.stringify({ verifier, state }));
    const query = new URLSearchParams({
      client_id: config.client_id,
      response_type: "code",
      response_mode: "fragment",
      redirect_uri: config.redirect_uri,
      scope: config.scope,
      state,
      code_challenge: await challenge(verifier),
      code_challenge_method: "S256",
      prompt: "select_account",
    });
    location.assign(`${config.authority}/oauth2/v2.0/authorize?${query}`);
  }

  // The sign-in answer comes back in the fragment, which never reaches a server. It is
  // removed from the address at once, and the verifier with it.
  async function finishSignIn() {
    const answer = new URLSearchParams(location.hash.slice(1));
    if (!answer.has("code") && !answer.has("error")) return null;
    history.replaceState(null, "", location.pathname + location.search);
    const saved = JSON.parse(sessionStorage.getItem(PKCE) || "null");
    sessionStorage.removeItem(PKCE);
    if (answer.has("error")) throw signInFailed(answer.get("error"));
    if (!saved || answer.get("state") !== saved.state) {
      throw new Error("That sign-in did not start on this page. Sign in again.");
    }
    const config = page.config;
    const response = await fetch(`${config.authority}/oauth2/v2.0/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.client_id,
        grant_type: "authorization_code",
        code: answer.get("code"),
        redirect_uri: config.redirect_uri,
        code_verifier: saved.verifier,
        scope: config.scope,
      }),
    });
    const tokens = await response.json().catch(() => ({}));
    if (!response.ok || !tokens.access_token) throw signInFailed(tokens.error);
    return tokens.access_token;
  }

  function signOut() {
    page.token = null;
    page.me = null;
    location.replace(location.pathname);
  }

  // -- the service -----------------------------------------------------------------------------

  async function api(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { ...(options.headers || {}), Authorization: `Bearer ${page.token}` },
      cache: "no-store",
    });
    const body = await response.json().catch(() => ({}));
    if (response.status === 401) {
      page.token = null;
      showSignedOut();
    }
    if (!response.ok) {
      const problems = (body.problems || []).map((p) => p.detail || p.code).join("; ");
      const error = new Error(body.detail && problems ? `${body.detail}: ${problems}` : body.detail || problems || `The service answered ${response.status}.`);
      error.body = body;
      error.status = response.status;
      throw error;
    }
    return body;
  }

  // -- screens ---------------------------------------------------------------------------------

  function showSignedOut() {
    say("who", "");
    show("sign-out", false);
    show("list", false);
    show("proposal", false);
    show("signed-out", true);
  }

  async function showList() {
    say("error", "");
    show("proposal", false);
    show("signed-out", false);
    const { proposals, unavailable } = await api("api/proposals");
    const missing = $("unavailable");
    missing.textContent = unavailable.length
      ? `Not shown: ${unavailable.join(", ")} cannot be read just now (starting or halted). Reload in a minute.`
      : "";
    show("unavailable", unavailable.length > 0);
    const list = $("proposals");
    list.replaceChildren();
    proposals.forEach((proposal) => {
      const card = node("article");
      const header = node("header");
      const title = node("strong", `${proposal.chain}, mandate ${proposal.version}`);
      const kind = proposal.previous ? `replaces ${proposal.previous.version}` : "first mandate";
      header.append(title, node("span", kind, "tag"));
      const reason = node("p", proposal.reason, "reason");
      const meta = node(
        "p",
        `Proposed by ${proposal.proposed_by.id} on ${when(proposal.proposed_at)}. Waits until ${when(proposal.expires_at)}.`,
        "meta",
      );
      const footer = node("footer");
      const button = node("button", "Review");
      button.type = "button";
      button.addEventListener("click", () => {
        busy(button, open(proposal.mandate)).catch((error) => say("error", error.message));
      });
      footer.append(button);
      card.append(header, reason, meta, footer);
      list.append(card);
    });
    show("none", proposals.length === 0 && unavailable.length === 0);
    show("list", true);
    $("main").focus();
  }

  function fact(list, name, value, className) {
    list.append(node("dt", name), node("dd", value, className));
  }

  function sentences(lines, className, tag) {
    const list = node("ul", null, className);
    lines.forEach((line) => {
      const item = node("li");
      item.append(tag ? node(tag, line) : document.createTextNode(line));
      list.append(item);
    });
    return list;
  }

  // Pico shows an element with aria-busy as loading.
  async function busy(element, promise) {
    element.setAttribute("aria-busy", "true");
    try {
      return await promise;
    } finally {
      element.removeAttribute("aria-busy");
    }
  }

  function confirmTyped() {
    const shown = page.shown;
    const input = $("confirm");
    const typed = input.value.trim();
    const matches = Boolean(shown) && typed === shown.proposal.chain;
    if (typed) input.setAttribute("aria-invalid", matches ? "false" : "true");
    else input.removeAttribute("aria-invalid");
    $("approve-button").disabled = !(matches && shown.caller.may_approve);
  }

  async function open(sha256) {
    say("error", "");
    say("message", "");
    const shown = await api(`api/proposals/${encodeURIComponent(sha256)}`);
    page.shown = shown;
    const p = shown.proposal;

    $("proposal-title").textContent = `Mandate ${p.version}`;
    $("proposal-chain").textContent = `For ${p.chain}. ${p.previous ? `Replaces mandate ${p.previous.version}.` : "The chain's first mandate."}`;
    const facts = $("facts");
    facts.replaceChildren();
    const print = node("dd");
    print.append(node("code", shown.fingerprint));
    facts.append(node("dt", "Fingerprint"), print);
    fact(facts, "Proposed by", p.proposed_by.id);
    fact(facts, "Proposed", when(p.proposed_at));
    fact(facts, "Reason", p.reason);
    fact(facts, "Waits until", when(p.expires_at));
    fact(facts, "Status", p.status);

    const changes = $("changes");
    changes.replaceChildren();
    if (shown.genesis) {
      changes.append(node("p", "This is the chain's first mandate: everything below is new, so read it all."));
    } else {
      shown.diff.forEach((change) => {
        const card = node("article");
        const header = node("header");
        header.append(node("h3", change.title));
        card.append(header);
        const both = change.removed.length && change.added.length;
        if (change.removed.length) {
          card.append(node("p", both ? "No longer" : "Removed", "label"), sentences(change.removed, "removed", "del"));
        }
        if (change.added.length) {
          card.append(node("p", both ? "Instead" : "Added", "label"), sentences(change.added, "added", "ins"));
        }
        changes.append(card);
      });
    }

    // For a first mandate every part is new, so every part starts open.
    const plain = $("plain");
    plain.replaceChildren();
    shown.plain.forEach((section) => {
      const part = node("details");
      part.open = Boolean(shown.genesis);
      part.append(node("summary", section.title), sentences(section.lines));
      plain.append(part);
    });

    const rows = $("technical").tBodies[0];
    rows.replaceChildren();
    shown.technical.forEach(([name, value]) => {
      const row = node("tr");
      row.append(node("th", name), node("td", value));
      rows.append(row);
    });

    $("chain-name").textContent = p.chain;
    $("confirm").value = "";
    const may = shown.caller.may_approve;
    $("confirm").disabled = !may;
    confirmTyped();
    say("refusal", may ? "" : `You cannot approve this change: ${shown.caller.refusal}.`);

    show("list", false);
    show("proposal", true);
    $("proposal-title").tabIndex = -1;
    $("proposal-title").focus();
  }

  async function approve(event) {
    event.preventDefault();
    const shown = page.shown;
    if (!shown) return;
    say("error", "");
    $("approve-button").disabled = true;
    let result;
    try {
      result = await busy($("approve-button"), api(`api/proposals/${encodeURIComponent(shown.fingerprint)}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirm: $("confirm").value.trim(), fingerprint: shown.fingerprint }),
      }));
    } catch (error) {
      if (error.status === undefined || error.status === 502 || error.status === 504) {
        // The approval may have reached the record even though no answer came back.
        say("error", "No clear answer came back, so the approval may or may not have been committed. Reload the page and look at the proposal's status before approving again.");
        return;
      }
      say("error", error.message);
      confirmTyped();
      return;
    }
    // Approved: the button stays disabled, whatever happens next.
    page.shown = null;
    const receipt = result.approved;
    const approved = `Approved: committed to the record at seq ${receipt.seq}, ${when(receipt.committed_at)}. It applies once the witness has stamped it.`;
    try {
      await showList();
      say("message", approved);
    } catch (error) {
      say("message", `Approved; the list could not be reloaded. It was committed at seq ${receipt.seq}.`);
    }
  }

  // -- start -----------------------------------------------------------------------------------

  async function start() {
    $("sign-in").addEventListener("click", () => signIn().catch((e) => say("error", e.message)));
    $("sign-out").addEventListener("click", signOut);
    $("back").addEventListener("click", () => showList().catch((e) => say("error", e.message)));
    $("approve").addEventListener("submit", approve);
    $("confirm").addEventListener("input", confirmTyped);
    try {
      page.config = await (await fetch("api/config", { cache: "no-store" })).json();
      page.token = await finishSignIn();
      if (!page.token) {
        showSignedOut();
        return;
      }
      page.me = await api("api/me");
      say("who", `Signed in as ${page.me.id}`);
      show("sign-out", true);
      await showList();
    } catch (error) {
      say("error", error.message);
      if (!page.token) showSignedOut();
    }
  }

  start();
})();
