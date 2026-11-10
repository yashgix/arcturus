const encode = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const decode = (text) => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const status = document.getElementById("status");

async function register(options) {
  const created = await navigator.credentials.create({ publicKey: {
    challenge: decode(options.challenge), rp: options.rp, user: { ...options.user, id: decode(options.user.id) },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }], attestation: "none",
    authenticatorSelection: { residentKey: "required", userVerification: "required" } } });
  return { credential_id: encode(created.rawId), client_data: encode(created.response.clientDataJSON),
    authenticator_data: encode(created.response.getAuthenticatorData()),
    public_key: encode(created.response.getPublicKey()), algorithm: created.response.getPublicKeyAlgorithm() };
}

async function approve(options) {
  const signed = await navigator.credentials.get({ publicKey: {
    challenge: decode(options.challenge), rpId: options.rpId, userVerification: "required",
    allowCredentials: options.allow.map((id) => ({ type: "public-key", id: decode(id) })) } });
  return { credential_id: encode(signed.rawId), client_data: encode(signed.response.clientDataJSON),
    authenticator_data: encode(signed.response.authenticatorData), signature: encode(signed.response.signature) };
}

document.getElementById("go").onclick = async () => {
  try {
    const options = await (await fetch("options")).json();
    const body = await (options.mode === "register" ? register : approve)(options);
    body.nonce = options.nonce;
    const reply = await fetch("done", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body) });
    status.textContent = await reply.text();
  } catch (error) {
    // fetch fails with a TypeError when the page's server is gone.
    status.textContent = error instanceof TypeError
      ? "Not approved: this page has closed. Use the newest link the runner printed."
      : `Not approved: ${error.message}`;
  }
};
