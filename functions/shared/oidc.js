// Função auxiliar para decodificar Base64URL em Uint8Array
function base64UrlDecode(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4;
  if (pad) {
    if (pad === 1) throw new Error('Base64URL inválido');
    b64 += new Array(5 - pad).join('=');
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function verifyGoogleIdToken(idToken, expectedNonce, clientId) {
  const parts = idToken.split('.');
  if (parts.length !== 3) return null;

  const [headerB64, payloadB64, signatureB64] = parts;

  const headerStr = new TextDecoder().decode(base64UrlDecode(headerB64));
  const header = JSON.parse(headerStr);
  
  if (header.alg !== "RS256" || !header.kid) return null;

  const payloadStr = new TextDecoder().decode(base64UrlDecode(payloadB64));
  const payload = JSON.parse(payloadStr);

  const discoveryResp = await fetch("https://accounts.google.com/.well-known/openid-configuration");
  const discovery = await discoveryResp.json();

  const jwksResp = await fetch(discovery.jwks_uri);
  const jwks = await jwksResp.json();

  const jwk = jwks.keys.find(k => k.kid === header.kid);
  if (!jwk) return null;

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signatureBytes = base64UrlDecode(signatureB64);
  const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  
  const isValid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    signatureBytes,
    signedData
  );

  if (!isValid) return null;

  const now = Math.floor(Date.now() / 1000);
  const validIssuers = ["https://accounts.google.com", "accounts.google.com"];
  
  if (!validIssuers.includes(payload.iss)) return null;
  if (payload.aud !== clientId) return null;
  if (payload.exp < now) return null;
  if (payload.iat > now + 60) return null; 
  if (payload.nonce !== expectedNonce) return null;

  return payload;
}
