
import { parseCookie, serializeSessionCookie } from "../../shared/cookies.js";
import { providers } from "../../shared/providers.js";


export async function onRequestGet(context) {
  const url = new URL(context.request.url);
  const provider = context.params.provider;
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  // 1. Recusar error ou a ausência de code e state
  if (error || !code || !state) {
    return new Response("Pedido inválido", { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  // 2. Exigir o cookie temporário
  const cookieHeader = context.request.headers.get("Cookie");
  const txCookie = parseCookie(cookieHeader, "__Host-oauth-tx");
  if (!txCookie) {
    return new Response("Sessão expirada ou cookie ausente", { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  // 3 & 4. Calcular resumo, localizar transação não expirada e comparar o state
  const txIdHash = await sha256(txCookie);
  const stateHash = await sha256(state);
  const now = Math.floor(Date.now() / 1000);

  const tx = await context.env.DB.prepare(
    `SELECT * FROM oauth_transactions WHERE id_hash = ? AND provider = ? AND expires_at > ?`
  ).bind(txIdHash, provider, now).first();

  if (!tx || tx.state_hash !== stateHash) {
    return new Response("Transação inválida ou expirada", { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  // 5. Apagar a transação ANTES de concluir o fluxo
  await context.env.DB.prepare(
    `DELETE FROM oauth_transactions WHERE id_hash = ?`
  ).bind(txIdHash).run();

  // 6. Trocar o código pelo token com PKCE (code_verifier)
  const clientId = provider === "google" ? context.env.GOOGLE_CLIENT_ID : context.env.GITHUB_CLIENT_ID;
  const clientSecret = provider === "google" ? context.env.GOOGLE_CLIENT_SECRET : context.env.GITHUB_CLIENT_SECRET;
  const redirectUri = `${context.env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;

  const tokenParams = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code: code,
    grant_type: "authorization_code",
    redirect_uri: redirectUri,
    code_verifier: tx.code_verifier
  });

  const tokenResponse = await fetch(providers[provider].tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
    body: tokenParams.toString()
  });

  if (!tokenResponse.ok) return new Response("Falha na troca de tokens", { status: 400, headers: { "Cache-Control": "no-store" } });
  const tokens = await tokenResponse.json();

  let sessionIssuer, sessionSubject, sessionEmail, sessionName;

  // 7. Confirmar a identidade sem bibliotecas externas
  if (provider === "google") {
    // Validação criptográfica do JWT OIDC
    const identity = await verifyGoogleIdToken(tokens.id_token, tx.nonce, clientId);
    if (!identity) return new Response("Identidade Google inválida", { status: 400, headers: { "Cache-Control": "no-store" } });
    
    sessionIssuer = "https://accounts.google.com";
    sessionSubject = identity.sub;
    sessionEmail = identity.email;
    sessionName = identity.name;

  } else if (provider === "github") {
    // Consultar o perfil no GitHub usando o access_token
    const userResp = await fetch(providers.github.userUrl, {
      headers: {
        "Authorization": `Bearer ${tokens.access_token}`,
        "Accept": "application/vnd.github+json",
        "User-Agent": "Laboratorio-OAuth"
      }
    });
    if (!userResp.ok) return new Response("Falha ao obter perfil GitHub", { status: 400, headers: { "Cache-Control": "no-store" } });
    const githubUser = await userResp.json();
    
    // Revogar a autorização imediatamente após o uso
    const revokeUrl = `https://api.github.com/applications/${clientId}/grant`;
    const revokeCreds = btoa(`${clientId}:${clientSecret}`);
    const revokeResp = await fetch(revokeUrl, {
      method: "DELETE",
      headers: {
        "Authorization": `Basic ${revokeCreds}`,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "Laboratorio-OAuth"
      },
      body: JSON.stringify({ access_token: tokens.access_token })
    });
    if (revokeResp.status !== 204) return new Response("Falha ao revogar token do GitHub", { status: 500, headers: { "Cache-Control": "no-store" } });

    sessionIssuer = "https://github.com";
    sessionSubject = String(githubUser.id);
    sessionEmail = githubUser.email || null;
    sessionName = githubUser.name || githubUser.login;
  }

  // 8. Criar sessão opaca local (8 horas)
  const sessionId = generateRandomString();
  const sessionIdHash = await sha256(sessionId);
  const expiresAt = now + 28800; 

  await context.env.DB.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at) 
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(sessionIdHash, sessionIssuer, sessionSubject, sessionEmail, sessionName, expiresAt, now).run();

  // 9 e 10. Limpar o cookie temporário, enviar o cookie de sessão e redirecionar
  const headers = new Headers();
  headers.append("Set-Cookie", serializeSessionCookie(sessionId));
  headers.append("Set-Cookie", `__Host-oauth-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
  headers.append("Location", context.env.PUBLIC_BASE_URL);
  headers.append("Cache-Control", "no-store");

  return new Response(null, { status: 302, headers });
}
