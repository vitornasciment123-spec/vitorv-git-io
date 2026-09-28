import { generateRandomString, sha256 } from "../../shared/crypto.js";
import { serializeTxCookie } from "../../shared/cookies.js";
import { providers } from "../../shared/providers.js";

export async function onRequestGet(context) {
  const provider = context.params.provider;

  // 1. Aceitar somente google ou github
  if (provider !== "google" && provider !== "github") {
    return new Response("Not Found", { status: 404 });
  }

  // 2. Gerar a transação (valores aleatórios em Base64URL)
  const txId = generateRandomString();
  const state = generateRandomString();
  const codeVerifier = generateRandomString();
  const nonce = provider === "google" ? generateRandomString() : null;

  // Calcular os resumos SHA-256
  const txIdHash = await sha256(txId);
  const stateHash = await sha256(state);
  const codeChallenge = await sha256(codeVerifier);

  // Gravar no D1 com expiração de 10 minutos (600 segundos)
  const expiresAt = Math.floor(Date.now() / 1000) + 600;
  await context.env.DB.prepare(
    `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at) 
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(txIdHash, provider, stateHash, nonce, codeVerifier, expiresAt).run();

  // 3. Obter as credenciais do ambiente
  const clientId = provider === "google" 
    ? context.env.GOOGLE_CLIENT_ID 
    : context.env.GITHUB_CLIENT_ID;
  
  const redirectUri = `${context.env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;

  // 4. Montar o pedido de autorização (conforme a sua imagem)
  const authUrl = new URL(providers[provider].authUrl);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  // Regra específica da imagem: Somente no Google adicionar scope e nonce
  if (provider === "google") {
    authUrl.searchParams.set("scope", "openid email profile");
    authUrl.searchParams.set("nonce", nonce);
  }

  // 5. Responder com redirecionamento 302 e o cookie temporário
  return new Response(null, {
    status: 302,
    headers: {
      "Location": authUrl.toString(),
      "Set-Cookie": serializeTxCookie(txId),
      "Cache-Control": "no-store"
    }
  });
}
