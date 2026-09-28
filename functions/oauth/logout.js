import { parseCookie } from "../shared/cookies.js";
import { sha256 } from "../shared/crypto.js";

// Só aceita POST (onRequestPost)
export async function onRequestPost(context) {
  // Exigir cabeçalho Origin exatamente igual a PUBLIC_BASE_URL
  const origin = context.request.headers.get("Origin");
  if (origin !== context.env.PUBLIC_BASE_URL) {
    return new Response("Origem inválida", { status: 403, headers: { "Cache-Control": "no-store" } });
  }

  const cookieHeader = context.request.headers.get("Cookie");
  const sessionCookie = parseCookie(cookieHeader, "__Host-session");

  if (sessionCookie) {
    const sessionIdHash = await sha256(sessionCookie);
    // Remover a linha da sessão no D1
    await context.env.DB.prepare(
      `DELETE FROM sessions WHERE id_hash = ?`
    ).bind(sessionIdHash).run();
  }

  // Expirar o cookie e redirecionar para a raiz
  const headers = new Headers();
  headers.append("Set-Cookie", `__Host-session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
  headers.append("Location", context.env.PUBLIC_BASE_URL);
  headers.append("Cache-Control", "no-store");

  return new Response(null, { status: 302, headers });
}
