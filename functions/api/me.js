import { parseCookie } from "../shared/cookies.js";
import { sha256 } from "../shared/crypto.js";

export async function onRequestGet(context) {
  const cookieHeader = context.request.headers.get("Cookie");
  const sessionCookie = parseCookie(cookieHeader, "__Host-session");

  // Se não houver cookie, devolve 401 Unauthorized
  if (!sessionCookie) {
    return new Response(null, { status: 401, headers: { "Cache-Control": "no-store" } });
  }

  // Calcula o hash do cookie para procurar no D1
  const sessionIdHash = await sha256(sessionCookie);
  const now = Math.floor(Date.now() / 1000);

  const session = await context.env.DB.prepare(
    `SELECT email, display_name FROM sessions WHERE id_hash = ? AND expires_at > ?`
  ).bind(sessionIdHash, now).first();

  if (!session) {
    return new Response(null, { status: 401, headers: { "Cache-Control": "no-store" } });
  }

  // Devolve o perfil mínimo exigido pelo laboratório
  return Response.json(
    {
      email: session.email,
      displayName: session.display_name
    },
    {
      headers: { "Cache-Control": "no-store" }
    }
  );
}
