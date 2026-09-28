// Cria o cookie temporário da transação (dura 10 minutos)
export function serializeTxCookie(value) {
  return `__Host-oauth-tx=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;
}

// Cria o cookie da sessão final (dura 8 horas)
export function serializeSessionCookie(value) {
  return `__Host-session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`;
}

// Função para extrair um cookie específico do cabeçalho da requisição
export function parseCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(new RegExp(`(^| )${name}=([^;]+)`));
  return match ? match[2] : null;
}
