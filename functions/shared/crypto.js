// Gera 32 bytes aleatórios e converte para Base64URL sem preenchimento
export function generateRandomString() {
  const buffer = new Uint8Array(32);
  crypto.getRandomValues(buffer);
  return base64UrlEncode(buffer);
}

// Calcula o hash SHA-256 de uma string e devolve em Base64URL
export async function sha256(plain) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(new Uint8Array(hashBuffer));
}

// Função auxiliar de conversão para Base64URL
function base64UrlEncode(buffer) {
  let binary = "";
  for (let i = 0; i < buffer.byteLength; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
