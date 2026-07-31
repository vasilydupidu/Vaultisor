// Фаза 3 (#1): криптостойкая генерация значения поля (локально, без сети).
// Источник — WebCrypto CSPRNG (crypto.getRandomValues). Используется rejection
// sampling, чтобы избежать modulo-bias при алфавитах, не кратных 256.

export type Charset = "alnumSymbols" | "alnum" | "hex" | "base64url";
import i18n from '@/lib/i18n';

const CHARSETS: Record<Charset, string> = {
  alnumSymbols:
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?",
  alnum: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  hex: "0123456789abcdef",
  base64url:
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
};

export const CHARSET_LABELS: Record<Charset, string> = {
  get alnumSymbols() { return i18n.t('generator.charsetAlnumSymbols'); },
  get alnum() { return i18n.t('generator.charsetAlnum'); },
  get hex() { return i18n.t('generator.charsetHex'); },
  get base64url() { return i18n.t('generator.charsetBase64url'); },
};

export const CHARSET_ORDER: Charset[] = ["alnumSymbols", "alnum", "hex", "base64url"];

export function generateSecret(length: number, charset: Charset): string {
  const chars = CHARSETS[charset];
  const n = chars.length;
  // Порог для отбраковки: убирает смещение при n, не делящем 256.
  const max = Math.floor(256 / n) * n;
  const out: string[] = [];
  const buf = new Uint8Array(64);
  while (out.length < length) {
    crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length && out.length < length; i++) {
      const b = buf[i]!;
      if (b >= max) continue; // rejection sampling
      out.push(chars[b % n]!);
    }
  }
  return out.join("");
}
