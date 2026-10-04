// Биты энтропии сгенерированного значения.
//
// Показываем число, а не полоску «Strong/Weak»: полоска ничего не объясняет и
// у каждого продукта своя шкала, а «87 бит» — проверяемая величина, из которой
// видно, почему 15 символов пароля это минимум, а 8 — нет.

import type { GeneratedKind } from "@/lib/api";

/** Размер алфавита для каждого типа. Должен совпадать с CHARSETS в
 *  generateSecret.ts: расхождение исказит показанную оценку. */
export const ALPHABET_SIZE: Record<GeneratedKind, number> = {
  // ABC..z + 0..9 + !@#$%^&*()_+-=[]{}|;:,.<>?
  password: 88,
  // Только латинские буквы и цифры: 26 + 26 + 10.
  alnum: 62,
  hex: 16,
  base64url: 64,
};

/** log2(алфавит) * длина, округлённое вниз — оценка не должна льстить. */
export function entropyBits(kind: GeneratedKind, length: number): number {
  if (length <= 0) return 0;
  return Math.floor(Math.log2(ALPHABET_SIZE[kind]) * length);
}
