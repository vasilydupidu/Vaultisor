import { cn } from "@/lib/cn";

interface Props {
  size?: number;
  className?: string;
  withWordmark?: boolean;
  /**
   * Стиль рендера:
   *  - "mark"  (default): два полупрозрачных треугольника на прозрачном фоне.
   *            Используется внутри UI (там, где фон уже задан).
   *  - "tile": тот же знак на teal-плитке со скруглением — для favicon/иконки/about.
   */
  variant?: "mark" | "tile";
}

/**
 * Знак Vaultisor — слоёный V.
 * Концепция: два треугольника (передний solid, задний полупрозрачный)
 * образуют монолитный "V" без обрамления. Прямая отсылка к названию,
 * никаких клише со щитом или замком.
 * Палитра — фирменный teal #0CA49F.
 */
export function BrandLogo({
  size = 48,
  className,
  withWordmark = false,
  variant = "mark",
}: Props) {
  const isTile = variant === "tile";
  return (
    <div className={cn("inline-flex items-center gap-2", className)}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 64 64"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-label="Vaultisor"
        role="img"
      >
        <defs>
          <linearGradient
            id="vault-front"
            x1="0"
            y1="0"
            x2="0"
            y2="1"
          >
            <stop offset="0" stopColor="#10B5AF" />
            <stop offset="1" stopColor="#0A8A86" />
          </linearGradient>
        </defs>

        {/* Плитка (только для variant="tile") */}
        {isTile && (
          <>
            <rect
              x="2"
              y="2"
              width="60"
              height="60"
              rx="14"
              fill="#0F0F0F"
            />
            <rect
              x="2"
              y="2"
              width="60"
              height="60"
              rx="14"
              fill="none"
              stroke="rgba(255,255,255,0.06)"
              strokeWidth="0.5"
            />
          </>
        )}

        {/* Задний треугольник — полупрозрачный teal. */}
        <path
          d="M 10 14 L 38 14 L 24 50 Z"
          fill="#0CA49F"
          opacity={isTile ? 0.55 : 0.45}
        />

        {/* Передний треугольник — solid с тонким градиентом. */}
        <path
          d="M 24 14 L 52 14 L 38 50 Z"
          fill="url(#vault-front)"
        />

        {/* Тонкая highlight-линия на переднем треугольнике для глубины. */}
        <path
          d="M 27 17 L 36 46"
          stroke="rgba(255,255,255,0.28)"
          strokeWidth="1"
          strokeLinecap="round"
        />
      </svg>
      {withWordmark && (
        <span className="text-lg font-medium tracking-tight">
          Vault<span className="text-brand-400">isor</span>
        </span>
      )}
    </div>
  );
}
