/**
 * Декоративный паттерн (вдохновлён фирменным паттерном бренд-бука,
 * но переинтерпретирован для тёмной темы — концентрические teal-дуги).
 * Используется на онбординге и lock-экране.
 */
export function BackgroundPattern({ opacity = 0.5 }: { opacity?: number }) {
  return (
    <div
      className="pointer-events-none absolute inset-0 -z-10 overflow-hidden"
      style={{ opacity }}
      aria-hidden
    >
      {/* Большие вспышки света */}
      <div className="absolute -top-40 left-1/2 -translate-x-1/2 h-[420px] w-[420px] rounded-full bg-brand-500/15 blur-3xl" />
      <div className="absolute bottom-[-180px] right-[-100px] h-[300px] w-[300px] rounded-full bg-accent-400/[0.06] blur-3xl" />
      {/* Сетка */}
      <div className="absolute inset-0 bg-dots" />
      {/* Тонкие концентрические дуги */}
      <svg
        className="absolute -top-32 left-1/2 -translate-x-1/2"
        width="700"
        height="500"
        viewBox="0 0 700 500"
        fill="none"
      >
        {[...Array(8)].map((_, i) => (
          <ellipse
            key={i}
            cx="350"
            cy="250"
            rx={120 + i * 38}
            ry={70 + i * 18}
            stroke="rgba(12,164,159,0.08)"
            strokeWidth="1"
          />
        ))}
      </svg>
    </div>
  );
}
