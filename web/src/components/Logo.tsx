/** PassAuth mark: a key whose bow and shank form a "P", with a keyhole in the bowl. */
export function LogoMark({ size = 32, title = "PassAuth" }: { size?: number; title?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" role="img" aria-label={title}>
      <rect width="64" height="64" rx="14" fill="var(--logo-plate)" />
      <g fill="var(--brass)">
        <path d="M34 8.5a15.5 15.5 0 1 1 0 31 15.5 15.5 0 0 1 0-31zm0 7a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17z" />
        <rect x="17" y="10" width="7.5" height="45" rx="3.75" />
        <rect x="23" y="41" width="9" height="5" rx="1.5" />
        <rect x="23" y="49" width="6" height="5" rx="1.5" />
        <circle cx="34" cy="22.5" r="3" />
        <path d="M32.4 24h3.2l.9 5.2h-5z" />
      </g>
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="wordmark">
      <LogoMark size={28} />
      <span>PassAuth</span>
    </span>
  );
}
