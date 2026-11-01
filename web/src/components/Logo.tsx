import { useId } from "react";

/** PassAuth mark (assets/passauth-logo.svg): a shield holding a white "P" with a keyhole. */
export function LogoMark({ size = 32, title = "PassAuth" }: { size?: number; title?: string }) {
  const gradient = `pa-shield-${useId().replace(/:/g, "")}`;
  return (
    <svg width={Math.round((size * 128) / 144)} height={size} viewBox="0 0 128 144" role="img" aria-label={title}>
      <defs>
        <linearGradient id={gradient} x1="0" y1="1" x2="1" y2="0">
          <stop offset="0" stopColor="#082052" />
          <stop offset="0.52" stopColor="#0866ED" />
          <stop offset="1" stopColor="#23D5F4" />
        </linearGradient>
      </defs>
      <path d="M64 5 111 27 Q117 30 117 39 V82 Q117 114 64 139 Q11 114 11 82 V39 Q11 30 17 27 Z" fill={`url(#${gradient})`} />
      <path
        d="M42 30 H70 C95 30 103 45 103 62 C103 82 89 96 66 96 H55 V121 L38 112 V30 Z M55 48 V78 H67 C79 78 84 72 84 63 C84 54 79 48 67 48 Z"
        fill="#FFFFFF"
        fillRule="evenodd"
      />
      <circle cx="69" cy="59" r="5" fill="#082052" />
      <path d="M66.8 62 H71.2 L74 71 H64 Z" fill="#082052" />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="wordmark">
      <LogoMark size={28} />
      <span>
        Pass<span className="wm-auth">Auth</span>
      </span>
    </span>
  );
}
