/** BlueStrix mark: a blue badge with an owl face (the genus name "Strix" means owl). */
export function BlueStrixMark({ className = "h-9 w-9" }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={className} role="img" aria-label="BlueStrix logo">
      <rect width="64" height="64" rx="16" fill="#2563eb" />
      <path
        d="M14 22 L20 11 L27 20 L37 20 L44 11 L50 22 L50 40 Q50 53 32 55 Q14 53 14 40 Z"
        fill="#eff6ff"
      />
      <circle cx="24" cy="32" r="8.5" fill="#1e3a8a" />
      <circle cx="40" cy="32" r="8.5" fill="#1e3a8a" />
      <circle cx="26.5" cy="30.5" r="3" fill="#eff6ff" />
      <circle cx="42.5" cy="30.5" r="3" fill="#eff6ff" />
      <path d="M28.5 39 L35.5 39 L32 46 Z" fill="#f59e0b" />
    </svg>
  );
}
