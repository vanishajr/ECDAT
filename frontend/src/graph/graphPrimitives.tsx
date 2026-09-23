// Graph-only presentational mirrors of the shared App.tsx primitives.
// Duplicated (not imported) to avoid a circular App <-> graph import;
// class names are kept identical so the card looks unchanged.

export function Card({
  children,
  className = "",
  ...props
}: React.HTMLAttributes<HTMLElement>) {
  return (
    <article
      className={`rounded-[1.25rem] border border-[#d7d3ca] bg-[#f8f6f1]/90 shadow-[0_12px_34px_rgba(79,74,65,.07)] ${className}`}
      {...props}
    >
      {children}
    </article>
  );
}

export function Empty({ label }: { label: string }) {
  return <div className="p-8 text-center text-sm text-[#74716a]">{label}</div>;
}
