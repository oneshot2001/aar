export function sanitizedRequestTarget(target: URL): string {
  const query = [...new Set(target.searchParams.keys())]
    .sort()
    .map((name) => `${encodeURIComponent(name)}=<sanitized>`)
    .join("&");
  return `${target.pathname}${query ? `?${query}` : ""}`;
}
