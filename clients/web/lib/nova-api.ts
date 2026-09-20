export async function novaFetch<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(`/api/nova/${path.replace(/^\//, '')}`, {
    ...init,
    cache: 'no-store',
  });

  if (response.status === 401 && typeof window !== 'undefined') {
    window.location.assign('/login');
    throw new Error('Authentication required');
  }

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      detail = data.detail || data.message || detail;
    } catch {
      // Keep the status-only error when the upstream response is not JSON.
    }
    throw new Error(detail);
  }

  return response.json() as Promise<T>;
}
