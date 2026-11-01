export async function load(): Promise<unknown> {
  return await import('@esg/db/control-plane');
}
