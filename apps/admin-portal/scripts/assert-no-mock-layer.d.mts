export const DEV_MOCK_MARKER: string;
export const NEEDLES: string[];
export function scanForMockLayer(nextDir: string): Promise<{ file: string; needle: string }[]>;
