export const EVALUATOR_PACKAGES: string[];
export const NEEDLES: string[];
export function scanForPolicyEvaluator(
  nextDir: string,
): Promise<{ file: string; needle: string }[]>;
