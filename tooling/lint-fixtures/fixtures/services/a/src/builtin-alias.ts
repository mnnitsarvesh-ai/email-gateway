const { getBuiltinModule } = process;

export const q: unknown = getBuiltinModule('node:module');
