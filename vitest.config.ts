import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts', 'conformance/**/*.test.ts'],
    environment: 'node',
  },
});
