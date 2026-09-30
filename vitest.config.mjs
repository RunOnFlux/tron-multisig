// Integration tests against a real java-tron private chain (see README-TESTING.md).
// Everything runs serially: one chain, one set of funded actors, real 3-second blocks.
import { defineConfig } from 'vitest/config';
import { BaseSequencer } from 'vitest/node';

/** Run test files in file-name order (00-…, 01-…, 90-energy last). */
class ByNameSequencer extends BaseSequencer {
  async sort(files) {
    return [...files].sort((a, b) => a.moduleId.localeCompare(b.moduleId));
  }
}

export default defineConfig({
  test: {
    include: ['test/**/*.test.mjs'],
    globalSetup: ['./test/globalSetup.mjs'],
    fileParallelism: false,
    maxWorkers: 1,
    isolate: false,
    sequence: { sequencer: ByNameSequencer, concurrent: false, shuffle: false },
    testTimeout: 300_000,
    hookTimeout: 900_000,
    teardownTimeout: 60_000,
    reporters: ['default'],
  },
});
