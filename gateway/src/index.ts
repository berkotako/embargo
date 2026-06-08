import { EmbargoStorageFilter } from './plugin';

export { EmbargoStorageFilter };
export { rewritePackument, buildHeldError } from './packument';

// Verdaccio plugin entry point — the loader calls the default export with the
// plugin's config block and Verdaccio's options, expecting a plugin instance.
export default function (config: unknown, options: unknown): EmbargoStorageFilter {
  return new EmbargoStorageFilter(config, options);
}
