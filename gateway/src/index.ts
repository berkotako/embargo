import { EmbargoPlugin } from './plugin';

export { EmbargoPlugin };

// Verdaccio plugin entry point — called by Verdaccio's plugin loader.
export default function (config: unknown, options: unknown): EmbargoPlugin {
  return new EmbargoPlugin(config, options);
}
