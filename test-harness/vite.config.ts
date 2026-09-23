import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
  plugins: [nodePolyfills({ globals: { Buffer: true, global: true, process: true } })],
  // embed-sdk is linked via `file:..`, so its imports of @stellar/stellar-sdk resolve to
  // ITS OWN node_modules copy (Node follows the real path, not the symlink) while this
  // harness resolves its own separate copy -- same version, but two distinct class
  // definitions. XDR's own instanceof-based type checks (e.g. XdrStringType._write's
  // `value instanceof XdrString` guard) then fail across that boundary for a value that IS
  // structurally correct, just built by "the other" copy of the class. Confirmed live:
  // "expected string, Uint8Array, or XdrString" thrown for entry.rootInvocation's
  // functionName, which genuinely was an XdrString -- just the wrong module instance of it.
  // dedupe forces both sides to resolve to this project's single copy.
  resolve: {
    dedupe: ['@stellar/stellar-sdk'],
  },
});
