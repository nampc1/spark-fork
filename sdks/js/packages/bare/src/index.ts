import 'bare-node-runtime/global';

/* Avoid a console.error that comes from an import of Node.js require-in-the-middle module, see LIG-8098 */
Object.defineProperty(globalThis.Module, "_resolveFilename", {
  value: () => {
    throw new Error(
      "@buildonspark/bare: This method is not supported in bare.",
    );
  },
  writable: false,
  enumerable: false,
  configurable: false,
});

export * from "@buildonspark/spark-sdk/bare" with { imports: 'bare-node-runtime/imports' };
export { BareSparkSigner } from "./bare-signer.js" with { imports: 'bare-node-runtime/imports' };
