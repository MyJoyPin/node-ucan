import { createRequire } from "node:module"
const {
  createDid,
  resolveDid,
  restoreDid,
  simpleSign,
  simpleVerify,
  invokeUcan,
  decodeUcan,
  verifyUcan
} = createRequire(import.meta.url)("./index.node")
export {
  createDid,
  resolveDid,
  restoreDid,
  simpleSign,
  simpleVerify,
  invokeUcan,
  decodeUcan,
  verifyUcan
}
export default createRequire(import.meta.url)("./index.node")
