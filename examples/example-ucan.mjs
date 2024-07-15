import { createRequire } from "node:module"
const require = createRequire(import.meta.url)
const {
  invokeUcan,
  verifyUcan,
  decodeUcan,
  createDid
} = require("../index.node")

async function testInvokeUcan() {
  const secretDidDocument = createDid()
  const verificationMethod = secretDidDocument.verificationMethod[0]

  const token = await invokeUcan({
    issuer: verificationMethod,
    audience: "did:key:zabcde...",
    expiration: Math.ceil(Date.now() / 1000) + 60,
    capabilities: {
      "mailto:username@example.com": {
        "msg/receive": [{}],
        "msg/send": [{ draft: true }, { publish: true, topic: ["foo"] }]
      }
    },
    facts: {
      a: "b",
    },
    addNonce: true
  })

  return { token, did: secretDidDocument.id }
}

function testDecodeUcan(token) {
  return decodeUcan(token)
}

async function testVerifyUcan(token, rootIssuer) {
  let audience = "did:key:zabcde..."

  return verifyUcan(token, {
    rootIssuer,
    audience,
    requiredCapabilities: {
      "mailto:username@example.com": {
        "msg/receive": [{}],
        "msg/send": [{ draft: true }, { publish: true, topic: ["foo"] }]
      }
    },
    requiredFacts: {
      a: "b"
    }
  })
}

const { token, did } = await testInvokeUcan()
console.log("ucan:")
console.log(token)
const decoded = testDecodeUcan(token)
console.log("decoded:")
console.log(JSON.stringify({
  header: decoded.header,
  payload: decoded.payload,
  cid: decoded.cid
}, null, 2))
const verification = await testVerifyUcan(token, did)
console.log('verification:')
console.log(JSON.stringify(verification, null, 2))
console.log("Access granted!")
