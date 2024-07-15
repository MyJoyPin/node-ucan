import { createRequire } from "node:module"
const require = createRequire(import.meta.url)
const {
  createDid,
  resolveDid,
  restoreDid,
  simpleSign,
  simpleVerify
} = require("../index.node")
import assert from "assert"

function testCreate() {
  console.log("Creating identity in JSON-LD format with a default algorithm...")
  const secretDidDocument = createDid()
  console.log("New identity:")
  console.log(JSON.stringify(secretDidDocument, null, 2))
  return secretDidDocument
}

function testResolve(did) {
  const didDocument = resolveDid(did)
  console.log("Resolved DID document:")
  console.log(JSON.stringify(didDocument, null, 2))
}

function testRestore() {
  const verificationMethod = {
    id: "did:key:z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au#z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au",
    type: "Ed25519VerificationKey2018",
    controller: "did:key:z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au",
    publicKeyBase58: "8BJoSgFxJRuna8x5a952PfaYPAJgGpzQBwZMBZTcoPX",
    privateKeyBase58: "CjePJc2FYbQKTDaKeFyFRgKnzKF6DreCaX95b9x4z4Lu"
  }
  const restored = restoreDid(verificationMethod)
  assert(
    restored.id === "did:key:z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au"
  )
  console.log("Restore DID from private key:")
  console.log(restored)
}

function testSign(verificationMethod, message) {
  const signature = simpleSign(verificationMethod, message)
  console.log(`Signature: ${signature}`)
  return signature
}

function testVerify(did, message, signature) {
  const isValid = simpleVerify(did, message, signature)
  console.log(`Signature id ${isValid ? "valid" : "invalid"}!`)
}

const secretDidDocument = testCreate()
const did = secretDidDocument.id
testResolve(did)
testRestore()

const message = "message to be signed"
const signature = testSign(secretDidDocument.verificationMethod[0], message)
testVerify(did, message, signature)
