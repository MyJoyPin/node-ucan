# UCAN for Node.js

This is a Node.js module to work with UCAN authorization tokens. It is a wrapper over the [rs-ucan](https://github.com/ucan-wg/rs-ucan) Rust library. To learn more about UCANs and how you might use them in your application, visit [https://ucan.xyz][ucan-website] or read the [spec][spec].

Current UCAN Specification is v0.10.0[spec].

## Installing @myjoypin/node-ucan

This module contains prebuilt platform-specific binaries for Node.js v18 on
Windows x64 and Linux x64 (can be used in Docker containers without Rust setup).
For other platforms it will build the binary from source.

To build from source, you must have the Rust toolchain installed.
Check a [supported version of Node and Rust](https://github.com/neon-bindings/neon#platform-support). If you don't already have Rust installed, or don't have a supported version, go to the [Rust web site][rust-website] for installation instructions.

```bash
npm i @myjoypin/node-ucan

# to rebuild
npm rebuild @myjoypin/node-ucan --foreground-scripts
```

## Usage

UCANs can act the same as a classic JWT (Bearer) token, and also can grant a user the full control over their resources, with ability to delegate rights.

Example of delegation:

```js
import { createDid, invokeUcan, verifyUcan } from "@myjoypin/node-ucan"

// secret part
// here are the server, Alice and Bob
const serverDidDocument = createDid()
const aliceDidDocument = createDid()
const bobDidDocument = createDid()

// public part
const serverDid = serverDidDocument.id
const aliceDid = aliceDidDocument.id
const bobDid = bobDidDocument.id

// Server provides some rights to Alice.

const aliceToken = await invokeUcan({
  issuer: serverDidDocument.verificationMethod[0],
  audience: aliceDid,
  // 1 day
  expiration: Math.ceil((Date.now() + 1000 * 60 * 60 * 24) / 1000),
  capabilities: {
    "api:app/xxx": {
      "book/view": [{}],
      "book/edit": [{}],
      "user/is": [{ user_id: "111" }]
    }
  },
  facts: {
    app_id: "xxx",
    user_id: "111"
  }
})

// Alice can delegate some of her rights to Bob,
// without any interaction to the server.

const bobToken = await invokeUcan({
  issuer: aliceDidDocument.verificationMethod[0],
  audience: bobDid,
  // 6 hours
  expiration: Math.ceil((Date.now() + 1000 * 60 * 60 * 6) / 1000),
  capabilities: {
    "api:app/xxx": {
      "book/view": [{}],
      "user/is": [{ user_id: "111" }]
    }
  },
  proofs: [aliceToken]
})

// Bob uses his token to acess some Alice's resource on the server.

const token = await invokeUcan({
  issuer: bobDidDocument.verificationMethod[0],
  audience: serverDid,
  expiration: Math.ceil((Date.now() + 1000 * 60 * 60 * 6) / 1000),
  capabilities: {
    "api:app/xxx": {
      "book/view": [{}],
      "user/is": [{ user_id: "111" }]
    }
  },
  proofs: [bobToken]
})

// Server verifies rights through the all proof chain.

const verification = await verifyUcan(token, {
  rootIssuer: serverDid,
  audience: serverDid,
  requiredCapabilities: {
    "api:app/{app_id}": {
      "book/view": [{}],
      "user/is": [{ user_id: "{user_id}" }]
    }
  },
  requiredFacts: {
    app_id: "*",
    user_id: "*"
  }
})
// Here the server can continue verification, checking token revocations by CID
// and performing custom caveat checks.

console.log("Access granted!")
console.log(JSON.stringify(verification, null, 2))
/*
{
  "capabilities": {
    "api:app/xxx": {
      "book/view": [
        {}
      ],
      "user/is": [
        {
          "user_id": "111"
        }
      ]
    }
  },
  "facts": {
    "app_id": "xxx",
    "user_id": "111"
  },
  "cids": [
    "bafkr4icmf3o2omytuqxkhzm76hd5ifdfnhhmharru622ca264rznwegdvy",
    "bafkr4ieyr2wnbxe6ziuuougwngnfhnfeuw2e2anwcxyy36lsmcbh5zcguu",
    "bafkr4ib24o6fsjpnmtzwvjrbptq244waiwwsdu67e27och6quzdd5azo4q"
  ]
}
*/
```

## Decentralized identifiers

### Creating an identity

To be able to invoke an UCAN, you must have a [DID](https://en.wikipedia.org/wiki/Decentralized_identifier) (Decentralized Identifier).
Example of DID: **`"did:key:z6MkmftLP2owSZPneufrtWF7t9j2HL7sXYVgoroM59sjD7yx"`**.

```ts
createDid(keyType?: String, useJoseFormat?: Boolean): DIDDocument
```

Only "did:key" DIDs are supported.

Supported key types:

- "Ed25519" | "Ed25519VerificationKey2018" | "JsonWebKey2020"
- "P256" | "P-256"

Additional types for DID, but you cannot sign UCANs with them:

- "X25519" | "X25519KeyAgreementKey2019"
- "Bls12381" | "Bls12381G2Key2020" | "BLS12381_G2"
- "Secp256k1" | "EcdsaSecp256k1VerificationKey2019" | "secp256k1"

Example:

```js
import { createDid } from "@myjoypin/node-ucan"

const secretDidDocument = createDid()

console.log(JSON.stringify(secretDidDocument, null, 2))
```

"secretDidDocument" is a secret DID document (in JSON-LD format), containing your ID and private key. Please keep it in secret.

Optionally, you can specify a key type of the DID on creation (default is "Ed25519") and the flag to return document in JOSE format:

```js
import { createDid } from "@myjoypin/node-ucan"

const secretDidDocument = createDid("P256", true)

console.log(JSON.stringify(secretDidDocument, null, 2))
```

### Resolving a DID document

A DID can be resolved to a DID document. The DID document (in JSON format) contains public information about the DID.

```ts
resolveDid(did: String, useJoseFormat?: Boolean): DIDDocument
```

Example:

```js
import { resolveDid } from "@myjoypin/node-ucan"

const didDocument = resolveDid(
  "did:key:z6MkmftLP2owSZPneufrtWF7t9j2HL7sXYVgoroM59sjD7yx"
)

console.log(JSON.stringify(didDocument, null, 2))
```

### Restoring a DID

A DID can be restored from a private key (specified in "verificationMethod" field in the secret DID document).

```ts
restoreDid(privateKey: Object, useJoseFormat?: Boolean): DIDDocument
```

Example:

```js
import { restoreDid } from "@myjoypin/node-ucan"

const privateKey = {
  "id": "did:key:z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au#z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au",
  "type": "Ed25519VerificationKey2018",
  "controller": "did:key:z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au",
  "publicKeyBase58": "8BJoSgFxJRuna8x5a952PfaYPAJgGpzQBwZMBZTcoPX",
  "privateKeyBase58": "CjePJc2FYbQKTDaKeFyFRgKnzKF6DreCaX95b9x4z4Lu"
}

const secretDidDocument = restoreDid(privateKey)

console.log(JSON.stringify(secretDidDocument, null, 2))
```

### Digital sign

The DID can be used to sign data and verify signatures.

```ts
simpleSign(privateKey: Object, message: String): String
simpleVerify(did: String, message: String, signature: String): Boolean
```

Example of signing a message:

```js
import { simpleSign } from "@myjoypin/node-ucan"

const privateKey = {
  "id": "did:key:z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au#z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au",
  "type": "Ed25519VerificationKey2018",
  "controller": "did:key:z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au",
  "publicKeyBase58": "8BJoSgFxJRuna8x5a952PfaYPAJgGpzQBwZMBZTcoPX",
  "privateKeyBase58": "CjePJc2FYbQKTDaKeFyFRgKnzKF6DreCaX95b9x4z4Lu"
}

const signature = simpleSign(privateKey, "message to be signed")

console.log(signature)
// 0f5591xbxJ7kx8WL4wNDAU5jWcodQ91kllAcm11HF69af8mJL4WNj858yphxUVmETD9L9F44paJu2r0eTs7dDA
```

Example of a signature verification:

```js
import { simpleVerify } from "@myjoypin/node-ucan"

const isValid = simpleVerify(
  "did:key:z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au",
  "message to be signed",
  "0f5591xbxJ7kx8WL4wNDAU5jWcodQ91kllAcm11HF69af8mJL4WNj858yphxUVmETD9L9F44paJu2r0eTs7dDA")

console.log(isValid)
```

## UCANs

> User-Controlled Authorization Network (UCAN) is a trustless, secure, local-first, user-originated authorization and revocation scheme.

We also call UCAN tokens UCANs.

### Invocation of UCAN

```ts
invokeUcan({
  // the private key
  issuer: Object,
  // audience DID
  audience: String,
  // Unix time in seconds when the token becomes expired.
  expiration: number,
  // Unix time in seconds after which token becomes enabled. Optional.
  notBefore?: number,
  // Capabilities object.
  // Example:
  // {
  //   "mailto:username@example.com": {
  //     "msg/receive": [{}],
  //     "msg/send": [{ draft: true }, { publish: true, topic: ["foo"] }]
  //   }
  // }
  capabilities: Capabilities,
  // Facts object. Can contain any data linked with a token. Optional.
  facts?: Object,
  // Array of delegation proof tokens. Optional.
  proofs?: Array<String>,
  // Add a random nonce to this token. Optional, default false.
  addNonce?: Boolean,
  // Whenever to embed proof tokens to the "prf" field of facts. Doing so,
  // UCAN is complete for self-verification. Optional, default true.
  addProofFacts?: Boolean
}): Promise<String>
```

Example:

```js
import { invokeUcan } from "@myjoypin/node-ucan"

const privateKey = {
  "id": "did:key:z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au#z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au",
  "type": "Ed25519VerificationKey2018",
  "controller": "did:key:z6MkeaSMPgvhHqvNu4yem96usVDaMxSA6A5M6CrVBTXUY2Au",
  "publicKeyBase58": "8BJoSgFxJRuna8x5a952PfaYPAJgGpzQBwZMBZTcoPX",
  "privateKeyBase58": "CjePJc2FYbQKTDaKeFyFRgKnzKF6DreCaX95b9x4z4Lu"
}

const token = await invokeUcan({
  issuer: privateKey,
  audience: "did:key:z6Mkmup4Wyv9kXKrmy1DB2bLhaviKSgPGSqjC1gCEtWoHjAY",
  expiration: Math.ceil((Date.now() + 1000 * 60 * 60) / 1000),
  capabilities: {
    "mailto:username@example.com": {
      "msg/receive": [{}],
      "msg/send": [{ draft: true }, { publish: true, topic: ["foo"] }]
    }
  },
  facts: {
    a: "b"
  }
})

console.log(token)
```

### Rights delegation

The DID which is the audience of a token can delegate own rights to other DID.
Tranferred rights can be the same or lower level.

*To be described...*

### Reading UCAN without verification

```ts
decodeUcan(token: String): Ucan
```

Example:

```js
import { decodeUcan } from "@myjoypin/node-ucan"

// const token = ...

let ucan = decodeUcan(token)

console.log(JSON.stringify(ucan, null, 2))
```

### Verification of UCAN

To verify a token, you should provide required capabilities in the following format:

```
{
  "resource": {
    "ability": [...caveat],
  }
}
```

*To be described...*

```ts
verifyUcan(
  // the token
  token,
  {
    // The root rights issuer DID. An important field in the verification of
    // rights delegation.
    rootIssuer: String,
    // Audience DID
    audience: String,
    // Required capabilities. You can use template variables from facts with
    // "{var}" syntax. For example: "user/{user_id}".
    // Example:
    // {
    //   "mailto:username@example.com/x": {
    //     "msg/receive": [{}],
    //     "msg/send": [{ draft: true }, { publish: true, topic: ["foo"] }]
    //   }
    // }
    requiredCapabilities: Capabilities,
    // Required facts. If some facts are required. Optional.
    // To check for a field presence (with any value), use "*".
    // Also, fact fields can be used for replacement in "requiredCapabilities",
    // with "{var}" syntax. For example: "user/{user_id}".
    // Example:
    // {
    //   "user_id": "*"
    // }
    requiredFacts?: Object,
    // If UCAN to be verified doesn't contain some proofs embedded, need to 
    // provide them. Optional.
    knownTokens?: Array<String>
  }
): Promise<{
  // Capabilities allowed.
  capabilities: Capabilities,
  // Facts, if any. 
  facts?: Object,
  // CIDs array. After successfull verification, use this list to check for
  // revoked tokens.
  cids: Array<String>,
}>
```

Example:

```js
import { verifyUcan } from "@myjoypin/node-ucan"

// const rootIssuer = ...
// const audience = ...

// will throw if doesn't pass checks
await verifyUcan(token, {
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

console.log('Access granted')
```

### Verification semantics

1. Resource: "<scheme>:<path>"
   
    The resource is an URL-like path to resource (it can be a real URL).
    "scheme" is any application specific scheme, like "api", "docs".
    "path" is an URL-like path, like "user/1", "user/1/post/2". The path
    includes access to all its sub-paths, for example "user/1" includes any of
    "user/1/post/1", "user/1/post/2", etc. Verification is performed by first
    by comparing schemes, then comparing each part of paths between "/"
    sequentally.
    The special path "*" means all in a capability, and "some" in the
    requirement resource, for example the requirement "user/ *" allows
    "user/1", compared to the requirement "user" which doesn't allow it
    (as in this context "user" means all users, but "user/ *" means some user,
    but not all users).
   
    Examples:
   
   | Capability resource | Required resource | Includes                     |
   | ------------------- | ----------------- | ---------------------------- |
   | user                | user/1            | Yes                          |
   | user/1              | user              | No (required is higher)      |
   | user/1              | user/1            | Yes (are equal)              |
   | user/1              | user/1/doc/1      | Yes (required is included)   |
   | user/1              | user/2            | No (are not equal)           |
   | user/1              | doc/1             | No (are not equal)           |
   | *                   | user/1            | Yes (requred is included)    |
   | user/1              | *                 | No (reqired is higher level) |
   | user/1              | user/ *           | Yes                          |
   | user/ *             | user/1            | Yes                          |
   | user/1/post/1       | user/ * /post/2   | No                           |
   
2. Ability: "<namespace>/ability[/sub-ability]"
       
    The ability is an action allowed for the resource.
    Its format is "namespace/ability[/sub-ability]". The special ability "*"
    always means "all" (in difference to its meaning for resource). It
    can be used at the end to include all sub-actions ("user/post/ *"), but
    not in the middle.
    
    Examples:
    
    | Capability ability | Required ability | Enables |
    | ------------------ | ---------------- | ------- |
    | user/post          | user/post        | Yes     |
    | user/post          | user/post/draft  | Yes     |
    | user/post/draft    | user/post        | No      |
    | *                  | user/post        | Yes     |
    | user/post          | *                | No      |
    | user/ *            | user/post        | Yes     |
    | user/post          | user/ *          | No      |
   
3. Caveats: "[{<key>: <value>}[, {}, ...]]"
   
To be described...

## Examples

See the `examples` folder.

## License

This project is licensed under the [MIT license](https://github.com/myjoypin/node-ucan/blob/main/LICENSE).

[commit-spec]: https://www.conventionalcommits.org/en/v1.0.0/#specification
[commit-spec-site]: https://www.conventionalcommits.org/
[pre-commit]: https://pre-commit.com/
[spec]: https://github.com/ucan-wg/spec
[ucan-website]: https://ucan.xyz
[rust-website]: https://www.rust-lang.org
[git-website]: https://git-scm.com/
