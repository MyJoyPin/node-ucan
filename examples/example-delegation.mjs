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
console.log("Access granted!")
