use std::collections::BTreeMap;

use crate::{
    capability::{proof::ProofDelegationSemantics, Capability, CapabilitySemantics},
    crypto::KeyMaterial,
    serde::Base64Encode,
    time::now,
    ucan::{FactsMap, Ucan, UcanHeader, UcanPayload, UCAN_VERSION},
};
use anyhow::{anyhow, Result};
use base64::Engine;
use log::warn;
use multihash_codetable::Code;
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};

/// A signable is a UCAN that has all the state it needs in order to be signed,
/// but has not yet been signed.
/// NOTE: This may be useful for bespoke signing flows down the road. It is
/// meant to approximate the way that ts-ucan produces an unsigned intermediate
/// artifact (e.g., <https://github.com/ucan-wg/ts-ucan/blob/e10bdeca26e663df72e4266ccd9d47f8ce100665/src/builder.ts#L257-L278>)
pub struct Signable<'a, K>
where
    K: KeyMaterial,
{
    pub issuer: &'a K,
    pub audience: String,

    pub capabilities: Vec<Capability>,

    pub expiration: Option<u64>,
    pub not_before: Option<u64>,

    pub facts: FactsMap,
    pub proofs: Vec<String>,
    pub add_nonce: bool,
}

impl<'a, K> Signable<'a, K>
where
    K: KeyMaterial,
{
    /// The header field components of the UCAN JWT
    pub fn ucan_header(&self) -> UcanHeader {
        UcanHeader {
            alg: self.issuer.get_jwt_algorithm_name(),
            typ: "JWT".into(),
        }
    }

    /// The payload field components of the UCAN JWT
    pub async fn ucan_payload(&self) -> Result<UcanPayload> {
        let nonce = match self.add_nonce {
            true => Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(rand::thread_rng().gen::<[u8; 32]>()),
            ),
            false => None,
        };

        let facts = if self.facts.is_empty() {
            None
        } else {
            Some(self.facts.clone())
        };

        let proofs = if self.proofs.is_empty() {
            None
        } else {
            Some(self.proofs.clone())
        };

        Ok(UcanPayload {
            ucv: UCAN_VERSION.into(),
            aud: self.audience.clone(),
            iss: self.issuer.get_did().await?,
            exp: self.expiration,
            nbf: self.not_before,
            nnc: nonce,
            cap: self.capabilities.clone().try_into()?,
            fct: facts,
            prf: proofs,
        })
    }

    /// Produces a Ucan, which contains finalized UCAN fields along with signed
    /// data suitable for encoding as a JWT token string
    pub async fn sign(&self) -> Result<Ucan> {
        let header = self.ucan_header();
        let payload = self
            .ucan_payload()
            .await
            .expect("Unable to generate UCAN payload");

        let header_base64 = header.jwt_base64_encode()?;
        let payload_base64 = payload.jwt_base64_encode()?;

        let data_to_sign = format!("{header_base64}.{payload_base64}")
            .as_bytes()
            .to_vec();
        let signature = self.issuer.sign(data_to_sign.as_slice()).await?;

        Ok(Ucan::new(header, payload, data_to_sign, signature))
    }
}

/// A builder API for UCAN tokens
#[derive(Clone)]
pub struct UcanBuilder<'a, K>
where
    K: KeyMaterial,
{
    issuer: Option<&'a K>,
    audience: Option<String>,

    capabilities: Vec<Capability>,

    lifetime: Option<u64>,
    expiration: Option<u64>,
    not_before: Option<u64>,

    facts: FactsMap,
    proofs: Vec<String>,
    add_nonce: bool,

    add_proof_facts: bool,
}

impl<'a, K> Default for UcanBuilder<'a, K>
where
    K: KeyMaterial,
{
    /// Create an empty builder.
    /// Before finalising the builder, you need to at least call:
    ///
    /// - `issued_by`
    /// - `to_audience` and one of
    /// - `with_lifetime` or `with_expiration`.
    ///
    /// To finalise the builder, call its `build` or `build_parts` method.
    fn default() -> Self {
        UcanBuilder {
            issuer: None,
            audience: None,

            capabilities: Vec::new(),

            lifetime: None,
            expiration: None,
            not_before: None,

            facts: BTreeMap::new(),
            proofs: Vec::new(),
            add_nonce: false,

            add_proof_facts: false,
        }
    }
}

impl<'a, K> UcanBuilder<'a, K>
where
    K: KeyMaterial,
{
    /// The UCAN must be signed with the private key of the issuer to be valid.
    pub fn issued_by(mut self, issuer: &'a K) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// This is the identity this UCAN transfers rights to.
    ///
    /// It could e.g. be the DID of a service you're posting this UCAN as a JWT to,
    /// or it could be the DID of something that'll use this UCAN as a proof to
    /// continue the UCAN chain as an issuer.
    pub fn for_audience(mut self, audience: &str) -> Self {
        self.audience = Some(String::from(audience));
        self
    }

    /// The number of seconds into the future (relative to when build() is
    /// invoked) to set the expiration. This is ignored if an explicit expiration
    /// is set.
    pub fn with_lifetime(mut self, seconds: u64) -> Self {
        self.lifetime = Some(seconds);
        self
    }

    /// Set the POSIX timestamp (in seconds) for when the UCAN should expire.
    /// Setting this value overrides a configured lifetime value.
    pub fn with_expiration(mut self, timestamp: u64) -> Self {
        self.expiration = Some(timestamp);
        self
    }

    /// Set the POSIX timestamp (in seconds) of when the UCAN becomes active.
    pub fn not_before(mut self, timestamp: u64) -> Self {
        self.not_before = Some(timestamp);
        self
    }

    /// Add a fact or proof of knowledge to this UCAN.
    pub fn with_fact<T: Serialize + DeserializeOwned>(mut self, key: &str, fact: T) -> Self {
        match serde_json::to_value(fact) {
            Ok(value) => {
                self.facts.insert(key.to_owned(), value);
            }
            Err(error) => warn!("Could not add fact to UCAN: {}", error),
        }
        self
    }

    /// Add facts or proofs of knowledge to this UCAN.
    pub fn with_facts<T: Serialize + DeserializeOwned>(mut self, facts: &[(String, T)]) -> Self {
        let f: Vec<(String, serde_json::Value)> = facts
            .iter()
            .map(|k| {
                (
                    k.0.to_owned(),
                    serde_json::to_value(&k.1).unwrap_or(serde_json::json!("null")),
                )
            })
            .collect();
        self.facts.extend(f);
        self
    }

    /// Will ensure that the built UCAN includes a number used once.
    pub fn with_nonce(mut self) -> Self {
        self.add_nonce = true;
        self
    }

    /// Will add a collection of proof tokens (if any) to the facts field "prf".
    pub fn with_add_proof_facts(mut self, add_proof_facts: bool) -> Self {
        self.add_proof_facts = add_proof_facts;
        self
    }

    /// Includes a UCAN in the list of proofs for the UCAN to be built.
    /// Note that the proof's audience must match this UCAN's issuer
    /// or else the proof chain will be invalidated!
    /// The proof is encoded into a [Cid], hashed via the [UcanBuilder::default_hasher()]
    /// algorithm, unless one is provided.
    pub fn witnessed_by(mut self, authority: &Ucan, hasher: Option<Code>) -> Result<Self> {
        match authority.to_cid(hasher.unwrap_or_else(|| UcanBuilder::<K>::default_hasher())) {
            Ok(proof) => {
                self.insert_proof(&proof, authority)?;
                Ok(self)
            }
            Err(error) => Err(anyhow!("Failed to add authority to proofs: {}", error)),
        }
    }

    fn insert_proof(&mut self, proof: &cid::Cid, authority: &Ucan) -> Result<()> {
        self.proofs.push(proof.to_string());
        if self.add_proof_facts {
            if !self.facts.contains_key("prf") {
                self.facts.insert("prf".to_owned(), serde_json::json!({}));
            }
            if let Some(prf_map) = self.facts.get_mut("prf") {
                if let Some(prf_map) = prf_map.as_object_mut() {
                    prf_map.insert(
                        proof.to_string(),
                        serde_json::Value::String(authority.encode()?),
                    );
                }
            }
        }
        Ok(())
    }

    // Includes a collection of UCANs in the list of proofs for the UCAN to be built.
    // (see witnessed_by)
    pub fn with_proofs(self, proofs: &Vec<Ucan>, hasher: Option<Code>) -> Result<Self> {
        let mut s = self;
        for authority in proofs {
            s = s.witnessed_by(authority, hasher)?;
        }

        Ok(s)
    }

    /// Claim a capability by inheritance (from an authorizing proof) or
    /// implicitly by ownership of the resource by this UCAN's issuer
    pub fn claiming_capability<C>(mut self, capability: C) -> Self
    where
        C: Into<Capability>,
    {
        self.capabilities.push(capability.into());
        self
    }

    /// Claim capabilities by inheritance (from an authorizing proof) or
    /// implicitly by ownership of the resource by this UCAN's issuer
    pub fn claiming_capabilities<C>(mut self, capabilities: &[C]) -> Self
    where
        C: Into<Capability> + Clone,
    {
        let caps: Vec<Capability> = capabilities
            .iter()
            .map(|c| <C as Into<Capability>>::into(c.to_owned()))
            .collect();
        self.capabilities.extend(caps);
        self
    }

    /// Delegate all capabilities from a given proof to the audience of the UCAN
    /// you're building.
    /// The proof is encoded into a [Cid], hashed via the [UcanBuilder::default_hasher()]
    /// algorithm, unless one is provided.
    pub fn delegating_from(mut self, authority: &Ucan, hasher: Option<Code>) -> Result<Self> {
        match authority.to_cid(hasher.unwrap_or_else(|| UcanBuilder::<K>::default_hasher())) {
            Ok(proof) => {
                self.insert_proof(&proof, authority)?;
                let proof_delegation = ProofDelegationSemantics {};
                let capability = proof_delegation.parse(&format!("ucan:{proof}"), "ucan/*", None);

                match capability {
                    Some(capability) => {
                        self.capabilities.push(Capability::from(&capability));
                    }
                    None => {
                        return Err(anyhow!("Could not produce delegation capability"));
                    }
                }
            }
            Err(error) => return Err(anyhow!("Could not encode authoritative UCAN: {:?}", error)),
        };

        Ok(self)
    }

    /// Returns the default hasher ([Code::Blake3_256]) used for [Cid] encodings.
    pub fn default_hasher() -> Code {
        Code::Blake3_256
    }

    fn implied_expiration(&self) -> Option<u64> {
        if self.expiration.is_some() {
            self.expiration
        } else {
            self.lifetime.map(|lifetime| now() + lifetime)
        }
    }

    pub fn build(self) -> Result<Signable<'a, K>> {
        match &self.issuer {
            Some(issuer) => match &self.audience {
                Some(audience) => Ok(Signable {
                    issuer,
                    audience: audience.clone(),
                    not_before: self.not_before,
                    expiration: self.implied_expiration(),
                    facts: self.facts.clone(),
                    capabilities: self.capabilities.clone(),
                    proofs: self.proofs.clone(),
                    add_nonce: self.add_nonce,
                }),
                None => Err(anyhow!("Missing audience")),
            },
            None => Err(anyhow!("Missing issuer")),
        }
    }
}
