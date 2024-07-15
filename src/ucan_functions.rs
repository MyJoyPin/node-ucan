use crate::did_functions::get_keys;
use crate::runtime;
use crate::semantics::GeneralSemantics;
use anyhow::{anyhow, Result};
use did_key::KeyFormat;
use did_key::VerificationMethod;
use neon::prelude::*;
use neon::types::JsPromise;
use serde::{Deserialize, Serialize};
use tinytemplate::TinyTemplate;
use ucan::store::{MemoryStore, UcanJwtStore};
use ucan::{
    builder::UcanBuilder,
    capability::{Capabilities, Capability, CapabilitySemantics},
    chain::ProofChain,
    crypto::did::{
        DidParser, KeyConstructorSlice, ED25519_MAGIC_BYTES, P256_MAGIC_BYTES, RSA_MAGIC_BYTES,
    },
    crypto::KeyMaterial,
    ucan::{Code, FactsMap},
    Ucan,
};
use ucan_key_support::{
    ed25519::{bytes_to_ed25519_key, bytes_to_ed25519_private_key},
    p256::{bytes_to_p256_key, bytes_to_p256_private_key},
    rsa::bytes_to_rsa_key,
};

pub const SUPPORTED_KEYS: &KeyConstructorSlice = &[
    // https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L94
    (ED25519_MAGIC_BYTES, bytes_to_ed25519_key),
    (RSA_MAGIC_BYTES, bytes_to_rsa_key),
    (P256_MAGIC_BYTES, bytes_to_p256_key),
];

#[derive(Debug, Serialize, Deserialize)]
pub struct InvokeOptions {
    pub issuer: VerificationMethod,
    pub audience: String,
    pub expiration: u64,
    #[serde(rename = "notBefore")]
    pub not_before: Option<u64>,
    pub capabilities: Capabilities,
    pub facts: Option<FactsMap>,
    pub proofs: Option<Vec<String>>,
    #[serde(rename = "addNonce")]
    pub add_nonce: Option<bool>,
    #[serde(rename = "addProofFacts")]
    pub add_proof_facts: Option<bool>,
}

pub fn invoke_ucan(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let config: Handle<neon::types::JsValue> = cx.argument(0)?;
    let config: InvokeOptions =
        neon_serde2::from_value(&mut cx, config).or_else(|e| cx.throw_error(e.to_string()))?;

    let verification_method = &config.issuer;

    let keys = get_keys(
        &verification_method.public_key,
        &verification_method.private_key,
    )
    .or_else(|e| cx.throw_error(e.to_string()))?;

    let mut key_type = verification_method.key_type.clone();
    if key_type == "JsonWebKey2020" {
        if let Some(KeyFormat::JWK(k)) = &verification_method.private_key {
            key_type.clone_from(&k.curve);
        } else {
            return cx.throw_error("invalid private key");
        }
    }

    let key_material = match key_type.as_str() {
        "Ed25519" | "Ed25519VerificationKey2018" => bytes_to_ed25519_private_key(keys.1),
        "P256" | "UnsupportedVerificationMethod2020" | "P-256" => bytes_to_p256_private_key(keys.1),
        _ => {
            return cx.throw_error(format!(r#"unsupported key type: "{}""#, key_type));
        }
    };

    let key_material = key_material.or_else(|e| cx.throw_error(e.to_string()))?;

    let proofs = match &config.proofs {
        Some(proofs) => {
            let mut ucans: Vec<Ucan> = Vec::new();
            for token in proofs.iter() {
                ucans.push(
                    Ucan::try_from(token.clone()).or_else(|e| cx.throw_error(e.to_string()))?,
                );
            }
            Some(ucans)
        }
        None => None,
    };

    // Construct a result promise which will be fulfilled when the computation completes.
    let (deferred, promise) = cx.promise();
    let channel = cx.channel();
    let runtime = runtime(&mut cx)?;

    // Perform the computation in a background thread using the Tokio thread pool.
    runtime.spawn(async move {
        let result = build_ucan(config, proofs, key_material).await;

        // Resolve the result promise with the result of the computation.
        deferred.settle_with(&channel, |mut cx| match result {
            Ok(result) => Ok(cx.string(result)),
            Err(e) => cx.throw_error(e.to_string()),
        });
    });

    Ok(promise)
}

async fn build_ucan(
    config: InvokeOptions,
    proofs: Option<Vec<Ucan>>,
    key_material: Box<dyn KeyMaterial>,
) -> Result<String> {
    let mut builder = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&config.audience)
        .with_expiration(config.expiration)
        .claiming_capabilities(&config.capabilities.iter().collect::<Vec<Capability>>());
    if let Some(add_proof_facts) = &config.add_proof_facts {
        builder = builder.with_add_proof_facts(*add_proof_facts);
    } else {
        builder = builder.with_add_proof_facts(true);
    }
    if let Some(not_before) = &config.not_before {
        builder = builder.not_before(*not_before);
    }
    if let Some(facts) = &config.facts {
        builder = builder.with_facts(
            &facts
                .iter()
                .map(|x| (x.0.clone(), x.1.clone()))
                .collect::<Vec<(String, serde_json::Value)>>(),
        );
    }
    if let Some(proofs) = &proofs {
        builder = builder.with_proofs(proofs, None)?;
    }
    if let Some(add_nonce) = &config.add_nonce {
        if *add_nonce {
            builder = builder.with_nonce();
        }
    }
    let result: String = builder.build()?.sign().await?.encode()?;
    Ok(result)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyOptions {
    #[serde(rename = "rootIssuer")]
    pub root_issuer: String,
    pub audience: String,
    #[serde(rename = "requiredCapabilities")]
    pub required_capabilities: Capabilities,
    #[serde(rename = "requiredFacts")]
    pub required_facts: Option<FactsMap>,
    #[serde(rename = "knownTokens")]
    pub known_tokens: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub capabilities: Capabilities,
    pub facts: Option<FactsMap>,
    pub cids: Vec<String>,
}

pub fn verify_ucan(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let token: Handle<neon::types::JsValue> = cx.argument(0)?;
    let token: Handle<JsString> = token.downcast_or_throw(&mut cx)?;
    let token: String = token.value(&mut cx);
    let config: Handle<neon::types::JsValue> = cx.argument(1)?;
    let config: VerifyOptions =
        neon_serde2::from_value(&mut cx, config).or_else(|e| cx.throw_error(e.to_string()))?;

    let mut did_parser = DidParser::new(SUPPORTED_KEYS);

    // Construct a result promise which will be fulfilled when the computation completes.
    let (deferred, promise) = cx.promise();
    let channel = cx.channel();
    let runtime = runtime(&mut cx)?;

    // Perform the computation in a background thread using the Tokio thread pool.
    runtime.spawn(async move {
        let result = internal_verify_ucan(&token, config, &mut did_parser).await;

        // Resolve the result promise with the result of the computation.
        deferred.settle_with(&channel, |mut cx| match result {
            Ok(result) => match neon_serde2::to_value(&mut cx, &result) {
                Ok(result) => Ok(result),
                Err(e) => cx.throw_error(e.to_string()),
            },
            Err(e) => cx.throw_error(e.to_string()),
        });
    });

    Ok(promise)
}

async fn internal_verify_ucan(
    token: &str,
    config: VerifyOptions,
    did_parser: &mut DidParser,
) -> Result<VerifyResponse> {
    // TODO use global store
    let mut store = MemoryStore::default();
    if let Some(proofs) = config.known_tokens {
        for proof in proofs.iter() {
            store.write_token(proof).await?;
        }
    }
    let chain = ProofChain::try_from_token_string(token, None, did_parser, &store).await?;
    if chain.ucan().audience() != config.audience {
        return Err(anyhow!("invalid audience"));
    }

    let mut facts = chain.ucan().facts().clone().unwrap_or(FactsMap::new());
    merge_facts(&chain, &mut facts);
    if let Some(required_facts) = &config.required_facts {
        for required_fact in required_facts.iter() {
            match facts.get(required_fact.0) {
                Some(fact) => {
                    if let Some(f) = fact.as_str() {
                        // marker for all doesn't allowed
                        if f == "*" {
                            return Err(anyhow!(r#"invalid fact "{}""#, required_fact.0));
                        }
                    }
                    if required_fact.1 == "*" {
                        // fact is present, any value allowed
                        continue;
                    }
                    if fact != required_fact.1 {
                        return Err(anyhow!(r#"invalid fact "{}""#, required_fact.0));
                    }
                }
                None => {
                    return Err(anyhow!(r#"no fact "{}""#, required_fact.0));
                }
            }
        }
    }
    facts.remove("prf");

    let semantics = GeneralSemantics {};
    let capabilities = chain.reduce_capabilities(&semantics);

    for required_capability in config.required_capabilities.iter() {
        let mut tt = TinyTemplate::new();
        tt.add_template("resource", &required_capability.resource)?;
        let resource = tt.render("resource", &facts)?;
        tt.add_template("ability", &required_capability.ability)?;
        let ability = tt.render("ability", &facts)?;

        let mut caveat = required_capability.caveat;
        if let Some(obj) = caveat.as_object_mut() {
            let obj_copy = obj.clone();

            for obj_item in obj_copy.iter() {
                if let Some(s) = obj_item.1.as_str() {
                    if s.contains('{') {
                        let mut tt = TinyTemplate::new();
                        tt.add_template("caveat", s)?;
                        let new_s = tt.render("caveat", &facts)?;
                        if new_s != s {
                            obj.insert(obj_item.0.to_owned(), serde_json::Value::String(new_s));
                        }
                    }
                }
            }
        }

        let cap = Capability::new(resource.clone(), ability, caveat);
        let view = semantics.parse_capability(&cap);
        if view.is_none() {
            return Err(anyhow!(
                r#"no capability "{} {}""#,
                required_capability.resource,
                required_capability.ability
            ));
        }
        let view = view.unwrap();
        let mut ok = false;
        for c in capabilities.iter() {
            // IMPORTANT! check the originator!
            if c.capability.enables(&view) && c.originators.contains(&config.root_issuer) {
                ok = true;
                break;
            }
        }
        if !ok {
            return Err(anyhow!(
                r#"no capability "{} {}""#,
                resource,
                required_capability.ability
            ));
        }
    }
    let c = Capabilities::try_from(
        capabilities
            .iter()
            .map(|c| Capability::from(c.capability.clone()))
            .collect::<Vec<Capability>>(),
    )?;

    let mut cids = Vec::new();
    merge_cids(&chain, &mut cids)?;

    Ok(VerifyResponse {
        capabilities: c,
        facts: if !facts.is_empty() { Some(facts) } else { None },
        cids,
    })
}

fn merge_facts(chain: &ProofChain, facts: &mut FactsMap) {
    if let Some(f) = chain.ucan().facts() {
        for item in f.iter() {
            if !facts.contains_key(item.0) {
                facts.insert(item.0.clone(), item.1.clone());
            }
        }
    }
    for c in chain.proofs() {
        merge_facts(c, facts);
    }
}

fn merge_cids(chain: &ProofChain, cids: &mut Vec<String>) -> Result<()> {
    let cid = chain.ucan().to_cid(Code::Blake3_256)?;
    if !cids.contains(&cid.to_string()) {
        cids.push(cid.to_string());
    }
    for c in chain.proofs() {
        merge_cids(c, cids)?;
    }
    Ok(())
}

pub fn decode_ucan(mut cx: FunctionContext) -> JsResult<JsValue> {
    let token: Handle<neon::types::JsValue> = cx.argument(0)?;
    let token: Handle<JsString> = token.downcast_or_throw(&mut cx)?;
    let token: String = token.value(&mut cx);
    let ucan = Ucan::try_from(token).or_else(|e| cx.throw_error(e.to_string()))?;
    let result =
        neon_serde2::to_value(&mut cx, &ucan).or_else(|e| cx.throw_error(e.to_string()))?;
    let obj: Handle<JsObject> = result.downcast_or_throw(&mut cx)?;
    let cid = ucan
        .to_cid(Code::Blake3_256)
        .or_else(|e| cx.throw_error(e.to_string()))?;
    let cid = cx.string(cid.to_string());
    obj.set(&mut cx, "cid", cid)?;

    Ok(result)
}
