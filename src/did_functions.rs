use anyhow::anyhow;
use anyhow::Result;
use base64::Engine;
use did_key::{
    from_existing_key, generate, Bls12381KeyPairs, Config, CoreSign, DIDCore, Ed25519KeyPair,
    KeyFormat, P256KeyPair, PatchedKeyPair, Secp256k1KeyPair, VerificationMethod, X25519KeyPair,
};
use neon::prelude::*;

pub fn create_did(mut cx: FunctionContext) -> JsResult<JsValue> {
    let use_jose_format = cx.argument_opt(0);
    let use_jose_format = match use_jose_format {
        Some(use_jose_format) => {
            let use_jose_format: Handle<JsBoolean> = use_jose_format.downcast_or_throw(&mut cx)?;
            use_jose_format.value(&mut cx)
        }
        None => false,
    };
    let key_type = cx.argument_opt(1);
    let key_type = match key_type {
        Some(key_type) => {
            let key_type: Handle<JsString> = key_type.downcast_or_throw(&mut cx)?;
            key_type.value(&mut cx)
        }
        None => "Ed25519".to_owned(),
    };

    let key = match key_type.as_str() {
        "Ed25519" | "Ed25519VerificationKey2018" | "JsonWebKey2020" => {
            generate::<Ed25519KeyPair>(None)
        }
        "X25519" | "X25519KeyAgreementKey2019" => generate::<X25519KeyPair>(None),
        "P256" | "UnsupportedVerificationMethod2020" | "P-256" => generate::<P256KeyPair>(None),
        "Bls12381" | "Bls12381G2Key2020" | "BLS12381_G2" => generate::<Bls12381KeyPairs>(None),
        "Secp256k1" | "EcdsaSecp256k1VerificationKey2019" | "secp256k1" => {
            generate::<Secp256k1KeyPair>(None)
        }
        _ => {
            return cx.throw_error(format!(r#"unsupported key type: "{}""#, key_type));
        }
    };
    let did_doc = key.get_did_document(Config {
        use_jose_format,         // toggle to switch between LD and JOSE key format
        serialize_secrets: true, // toggle to serialize private keys
    });
    match neon_serde2::to_value(&mut cx, &did_doc) {
        Ok(result) => Ok(result),
        Err(e) => cx.throw_error(e.to_string()),
    }
}

pub fn resolve_did(mut cx: FunctionContext) -> JsResult<JsValue> {
    let did: Handle<JsValue> = cx.argument(0)?;
    let did: Handle<JsString> = did.downcast_or_throw(&mut cx)?;
    let did = did.value(&mut cx);
    let key = did_key::resolve(&did).or_else(|e| cx.throw_error(format!("{:#?}", e)))?;
    let use_jose_format = cx.argument_opt(1);
    let use_jose_format = match use_jose_format {
        Some(use_jose_format) => {
            let use_jose_format: Handle<JsBoolean> = use_jose_format.downcast_or_throw(&mut cx)?;
            use_jose_format.value(&mut cx)
        }
        None => false,
    };

    let did_doc = key.get_did_document(Config {
        use_jose_format,         // toggle to switch between LD and JOSE key format
        serialize_secrets: true, // toggle to serialize private keys
    });
    match neon_serde2::to_value(&mut cx, &did_doc) {
        Ok(result) => Ok(result),
        Err(e) => cx.throw_error(e.to_string()),
    }
}

pub fn restore_did(mut cx: FunctionContext) -> JsResult<JsValue> {
    let verification_method: Handle<JsValue> = cx.argument(0)?;
    let verification_method: VerificationMethod =
        neon_serde2::from_value(&mut cx, verification_method)
            .or_else(|e| cx.throw_error(e.to_string()))?;
    let use_jose_format = cx.argument_opt(1);
    let use_jose_format = match use_jose_format {
        Some(use_jose_format) => {
            let use_jose_format: Handle<JsBoolean> = use_jose_format.downcast_or_throw(&mut cx)?;
            use_jose_format.value(&mut cx)
        }
        None => false,
    };

    let key = get_keypair_from_keys(
        &verification_method.key_type,
        &verification_method.public_key,
        &verification_method.private_key,
    )
    .or_else(|e| cx.throw_error(e.to_string()))?;

    let did_doc = key.get_did_document(Config {
        use_jose_format,         // toggle to switch between LD and JOSE key format
        serialize_secrets: true, // toggle to serialize private keys
    });
    match neon_serde2::to_value(&mut cx, &did_doc) {
        Ok(result) => Ok(result),
        Err(e) => cx.throw_error(e.to_string()),
    }
}

fn get_keypair_from_keys(
    key_type: &str,
    public_key: &Option<KeyFormat>,
    private_key: &Option<KeyFormat>,
) -> Result<PatchedKeyPair> {
    let keys = get_keys(public_key, private_key)?;
    let mut key_type = key_type.to_owned();
    if key_type == "JsonWebKey2020" {
        if let Some(KeyFormat::JWK(k)) = private_key {
            key_type.clone_from(&k.curve);
        } else {
            return Err(anyhow!("invalid private key"));
        }
    }

    let key = match key_type.as_str() {
        "Ed25519" | "Ed25519VerificationKey2018" => {
            from_existing_key::<Ed25519KeyPair>(&keys.0, Some(&keys.1))
        }
        "X25519" | "X25519KeyAgreementKey2019" => {
            from_existing_key::<X25519KeyPair>(&keys.0, Some(&keys.1))
        }
        "P256" | "UnsupportedVerificationMethod2020" | "P-256" => {
            from_existing_key::<P256KeyPair>(&keys.0, Some(&keys.1))
        }
        "Bls12381" | "Bls12381G2Key2020" | "BLS12381_G2" => {
            from_existing_key::<Bls12381KeyPairs>(&keys.0, Some(&keys.1))
        }
        "Secp256k1" | "EcdsaSecp256k1VerificationKey2019" | "secp256k1" => {
            from_existing_key::<Secp256k1KeyPair>(&keys.0, Some(&keys.1))
        }
        _ => {
            return Err(anyhow!(r#"unsupported key type: "{}""#, key_type));
        }
    };

    Ok(key)
}

pub fn get_keys(
    public_key: &Option<KeyFormat>,
    private_key: &Option<KeyFormat>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let public_key = match public_key {
        Some(public_key) => public_key,
        None => {
            return Err(anyhow!("Invalid public key"));
        }
    };
    let private_key = match private_key {
        Some(private_key) => private_key,
        None => {
            return Err(anyhow!("Invalid private key"));
        }
    };
    let pub_vec = match public_key {
        KeyFormat::Base58(k) => bs58::decode(k).into_vec()?,
        KeyFormat::Multibase(_k) => {
            return Err(anyhow!("multibase is not supported"));
        }
        KeyFormat::JWK(k) => match &k.x {
            Some(k) => base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(k)?,
            None => {
                return Err(anyhow!("Invalid public key"));
            }
        },
    };
    let priv_vec = match private_key {
        KeyFormat::Base58(k) => bs58::decode(k).into_vec()?,
        KeyFormat::Multibase(_k) => {
            return Err(anyhow!("multibase is not supported"));
        }
        KeyFormat::JWK(k) => match &k.x {
            Some(k) => base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(k)?,
            None => {
                return Err(anyhow!("Invalid private key"));
            }
        },
    };
    Ok((pub_vec, priv_vec))
}

pub fn simple_sign(mut cx: FunctionContext) -> JsResult<JsString> {
    let verification_method: Handle<JsValue> = cx.argument(0)?;
    let verification_method: VerificationMethod =
        neon_serde2::from_value(&mut cx, verification_method)
            .or_else(|e| cx.throw_error(e.to_string()))?;
    let message: Handle<JsValue> = cx.argument(1)?;
    let message: Handle<JsString> = message.downcast_or_throw(&mut cx)?;
    let message = message.value(&mut cx);

    let key = get_keypair_from_keys(
        &verification_method.key_type,
        &verification_method.public_key,
        &verification_method.private_key,
    )
    .or_else(|e| cx.throw_error(e.to_string()))?;

    let signature = key.sign(message.as_bytes());
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);
    Ok(cx.string(signature))
}

pub fn simple_verify(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let did: Handle<neon::types::JsValue> = cx.argument(0)?;
    let did: Handle<JsString> = did.downcast_or_throw(&mut cx)?;
    let did = did.value(&mut cx);
    let message: Handle<JsValue> = cx.argument(1)?;
    let message: Handle<JsString> = message.downcast_or_throw(&mut cx)?;
    let message = message.value(&mut cx);
    let signature: Handle<JsValue> = cx.argument(2)?;
    let signature: Handle<JsString> = signature.downcast_or_throw(&mut cx)?;
    let signature = signature.value(&mut cx);
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature)
        .or_else(|e| cx.throw_error(format!("{:#?}", e)))?;

    let key = did_key::resolve(&did).or_else(|e| cx.throw_error(format!("{:#?}", e)))?;
    if let Err(e) = key.verify(message.as_bytes(), &signature) {
        return cx.throw_error(format!("{:#?}", e));
    }
    Ok(cx.boolean(true))
}
