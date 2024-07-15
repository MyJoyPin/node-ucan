use super::{Ability, CapabilitySemantics, Scope};
use anyhow::{anyhow, Result};
use cid::Cid;
use std::fmt::Display;
use url::Url;

#[derive(Ord, Eq, PartialEq, PartialOrd, Clone)]
pub enum ProofAction {
    Delegate,
}

impl Ability for ProofAction {}

impl TryFrom<String> for ProofAction {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        match value.as_str() {
            "ucan/*" => Ok(ProofAction::Delegate),
            unsupported => Err(anyhow!(
                "Unsupported action for proof resource ({})",
                unsupported
            )),
        }
    }
}

impl Display for ProofAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let action_content = match self {
            ProofAction::Delegate => "ucan/*",
        };

        write!(f, "{action_content}")
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum ProofSelection {
    Cid(Cid),
    TheseProofs,
    Did(String),
    DidScheme(String, String),
    All,
}

impl Scope for ProofSelection {
    fn contains(&self, other: &Self) -> bool {
        self == other
            || *self == ProofSelection::All
            || (*self == ProofSelection::TheseProofs && *other != ProofSelection::All)
    }
}

impl TryFrom<Url> for ProofSelection {
    type Error = anyhow::Error;

    fn try_from(value: Url) -> Result<Self, Self::Error> {
        match value.scheme() {
            "ucan" => value.to_string().try_into(),
            _ => Err(anyhow!("Unrecognized URI scheme")),
        }
    }
}

impl TryFrom<String> for ProofSelection {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        match value.as_str() {
            "ucan:*" => Ok(ProofSelection::All),
            "ucan:./*" => Ok(ProofSelection::TheseProofs),
            selection => {
                if let Some(s) = selection.strip_prefix("ucan://") {
                    let s: Vec<&str> = s.split('/').collect();
                    if s.len() != 2 {
                        return Err(anyhow!("Invalid delegation URI"));
                    }
                    if s[1] == "*" {
                        Ok(ProofSelection::Did(s[0].to_owned()))
                    } else {
                        Ok(ProofSelection::DidScheme(s[0].to_owned(), s[1].to_owned()))
                    }
                } else if let Some(s) = selection.strip_prefix("ucan:") {
                    Ok(ProofSelection::Cid(Cid::try_from(s.to_string())?))
                } else {
                    Err(anyhow!("Unrecognized delegation URI"))
                }
            }
        }
    }
}

impl Display for ProofSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proof_content = match self {
            ProofSelection::Cid(cid) => format!("ucan:{cid}"),
            ProofSelection::Did(did) => "ucan://".to_string() + did + "/*",
            ProofSelection::DidScheme(did, scheme) => "ucan://".to_string() + did + "/" + scheme,
            ProofSelection::TheseProofs => "ucan:./*".to_string(),
            ProofSelection::All => "ucan:*".to_string(),
        };

        write!(f, "{proof_content}")
    }
}

pub struct ProofDelegationSemantics {}

impl CapabilitySemantics<ProofSelection, ProofAction> for ProofDelegationSemantics {}
