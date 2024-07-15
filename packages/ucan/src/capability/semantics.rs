use super::{proof::ProofSelection, Capability, Caveat};
use serde_json::{json, Value};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;
use url::Url;

pub trait Scope: ToString + TryFrom<Url> + PartialEq + Clone {
    fn contains(&self, other: &Self) -> bool;
}

pub trait Ability: Ord + TryFrom<String> + ToString + Clone {}

#[derive(Clone, Eq, PartialEq)]
pub enum Resource<S>
where
    S: Scope,
{
    ResourceUri(S),
    Ucan(ProofSelection),
}

impl<S> Resource<S>
where
    S: Scope,
{
    pub fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Resource::ResourceUri(resource), Resource::ResourceUri(other_resource)) => {
                resource.contains(other_resource)
            }
            (Resource::Ucan(resource), Resource::Ucan(other_resource)) => {
                resource.contains(other_resource)
            }
            (Resource::Ucan(resource), Resource::ResourceUri(_other_resource)) => {
                // TODO is it called at all?
                matches!(resource, ProofSelection::All | ProofSelection::TheseProofs)
            }
            _ => false,
        }
    }
}

impl<S> Display for Resource<S>
where
    S: Scope,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let resource_content = match self {
            Resource::Ucan(kind) => kind.to_string(),
            Resource::ResourceUri(kind) => kind.to_string(),
        };

        write!(f, "{resource_content}")
    }
}

pub trait CapabilitySemantics<S, A>
where
    S: Scope,
    A: Ability,
{
    fn parse_scope(&self, scope: &Url) -> Option<S> {
        S::try_from(scope.clone()).ok()
    }
    fn parse_action(&self, ability: &str) -> Option<A> {
        A::try_from(String::from(ability)).ok()
    }

    fn parse_caveat(&self, caveat: Option<&Value>) -> Value {
        if let Some(caveat) = caveat {
            caveat.to_owned()
        } else {
            json!({})
        }
    }

    /// Parse a resource and abilities string and a caveats object.
    /// The default "no caveats" (`[{}]`) is implied if `None` caveats given.
    fn parse(
        &self,
        resource: &str,
        ability: &str,
        caveat: Option<&Value>,
    ) -> Option<CapabilityView<S, A>> {
        // "ucan://did..." cannot be parsed by "url" crate
        let cap_resource = if resource.starts_with("ucan:") {
            Resource::Ucan(ProofSelection::try_from(resource.to_owned()).ok()?)
        } else {
            let uri = Url::parse(resource).ok()?;
            Resource::ResourceUri(self.parse_scope(&uri)?)
        };

        let cap_ability = match self.parse_action(ability) {
            Some(ability) => ability,
            None => return None,
        };

        let cap_caveat = self.parse_caveat(caveat);

        Some(CapabilityView::new_with_caveat(
            cap_resource,
            cap_ability,
            cap_caveat,
        ))
    }

    fn parse_capability(&self, value: &Capability) -> Option<CapabilityView<S, A>> {
        self.parse(&value.resource, &value.ability, Some(&value.caveat))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityView<S, A>
where
    S: Scope,
    A: Ability,
{
    pub resource: Resource<S>,
    pub ability: A,
    pub caveat: Value,
}

impl<S, A> Debug for CapabilityView<S, A>
where
    S: Scope,
    A: Ability,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capability")
            .field("resource", &self.resource.to_string())
            .field("ability", &self.ability.to_string())
            .field("caveats", &serde_json::to_string(&self.caveat))
            .finish()
    }
}

impl<S, A> CapabilityView<S, A>
where
    S: Scope,
    A: Ability,
{
    /// Creates a new [CapabilityView] semantics view over a capability
    /// without caveats.
    pub fn new(resource: Resource<S>, ability: A) -> Self {
        CapabilityView {
            resource,
            ability,
            caveat: json!({}),
        }
    }

    /// Creates a new [CapabilityView] semantics view over a capability
    /// with caveats. Note that an empty caveats array will imply NO
    /// capabilities, rendering this capability meaningless.
    pub fn new_with_caveat(resource: Resource<S>, ability: A, caveat: Value) -> Self {
        CapabilityView {
            resource,
            ability,
            caveat,
        }
    }

    pub fn enables(&self, other: &CapabilityView<S, A>) -> bool {
        match (
            Caveat::try_from(self.caveat()),
            Caveat::try_from(other.caveat()),
        ) {
            (Ok(self_caveat), Ok(other_caveat)) => {
                self.resource.contains(&other.resource)
                    && self.ability >= other.ability
                    && self_caveat.enables(&other_caveat)
            }
            _ => false,
        }
    }

    pub fn resource(&self) -> &Resource<S> {
        &self.resource
    }

    pub fn ability(&self) -> &A {
        &self.ability
    }

    pub fn caveat(&self) -> &Value {
        &self.caveat
    }
}

impl<S, A> From<&CapabilityView<S, A>> for Capability
where
    S: Scope,
    A: Ability,
{
    fn from(value: &CapabilityView<S, A>) -> Self {
        Capability::new(
            value.resource.to_string(),
            value.ability.to_string(),
            value.caveat.to_owned(),
        )
    }
}

impl<S, A> From<CapabilityView<S, A>> for Capability
where
    S: Scope,
    A: Ability,
{
    fn from(value: CapabilityView<S, A>) -> Self {
        Capability::new(
            value.resource.to_string(),
            value.ability.to_string(),
            value.caveat,
        )
    }
}
