/**
 * This semantics realizes a general comparizon of capabilities.
 *
 * 1. Resource: "<scheme>:<path>"
 *    
 *    The resource is an URL-like path to resource (it can be a real URL).
 *    "scheme" is any application specific scheme, like "api", "docs".
 *    "path" is an URL-like path, like "user/1", "user/1/post/2". The path
 *    includes access to all its sub-paths, for example "user/1" includes any of
 *    "user/1/post/1", "user/1/post/2", etc. Verification is performed by first
 *    by comparing schemes, then comparing each part of paths between "/"
 *    sequentally.
 *    The special path "*" means all in a capability, and "some" in the
 *    requirement resource, for example the requirement "user/ *" allows
 *    "user/1", compared to the requirement "user" which doesn't allow it
 *    (as in this context "user" means all users, but "user/ *" means some user,
 *    but not all users).
 *
 *    Examples:
 *
 *    | Capability resource | Required resource | Includes                     |
 *    |---------------------|-------------------|------------------------------|
 *    | user                | user/1            | Yes                          |
 *    | user/1              | user              | No (required is higher)      |
 *    | user/1              | user/1            | Yes (are equal)              |
 *    | user/1              | user/1/doc/1      | Yes (required is included)   |
 *    | user/1              | user/2            | No (are not equal)           |
 *    | user/1              | doc/1             | No (are not equal)           |
 *    | *                   | user/1            | Yes (requred is included)    |
 *    | user/1              | *                 | No (reqired is higher level) |
 *    | user/1              | user/ *           | Yes                          |
 *    | user/ *             | user/1            | Yes                          |
 *    | user/1/post/1       | user/ * /post/2   | No                           |
 *
 * 2. Ability: "<namespace>/ability[/sub-ability]"
 *
 *    The ability is an action allowed for the resource.
 *    Its format is "namespace/ability[/sub-ability]". The special ability "*"
 *    always means "all" (in difference to its meaning for resource). It
 *    can be used at the end to include all sub-actions ("user/post/ *"), but
 *    not in the middle.
 *
 *    Examples:
 *
 *    | Capability ability  | Required ability  | Enables |
 *    |---------------------|-------------------|---------|
 *    | user/post           | user/post         | Yes     |
 *    | user/post           | user/post/draft   | Yes     |
 *    | user/post/draft     | user/post         | No      |
 *    | *                   | user/post         | Yes     |
 *    | user/post           | *                 | No      |
 *    | user/ *             | user/post         | Yes     |
 *    | user/post           | user/ *           | No      |
 *
 * 3. Caveats: "[{<key>: <value>}[, {}, ...]]"
 *
 * To be described...
 */
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use ucan::capability::{Ability, CapabilitySemantics, Scope};
use url::Url;

#[derive(Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct GeneralAbility {
    ability: String,
}

impl Ability for GeneralAbility {}

impl TryFrom<String> for GeneralAbility {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Ok(GeneralAbility { ability: value })
    }
}

impl Display for GeneralAbility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let content = &self.ability;
        write!(f, "{content}")
    }
}

impl PartialOrd for GeneralAbility {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GeneralAbility {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.ability == other.ability {
            return std::cmp::Ordering::Equal;
        }
        if self.ability == "*" {
            return std::cmp::Ordering::Greater;
        } else if other.ability == "*" {
            return std::cmp::Ordering::Less;
        }

        let self_path_parts = self.ability.split('/');
        let mut other_path_parts = other.ability.split('/');
        let mut result = std::cmp::Ordering::Equal;

        for part in self_path_parts {
            match other_path_parts.nth(0) {
                Some(other_part) => {
                    if part == "*" && other_part == "*" {
                        result = std::cmp::Ordering::Equal;
                    } else if part == "*" {
                        result = std::cmp::Ordering::Greater;
                    } else if other_part == "*" {
                        result = std::cmp::Ordering::Less;
                    } else if part != other_part {
                        return std::cmp::Ordering::Less;
                    }
                }
                None => return std::cmp::Ordering::Less,
            }
        }

        if other_path_parts.next().is_some() {
            std::cmp::Ordering::Greater
        } else {
            result
        }
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct GeneralResource {
    scheme: String,
    path: String,
}

impl Scope for GeneralResource {
    fn contains(&self, other: &Self) -> bool {
        if self.scheme != other.scheme {
            return false;
        }
        if self.path == "*" {
            return true;
        }
        if other.path == "*" {
            return false;
        }

        let self_path_parts = self.path.split('/');
        let mut other_path_parts = other.path.split('/');

        for part in self_path_parts {
            match other_path_parts.nth(0) {
                Some(other_part) => {
                    if part != "*" && other_part != "*" && part != other_part {
                        return false;
                    }
                }
                None => {
                    return false;
                }
            }
        }

        // all sub-resources allowed
        true
    }
}

impl TryFrom<Url> for GeneralResource {
    type Error = anyhow::Error;

    fn try_from(value: Url) -> Result<Self, Self::Error> {
        let p = value.path();
        let mut p1 = value.host_str().unwrap_or("").to_owned();
        if !p.is_empty() {
            if p1.is_empty() {
                p.clone_into(&mut p1);
            } else {
                p1 += &("/".to_owned() + p);
            }
        }
        Ok(GeneralResource {
            scheme: String::from(value.scheme()),
            path: p1,
        })
    }
}

impl TryFrom<String> for GeneralResource {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let u = Url::parse(&value)?;
        Self::try_from(u)
    }
}

impl Display for GeneralResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let content = format!("{}:{}", self.scheme, self.path);
        write!(f, "{content}")
    }
}

pub struct GeneralSemantics {}

impl CapabilitySemantics<GeneralResource, GeneralAbility> for GeneralSemantics {}
