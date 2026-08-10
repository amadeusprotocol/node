use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{kv_get, kv_put};
use crate::consensus;
use std::panic::panic_any;
use vecpak::{decode, encode, Term};

pub struct PermissionUpdate {
    pub identifier: Vec<u8>,
    additions: Vec<Term>,
    removals: Vec<Term>,
}

pub fn has(env: &mut ApplyEnv, permission_key: &[u8], signer: &[u8]) -> bool {
    match kv_get(env, permission_key) {
        None => false,
        Some(encoded) => match decode(&encoded) {
            Ok(Term::List(permissions)) => permissions.iter().any(|permission| matches!(permission, Term::Binary(pk) if pk == signer)),
            _ => false,
        },
    }
}

pub fn initialize(env: &mut ApplyEnv, permission_key: &[u8], admin: &[u8]) {
    let encoded = encode(Term::List(vec![Term::Binary(admin.to_vec())]));
    kv_put(env, permission_key, &encoded);
}

fn validate_list(items: Vec<Term>, error: &'static str) -> Vec<Vec<u8>> {
    let mut permissions = Vec::with_capacity(items.len());
    for item in items {
        let Term::Binary(permission) = item else { panic_any(error) };
        if permission.len() != 48 || !consensus::bls12_381::validate_public_key(&permission) {
            panic_any("invalid_permission_pk")
        }
        if !permissions.contains(&permission) {
            permissions.push(permission);
        }
    }
    permissions
}

fn decode_list(encoded: &[u8], error: &'static str) -> Vec<Vec<u8>> {
    let Term::List(items) = decode(encoded).unwrap_or_else(|_| panic_any(error)) else { panic_any(error) };
    validate_list(items, error)
}

//Decode the common one-map permission API. Asset modules supply the name of
//their identifier field (for example "symbol" or "collection").
pub fn decode_update(args: Vec<Vec<u8>>, identifier_key: &[u8], invalid_identifier_error: &'static str) -> PermissionUpdate {
    if args.len() != 1 {
        panic_any("invalid_args")
    }
    let Term::PropList(pairs) = decode(&args[0]).unwrap_or_else(|_| panic_any("invalid_args")) else { panic_any("invalid_args") };
    let mut additions = None;
    let mut removals = None;
    let mut identifier = None;
    for (key, value) in pairs {
        let Term::Binary(key) = key else { panic_any("invalid_args") };
        if key == b"add" {
            if additions.replace(value).is_some() {
                panic_any("invalid_args")
            }
        } else if key == b"remove" {
            if removals.replace(value).is_some() {
                panic_any("invalid_args")
            }
        } else if key == identifier_key {
            if identifier.replace(value).is_some() {
                panic_any("invalid_args")
            }
        } else {
            panic_any("unknown_arg")
        }
    }

    let Term::List(additions) = additions.unwrap_or_else(|| panic_any("invalid_args")) else { panic_any("invalid_add_permissions") };
    let Term::List(removals) = removals.unwrap_or_else(|| panic_any("invalid_args")) else { panic_any("invalid_remove_permissions") };
    let Term::Binary(identifier) = identifier.unwrap_or_else(|| panic_any("invalid_args")) else { panic_any(invalid_identifier_error) };
    PermissionUpdate { identifier, additions, removals }
}

//Apply an atomic add/remove update after the asset module has validated that
//the referenced asset exists. The current admin list is the authority source.
pub fn apply_update(env: &mut ApplyEnv, permission_key: &[u8], caller: &[u8], update: PermissionUpdate) {
    let encoded = kv_get(env, permission_key).unwrap_or_else(|| panic_any("permissions_missing"));
    let mut permissions = decode_list(&encoded, "invalid_permissions");
    if !permissions.iter().any(|permission| permission == caller) {
        panic_any("no_permissions")
    }

    let additions = validate_list(update.additions, "invalid_add_permissions");
    let removals = validate_list(update.removals, "invalid_remove_permissions");
    if additions.iter().any(|permission| removals.contains(permission)) {
        panic_any("permission_update_overlap")
    }

    for permission in additions {
        if !permissions.contains(&permission) {
            permissions.push(permission);
        }
    }
    permissions.retain(|permission| !removals.contains(permission));
    if permissions.is_empty() {
        panic_any("permissions_cannot_be_empty")
    }

    let encoded = encode(Term::List(permissions.into_iter().map(Term::Binary).collect()));
    kv_put(env, permission_key, &encoded);
}
