#![cfg(test)]

use crate::bcat;
use crate::consensus::bic::protocol::AMA_1_DOLLAR;
use crate::consensus::tests::chain_harness::{Chain, Wallet};
use vecpak::{decode, encode, Term};

fn nft_key(address: &[u8], collection: &[u8], token: &[u8]) -> Vec<u8> {
    bcat(&[b"account:", address, b":nft:", collection, b":", token])
}

fn binary_map(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
    encode(Term::PropList(
        pairs.iter().map(|(key, value)| (Term::Binary(key.to_vec()), Term::Binary(value.to_vec()))).collect(),
    ))
}

fn create_collection_with_type(chain: &Chain, admin: &Wallet, collection: &[u8], soulbound: &[u8], nonfungible: &[u8]) -> Result<(), String> {
    let args = binary_map(&[(b"collection", collection), (b"soulbound", soulbound), (b"nonfungible", nonfungible)]);
    chain.call(admin, b"Nft", b"create_collection", &[&args])
}

fn create_collection(chain: &Chain, admin: &Wallet, collection: &[u8], soulbound: &[u8]) -> Result<(), String> {
    create_collection_with_type(chain, admin, collection, soulbound, b"false")
}

fn mint(chain: &Chain, admin: &Wallet, receiver: &[u8], amount: &[u8], collection: &[u8], token: &[u8], soulbound: &[u8]) -> Result<(), String> {
    let args = binary_map(&[
        (b"receiver", receiver),
        (b"amount", amount),
        (b"collection", collection),
        (b"token", token),
        (b"soulbound", soulbound),
    ]);
    chain.call(admin, b"Nft", b"mint", &[&args])
}

fn permission_update(add: &[&[u8]], remove: &[&[u8]], collection: &[u8]) -> Vec<u8> {
    let addresses = |items: &[&[u8]]| Term::List(items.iter().map(|item| Term::Binary(item.to_vec())).collect());
    encode(Term::PropList(vec![
        (Term::Binary(b"add".to_vec()), addresses(add)),
        (Term::Binary(b"remove".to_vec()), addresses(remove)),
        (Term::Binary(b"collection".to_vec()), Term::Binary(collection.to_vec())),
    ]))
}

fn permissions(chain: &Chain, collection: &[u8]) -> Vec<Vec<u8>> {
    let encoded = chain.get(&bcat(&[b"nft:", collection, b":permission"])).expect("permission list missing");
    let Term::List(items) = decode(&encoded).expect("invalid permission list") else { panic!("permission list is not a list") };
    items
        .into_iter()
        .map(|item| match item {
            Term::Binary(permission) => permission,
            _ => panic!("permission entry is not a binary"),
        })
        .collect()
}

#[test]
fn full_transfer_deletes_sender_key() {
    let chain = Chain::new();
    let admin = chain.wallet(AMA_1_DOLLAR);
    let holder = chain.wallet(0);
    let receiver = chain.wallet(0);

    create_collection(&chain, &admin, b"CARDS", b"false").unwrap();
    mint(&chain, &admin, &holder.pk, b"5", b"CARDS", b"RARE", b"false").unwrap();
    chain.call(&holder, b"Nft", b"transfer", &[&receiver.pk, b"5", b"CARDS", b"RARE"]).unwrap();

    assert_eq!(chain.get(&nft_key(&holder.pk, b"CARDS", b"RARE")), None);
    assert_eq!(chain.get(&nft_key(&receiver.pk, b"CARDS", b"RARE")), Some(b"5".to_vec()));
}

#[test]
fn partial_and_self_transfers_keep_the_correct_balance() {
    let chain = Chain::new();
    let admin = chain.wallet(AMA_1_DOLLAR);
    let holder = chain.wallet(0);
    let receiver = chain.wallet(0);

    create_collection(&chain, &admin, b"ITEMS", b"false").unwrap();
    mint(&chain, &admin, &holder.pk, b"7", b"ITEMS", b"POTION", b"false").unwrap();
    chain.call(&holder, b"Nft", b"transfer", &[&receiver.pk, b"2", b"ITEMS", b"POTION"]).unwrap();
    chain.call(&holder, b"Nft", b"transfer", &[&holder.pk, b"5", b"ITEMS", b"POTION"]).unwrap();

    assert_eq!(chain.get(&nft_key(&holder.pk, b"ITEMS", b"POTION")), Some(b"5".to_vec()));
    assert_eq!(chain.get(&nft_key(&receiver.pk, b"ITEMS", b"POTION")), Some(b"2".to_vec()));
}

#[test]
fn collection_creation_requires_exact_args_and_boolean() {
    let chain = Chain::new();
    let admin = chain.wallet(AMA_1_DOLLAR);

    assert_eq!(chain.call(&admin, b"Nft", b"create_collection", &[b"not vecpak"]), Err("invalid_args".to_string()));
    let missing = binary_map(&[(b"collection", b"ONE")]);
    assert_eq!(chain.call(&admin, b"Nft", b"create_collection", &[&missing]), Err("invalid_args".to_string()));
    let extra = binary_map(&[(b"collection", b"THREE"), (b"soulbound", b"false"), (b"nonfungible", b"false"), (b"ignored", b"value")]);
    assert_eq!(
        chain.call(&admin, b"Nft", b"create_collection", &[&extra]),
        Err("unknown_arg".to_string())
    );
    for invalid in [b"".as_slice(), b"True".as_slice(), b"yes".as_slice(), b"0".as_slice()] {
        assert_eq!(create_collection(&chain, &admin, b"INVALID", invalid), Err("invalid_soulbound".to_string()));
        assert_eq!(
            create_collection_with_type(&chain, &admin, b"INVALID", b"false", invalid),
            Err("invalid_nonfungible".to_string())
        );
    }

    create_collection(&chain, &admin, b"BOUND", b"true").unwrap();
    create_collection(&chain, &admin, b"FREE", b"false").unwrap();
    create_collection_with_type(&chain, &admin, b"UNIQUE", b"false", b"true").unwrap();
    assert_eq!(chain.get(b"nft:BOUND:soulbound"), Some(b"true".to_vec()));
    assert_eq!(chain.get(b"nft:FREE:soulbound"), None);
    assert_eq!(chain.get(b"nft:UNIQUE:nonfungible"), Some(b"true".to_vec()));
}

#[test]
fn collection_ids_are_case_sensitive_ascii_alphanumeric_and_respect_coin_symbols() {
    let chain = Chain::new();
    let admin = chain.wallet(AMA_1_DOLLAR);

    //Collection IDs preserve case but must not use a case-insensitive reserved
    //coin symbol or the exact symbol of an existing custom coin.
    create_collection(&chain, &admin, b"Cards123", b"false").unwrap();
    chain.call(&admin, b"Coin", b"create_and_mint", &[b"CUSTOM1", b"1"]).unwrap();

    for reserved in [b"wUSDT".as_slice(), b"WUSDT".as_slice(), b"PRIME".as_slice(), b"AmA".as_slice()] {
        assert_eq!(
            create_collection(&chain, &admin, reserved, b"false"),
            Err("collection_reserved".to_string())
        );
    }
    assert_eq!(
        create_collection(&chain, &admin, b"CUSTOM1", b"false"),
        Err("collection_conflicts_with_coin".to_string())
    );

    create_collection(&chain, &admin, b"NFTFIRST", b"false").unwrap();
    assert_eq!(
        chain.call(&admin, b"Coin", b"create_and_mint", &[b"NFTFIRST", b"1"]),
        Err("symbol_conflicts_with_collection".to_string())
    );

    for invalid in [b"BAD-ID".as_slice(), b"BAD_ID".as_slice(), b"BAD ID".as_slice(), "café".as_bytes()] {
        assert_eq!(
            create_collection(&chain, &admin, invalid, b"false"),
            Err("invalid_collection".to_string())
        );
    }
    assert_eq!(
        create_collection(&chain, &admin, b"", b"false"),
        Err("collection_too_short".to_string())
    );
    assert_eq!(
        create_collection(&chain, &admin, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567", b"false"),
        Err("collection_too_long".to_string())
    );
}

#[test]
fn mint_and_burn_track_per_token_total_supply() {
    let chain = Chain::new();
    let admin = chain.wallet(AMA_1_DOLLAR);
    let holder = chain.wallet(0);
    let receiver = chain.wallet(0);
    let burn = crate::consensus::bic::coin::BURN_ADDRESS;

    create_collection(&chain, &admin, b"SUPPLY", b"false").unwrap();
    mint(&chain, &admin, &holder.pk, b"7", b"SUPPLY", b"COMMON", b"false").unwrap();
    mint(&chain, &admin, &receiver.pk, b"3", b"SUPPLY", b"COMMON", b"false").unwrap();
    mint(&chain, &admin, &holder.pk, b"2", b"SUPPLY", b"RARE", b"false").unwrap();

    assert_eq!(chain.get(b"nft:SUPPLY:COMMON:totalSupply"), Some(b"10".to_vec()));
    assert_eq!(chain.get(b"nft:SUPPLY:RARE:totalSupply"), Some(b"2".to_vec()));

    //Ordinary transfers do not change supply; burning does.
    chain.call(&holder, b"Nft", b"transfer", &[&receiver.pk, b"2", b"SUPPLY", b"COMMON"]).unwrap();
    assert_eq!(chain.get(b"nft:SUPPLY:COMMON:totalSupply"), Some(b"10".to_vec()));
    chain.call(&receiver, b"Nft", b"transfer", &[&burn, b"4", b"SUPPLY", b"COMMON"]).unwrap();
    assert_eq!(chain.get(b"nft:SUPPLY:COMMON:totalSupply"), Some(b"6".to_vec()));
    assert_eq!(chain.get(&nft_key(&burn, b"SUPPLY", b"COMMON")), Some(b"4".to_vec()));
}

#[test]
fn collection_permissions_rotate_atomically_and_control_minting() {
    let chain = Chain::new();
    let original_admin = chain.wallet(AMA_1_DOLLAR);
    let new_admin = chain.wallet(0);
    let outsider = chain.wallet(0);
    let receiver = chain.wallet(0);
    create_collection(&chain, &original_admin, b"ROTATE", b"false").unwrap();

    assert_eq!(permissions(&chain, b"ROTATE"), vec![original_admin.pk.to_vec()]);
    let missing = permission_update(&[], &[], b"MISSING");
    assert_eq!(
        chain.call(&original_admin, b"Nft", b"update_permission", &[&missing]),
        Err("collection_doesnt_exist".to_string())
    );
    let overlap = permission_update(&[&new_admin.pk], &[&new_admin.pk], b"ROTATE");
    assert_eq!(
        chain.call(&original_admin, b"Nft", b"update_permission", &[&overlap]),
        Err("permission_update_overlap".to_string())
    );
    let invalid_admin = [1u8; 48];
    let invalid = permission_update(&[&invalid_admin], &[], b"ROTATE");
    assert_eq!(
        chain.call(&original_admin, b"Nft", b"update_permission", &[&invalid]),
        Err("invalid_permission_pk".to_string())
    );
    assert_eq!(permissions(&chain, b"ROTATE"), vec![original_admin.pk.to_vec()]);

    let update = permission_update(&[&new_admin.pk], &[&original_admin.pk], b"ROTATE");
    assert_eq!(chain.call(&outsider, b"Nft", b"update_permission", &[&update]), Err("no_permissions".to_string()));
    chain.call(&original_admin, b"Nft", b"update_permission", &[&update]).unwrap();
    assert_eq!(permissions(&chain, b"ROTATE"), vec![new_admin.pk.to_vec()]);

    assert_eq!(
        mint(&chain, &original_admin, &receiver.pk, b"1", b"ROTATE", b"ITEM", b"false"),
        Err("no_permissions".to_string())
    );
    mint(&chain, &new_admin, &receiver.pk, b"1", b"ROTATE", b"ITEM", b"false").unwrap();

    let remove_all = permission_update(&[], &[&new_admin.pk], b"ROTATE");
    assert_eq!(
        chain.call(&new_admin, b"Nft", b"update_permission", &[&remove_all]),
        Err("permissions_cannot_be_empty".to_string())
    );
    assert_eq!(permissions(&chain, b"ROTATE"), vec![new_admin.pk.to_vec()]);
}

#[test]
fn token_soulbound_is_set_on_first_mint_and_is_immutable() {
    let chain = Chain::new();
    let admin = chain.wallet(AMA_1_DOLLAR);
    let holder = chain.wallet(0);
    let receiver = chain.wallet(0);
    create_collection(&chain, &admin, b"MIXED", b"false").unwrap();

    mint(&chain, &admin, &holder.pk, b"2", b"MIXED", b"BOUND", b"true").unwrap();
    mint(&chain, &admin, &holder.pk, b"2", b"MIXED", b"FREE", b"false").unwrap();
    assert_eq!(chain.get(b"nft:MIXED:BOUND:soulbound"), Some(b"true".to_vec()));
    assert_eq!(chain.get(b"nft:MIXED:FREE:soulbound"), None);

    assert_eq!(
        chain.call(&holder, b"Nft", b"transfer", &[&receiver.pk, b"1", b"MIXED", b"BOUND"]),
        Err("soulbound".to_string())
    );
    chain.call(&holder, b"Nft", b"transfer", &[&receiver.pk, b"1", b"MIXED", b"FREE"]).unwrap();
    assert_eq!(
        mint(&chain, &admin, &holder.pk, b"1", b"MIXED", b"BOUND", b"false"),
        Err("token_soulbound_immutable".to_string())
    );
    assert_eq!(
        mint(&chain, &admin, &holder.pk, b"1", b"MIXED", b"BAD-TOKEN", b"false"),
        Err("invalid_token".to_string())
    );
}

#[test]
fn nonfungible_tokens_are_single_issue_and_can_be_burned() {
    let chain = Chain::new();
    let admin = chain.wallet(AMA_1_DOLLAR);
    let holder = chain.wallet(0);
    let burn = crate::consensus::bic::coin::BURN_ADDRESS;
    create_collection_with_type(&chain, &admin, b"UNIQUE", b"false", b"true").unwrap();

    assert_eq!(
        mint(&chain, &admin, &holder.pk, b"2", b"UNIQUE", b"ONE", b"false"),
        Err("nonfungible_amount_must_be_one".to_string())
    );
    mint(&chain, &admin, &holder.pk, b"1", b"UNIQUE", b"ONE", b"false").unwrap();
    assert_eq!(
        mint(&chain, &admin, &holder.pk, b"1", b"UNIQUE", b"ONE", b"false"),
        Err("nonfungible_token_already_minted".to_string())
    );

    chain.call(&holder, b"Nft", b"transfer", &[&burn, b"1", b"UNIQUE", b"ONE"]).unwrap();
    assert_eq!(chain.get(&nft_key(&holder.pk, b"UNIQUE", b"ONE")), None);
    assert_eq!(chain.get(&nft_key(&burn, b"UNIQUE", b"ONE")), Some(b"1".to_vec()));
    assert_eq!(chain.get(b"nft:UNIQUE:ONE:totalSupply"), Some(b"0".to_vec()));
    assert_eq!(
        mint(&chain, &admin, &holder.pk, b"1", b"UNIQUE", b"ONE", b"false"),
        Err("nonfungible_token_already_minted".to_string())
    );

    //A different token ID remains independently mintable once.
    mint(&chain, &admin, &holder.pk, b"1", b"UNIQUE", b"TWO", b"false").unwrap();
}
