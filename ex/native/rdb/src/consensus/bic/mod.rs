pub mod coin;
pub mod coin_symbol_reserved;
pub mod contract;
pub mod epoch;
pub mod exsss;
pub mod lockup;
pub mod lockup_prime;
pub mod nft;
pub mod protocol;
pub mod sol;
pub mod sol_bloom;
pub mod sol_difficulty;
pub mod sol_freivalds;
pub mod wasm;

pub fn list_of_binaries_to_vecpak(list_of_binaries: Vec<Vec<u8>>) -> Vec<u8> {
    let elements: Vec<vecpak::Term> = list_of_binaries
        .into_iter()
        .map(|bytes| vecpak::Term::from(vecpak::Term::Binary(bytes)))
        .collect();
    vecpak::encode(vecpak::Term::List(elements))
}
