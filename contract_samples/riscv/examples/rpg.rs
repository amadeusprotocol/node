#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use amadeus_contract as c;
use c::vecpak::Term;

const COLLECTION: &[u8] = b"RPG";
const COLLECTION_SOULBOUND: &[u8] = b"RPGSOULBOUND";
const IMAGE: &[u8] = b"https://ipfs.io/ipfs/QmWBaeu6y1zEcKbsEqCuhuDHPL3W8pZouCPdafMCRCSUWk";

struct Hero {
    hp_cur: i64,
    hp_max: i64,
    str: i64,
    dex: i64,
    int: i64,
    weapon: Vec<u8>,
    helmet: Vec<u8>,
}

impl Hero {
    fn new() -> Hero {
        Hero { hp_cur: 20, hp_max: 20, str: 10, dex: 10, int: 10, weapon: Vec::new(), helmet: Vec::new() }
    }

    fn encode(&self) -> Vec<u8> {
        let int = |k: &[u8], v: i64| (Term::Binary(k.to_vec()), Term::Int(v as i128));
        let bin = |k: &[u8], v: &[u8]| (Term::Binary(k.to_vec()), Term::Binary(v.to_vec()));
        let map = Term::Map(alloc::vec![
            int(b"hp_cur", self.hp_cur),
            int(b"hp_max", self.hp_max),
            int(b"str", self.str),
            int(b"dex", self.dex),
            int(b"int", self.int),
            bin(b"weapon", &self.weapon),
            bin(b"helmet", &self.helmet),
        ]);
        c::vecpak::encode(&map).unwrap_or_else(|e| c::abort(e.as_bytes()))
    }

    fn decode(bytes: &[u8]) -> Hero {
        let Ok(Term::Map(pairs)) = c::vecpak::decode(bytes) else { c::abort(b"corrupt hero") };
        let mut hero = Hero::new();
        for (k, v) in pairs {
            match (k, v) {
                (Term::Binary(k), Term::Int(v)) => match k.as_slice() {
                    b"hp_cur" => hero.hp_cur = v as i64,
                    b"hp_max" => hero.hp_max = v as i64,
                    b"str" => hero.str = v as i64,
                    b"dex" => hero.dex = v as i64,
                    b"int" => hero.int = v as i64,
                    _ => {}
                },
                (Term::Binary(k), Term::Binary(v)) => match k.as_slice() {
                    b"weapon" => hero.weapon = v,
                    b"helmet" => hero.helmet = v,
                    _ => {}
                },
                _ => {}
            }
        }
        hero
    }
}

struct Monster {
    name: &'static [u8],
    hp_cur: i64,
    hp_max: i64,
    dam_min: i64,
    dam_max: i64,
    ac: i64,
    drops: &'static [(&'static [u8], i64)],
}

const GOBLIN: Monster = Monster { name: b"goblin", hp_cur: 10, hp_max: 10, dam_min: 1, dam_max: 2, ac: 0, drops: &[(b"gold", 30), (b"rustydagger", 5)] };
const ORC: Monster = Monster { name: b"orc", hp_cur: 18, hp_max: 18, dam_min: 1, dam_max: 3, ac: 1, drops: &[(b"gold", 30), (b"orchelmet", 5)] };

struct Stats {
    dam_dice_sides: i64,
    dam_extra: i64,
    ac: i64,
}

fn item(nft: &[u8]) -> Stats {
    match nft {
        b"rustydagger" => Stats { dam_dice_sides: 3, dam_extra: 1, ac: 0 },
        b"orchelmet" => Stats { dam_dice_sides: 0, dam_extra: 0, ac: 1 },
        _ => Stats { dam_dice_sides: 4, dam_extra: 0, ac: 0 },
    }
}

struct Dice(u64);

impl Dice {
    fn from_seed() -> Dice {
        let seed = c::seed();
        Dice(seed.iter().fold(0x9E37_79B9_7F4A_7C15u64, |h, &b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3)))
    }

    fn roll(&mut self, sides: i64) -> i64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        if sides <= 0 { 1 } else { (z % sides as u64) as i64 + 1 }
    }
}

fn named(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
    let map = Term::Map(pairs.iter().map(|(k, v)| (Term::Binary(k.to_vec()), Term::Binary(v.to_vec()))).collect());
    c::vecpak::encode(&map).unwrap_or_else(|e| c::abort(e.as_bytes()))
}

fn hero_key() -> Vec<u8> {
    [b"hero:".as_slice(), &c::account_caller()].concat()
}

fn num(v: i64) -> Vec<u8> {
    let mut buf = [0u8; 48];
    c::itoa(v as i128, &mut buf).to_vec()
}

fn fight() {
    let key = hero_key();
    let mut hero = Hero::decode(&c::kv_get(&key).unwrap_or_else(|| c::abort(b"hero doesnt exist")));
    let mut dice = Dice::from_seed();
    let mut mob = if dice.roll(10) >= 7 { ORC } else { GOBLIN };
    c::log(&[b"A wild ".as_slice(), mob.name, b" appears"].concat());

    let weapon = item(&hero.weapon);
    let helmet = item(&hero.helmet);
    loop {
        if hero.hp_cur <= 0 {
            c::log(b"You have died, reviving");
            hero.hp_cur = hero.hp_max;
            break;
        }
        if mob.hp_cur <= 0 {
            c::log(&[mob.name, b" died"].concat());
            for &(nft, chance) in mob.drops {
                if dice.roll(100) <= chance {
                    c::log(&[mob.name, b" dropped ", nft].concat());
                    let args = named(&[(b"receiver", &c::account_caller()), (b"amount", b"1"), (b"collection", COLLECTION), (b"token", nft), (b"soulbound", b"false")]);
                    c::call(b"Nft", b"mint", &[&args], &[]);
                }
            }
            break;
        }
        let dealt = (dice.roll(weapon.dam_dice_sides) + weapon.dam_extra - mob.ac).max(0);
        let taken = (dice.roll(mob.dam_max) + mob.dam_min - helmet.ac).max(1);
        mob.hp_cur -= dealt;
        hero.hp_cur -= taken;
        c::log(&[
            b"You hit for ".as_slice(), &num(dealt), b", ", mob.name, b" HP ", &num(mob.hp_cur), b"/", &num(mob.hp_max),
            b". It hits for ", &num(taken), b", your HP ", &num(hero.hp_cur), b"/", &num(hero.hp_max),
        ].concat());
    }
    c::kv_put(&key, &hero.encode());
}

fn dispatch(f: &[u8]) {
    match f {
        b"init" => {
            for (collection, soulbound) in [(COLLECTION, b"false".as_slice()), (COLLECTION_SOULBOUND, b"true")] {
                let args = named(&[(b"collection", collection), (b"soulbound", soulbound), (b"nonfungible", b"false")]);
                c::call(b"Nft", b"create_collection", &[&args], &[]);
            }
        }
        b"create_hero" => {
            let key = hero_key();
            if c::kv_exists(&key) {
                c::abort(b"hero exists");
            }
            c::kv_put(&key, &Hero::new().encode());
        }
        b"hero" => c::ret(&c::kv_get(&hero_key()).unwrap_or_else(|| c::abort(b"hero doesnt exist"))),
        b"fight" => fight(),
        b"view_nft" => c::ret(IMAGE),
        _ => c::abort(b"unknown function"),
    }
}

c::entry!(dispatch);
