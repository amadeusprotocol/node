//non-consensus epoch payout report: each epoch boundary writes
//<WORKFOLDER>/epoch_payouts/<epoch>.csv with one row per balance credit made at
//the boundary: <b58 address>,<type>,<flat amount>. types: "emission" (solver
//mining emission), "interest" (vault APY paid out to a payout address, net of
//commission), "interest_compounded" (vault APY accrued into the vault, attributed
//to the vault owner — not a balance credit), "commission" (validator commission
//skimmed off vault yield), "tax" (network tax to treasury). the directory comes
//from the same WORKFOLDER envvar runtime.exs reads (default ~/.cache/amadeusd).
//observer only: consensus state and mutation tracking are untouched, and the file
//is written atomically (tmp+rename) so re-applies and reorg replays converge on
//the canonical content.
use std::sync::OnceLock;

static REPORT_DIR: OnceLock<Option<String>> = OnceLock::new();

fn dir() -> Option<&'static String> {
    REPORT_DIR
        .get_or_init(|| {
            let base = std::env::var("WORKFOLDER")
                .ok()
                .or_else(|| std::env::var("HOME").ok().map(|home| format!("{}/.cache/amadeusd", home)))?;
            Some(format!("{}/epoch_payouts", base.trim_end_matches('/')))
        })
        .as_ref()
}

pub struct Report {
    rows: Vec<(Vec<u8>, &'static str, i128)>,
}

impl Report {
    pub fn new() -> Report {
        Report { rows: Vec::new() }
    }

    pub fn add(&mut self, address: &[u8], kind: &'static str, amount: i128) {
        if dir().is_some() && amount > 0 {
            self.rows.push((address.to_vec(), kind, amount));
        }
    }

    pub fn write(&self, epoch: u64) {
        let Some(dir) = dir() else { return };
        let _ = std::fs::create_dir_all(dir);
        let mut out = String::new();
        for (addr, kind, amount) in &self.rows {
            out.push_str(&format!("{},{},{}\n", bs58::encode(addr).into_string(), kind, amount));
        }
        let tmp = format!("{}/{}.csv.tmp", dir, epoch);
        let path = format!("{}/{}.csv", dir, epoch);
        if std::fs::write(&tmp, out).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}
