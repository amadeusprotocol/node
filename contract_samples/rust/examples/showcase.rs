#![cfg_attr(not(any(test, feature = "testing")), no_std)]
#![cfg_attr(not(any(test, feature = "testing")), no_main)]
#![cfg_attr(any(test, feature = "testing"), feature(thread_local))]

extern crate alloc;

#[cfg(any(test, feature = "testing"))]
extern crate std;

use alloc::string::{String, ToString};
use amadeus_sdk::*;

#[contract_state]
struct Match {
    #[flat] score: u16,
    #[flat] opponent: String,
}

#[contract_state]
struct TournamentInfo {
    #[flat] name: String,
    #[flat] prize_pool: u64,
}

type PlayerWinsMap = MapFlat<String, u32>;
type MatchesMap = Map<u64, Match>;
type PlayersMap = Map<String, MatchesMap>;

#[contract_state]
struct Leaderboard {
    #[flat] total_matches: i32,
    player_wins: PlayerWinsMap,
    players: PlayersMap,
    tournament: TournamentInfo,
}

#[contract]
impl Leaderboard {
    pub fn increment_total_matches(&mut self) {
        *self.total_matches += 1;
    }

    pub fn get_total_matches(&self) -> i32 {
        *self.total_matches
    }

    pub fn record_match(&mut self, player: String, match_id: u64, score: u16, opponent: String) {
        if let Some(matches) = self.players.get_mut(player.clone()) {
            if let Some(m) = matches.get_mut(match_id) {
                *m.score = score;
                *m.opponent = opponent;
            }
        }
        *self.total_matches += 1;
    }

    pub fn get_match_score(&self, player: String, match_id: u64) -> u16 {
        if let Some(matches) = self.players.get(player) {
            if let Some(m) = matches.get(match_id) {
                return *m.score;
            }
        }
        0
    }

    pub fn get_match_opponent(&self, player: String, match_id: u64) -> String {
        if let Some(matches) = self.players.get(player) {
            if let Some(m) = matches.get(match_id) {
                return (*m.opponent).clone();
            }
        }
        String::new()
    }

    pub fn set_tournament_info(&mut self, name: String, prize_pool: u64) {
        *self.tournament.name = name;
        *self.tournament.prize_pool = prize_pool;
    }

    pub fn get_tournament_name(&self) -> String {
        (*self.tournament.name).clone()
    }

    pub fn get_tournament_prize(&self) -> u64 {
        *self.tournament.prize_pool
    }

    pub fn record_win(&mut self, player: String) {
        if let Some(wins) = self.player_wins.get_mut(&player) {
            **wins += 1;
        } else {
            self.player_wins.insert(player, 1);
        }
    }

    pub fn get_player_wins(&self, player: String) -> u32 {
        if let Some(wins) = self.player_wins.get(&player) {
            **wins
        } else {
            0
        }
    }

    pub fn set_player_wins(&mut self, player: String, wins: u32) {
        self.player_wins.insert(player, wins);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amadeus_sdk::testing::*;

    #[test]
    fn test_increment_total_matches() {
        reset();
        let mut state = Leaderboard::with_prefix(Vec::new());
        state.increment_total_matches();
        state.flush();
        println!("\n{}\n", dump());
        let state2 = Leaderboard::with_prefix(Vec::new());
        assert_eq!(state2.get_total_matches(), 1);
    }

    #[test]
    fn test_set_tournament_info() {
        reset();
        let mut state = Leaderboard::with_prefix(Vec::new());
        state.set_tournament_info("World Cup".to_string(), 1000000);
        state.flush();
        println!("\n{}\n", dump());
        let state2 = Leaderboard::with_prefix(Vec::new());
        assert_eq!(state2.get_tournament_name(), "World Cup");
        assert_eq!(state2.get_tournament_prize(), 1000000);
    }

    #[test]
    fn test_record_win() {
        reset();
        let mut state = Leaderboard::with_prefix(Vec::new());
        state.record_win("alice".to_string());
        state.flush();
        println!("\n{}\n", dump());
        let state2 = Leaderboard::with_prefix(Vec::new());
        assert_eq!(state2.get_player_wins("alice".to_string()), 1);
    }

    #[test]
    fn test_multiple_operations() {
        reset();

        let mut state = Leaderboard::with_prefix(Vec::new());
        state.increment_total_matches();
        state.flush();
        println!("After increment_total_matches():\n{}\n", dump());

        let mut state = Leaderboard::with_prefix(Vec::new());
        state.set_tournament_info("World Cup".to_string(), 1000000);
        state.flush();
        println!("After set_tournament_info():\n{}\n", dump());

        let mut state = Leaderboard::with_prefix(Vec::new());
        state.record_win("alice".to_string());
        state.flush();
        println!("After record_win(alice):\n{}\n", dump());

        let mut state = Leaderboard::with_prefix(Vec::new());
        state.record_win("alice".to_string());
        state.flush();
        println!("After record_win(alice) 2nd:\n{}\n", dump());

        let mut state = Leaderboard::with_prefix(Vec::new());
        state.record_win("bob".to_string());
        state.flush();
        println!("After record_win(bob):\n{}\n", dump());

        let mut state = Leaderboard::with_prefix(Vec::new());
        state.set_player_wins("charlie".to_string(), 5);
        state.flush();
        println!("After set_player_wins(charlie, 5):\n{}\n", dump());

        let state = Leaderboard::with_prefix(Vec::new());
        assert_eq!(state.get_total_matches(), 1);
        assert_eq!(state.get_player_wins("alice".to_string()), 2);
        assert_eq!(state.get_player_wins("bob".to_string()), 1);
        assert_eq!(state.get_player_wins("charlie".to_string()), 5);
        assert_eq!(state.get_tournament_name(), "World Cup");
        assert_eq!(state.get_tournament_prize(), 1000000);
    }
}
