use crate::hashing::{Hash};
use crate::artifact::{Config, Keyshares, Ballots, Mix, PartialDecryption, Plaintexts};
use crate::Application;
use crypto::cryptosystem::naoryung::PublicKey;
use crate::protocol::SVerifier;

pub trait Names {
    const CONFIG: &'static str = "config";
    const CONFIG_STMT: &'static str = "config.stmt";
    const PAUSE: &'static str = "pause";
    const ERROR: &'static str = "error";

    fn config_stmt(auth: u32) -> String { format!("{}/config.stmt", auth).to_string() }

    fn share(contest: u32, auth: u32) -> String { format!("{}/{}/share", auth, contest).to_string() }
    fn share_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/share.stmt", auth, contest).to_string() }
    

    fn public_key(contest: u32, auth: u32) -> String { format!("{}/{}/public_key", auth, contest).to_string() }
    fn public_key_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/public_key.stmt", auth, contest).to_string() }
    

    fn ballots(contest: u32) -> String { format!("ballotbox/{}/ballots", contest).to_string() }
    fn ballots_stmt(contest: u32) -> String { format!("ballotbox/{}/ballots.stmt", contest).to_string() }
    
    
    fn mix(contest: u32, auth: u32) -> String { format!("{}/{}/mix", auth, contest).to_string() }
    fn mix_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/mix.stmt", auth, contest).to_string() }
    fn mix_stmt_other(contest: u32, auth: u32, other_t: u32) -> String { format!("{}/{}/mix.{}.stmt", auth, contest, other_t).to_string() }

    fn decryption(contest: u32, auth: u32) -> String { format!("{}/{}/decryption", auth, contest).to_string() }
    fn decryption_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/decryption.stmt", auth, contest).to_string() }
    

    fn plaintexts(contest: u32, auth: u32) -> String { format!("{}/{}/plaintexts", auth, contest).to_string() }
    fn plaintexts_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/plaintexts.stmt", auth, contest).to_string() }
    
    
    fn auth_error(auth: u32) -> String { format!("{}/error", auth).to_string() }
}

use crate::localstore::*;

pub trait BulletinBoard<A: Application> {

    fn list(&self) -> Vec<String>;
    
    fn add_config(&mut self, config: &ConfigPath);
    fn get_config_unsafe(&self) -> Option<Config<A>>;
    
    fn add_config_stmt(&mut self, stmt: &ConfigStmtPath, trustee: u32);
    fn get_config(&self, hash: Hash) -> Option<Config<A>>;
    
    fn add_share(&mut self, path: &KeysharePath, contest: u32, trustee: u32);
    fn get_shares(&self, contest: u32, hashes: Vec<Hash>) -> Option<[Keyshares<A>; A::P]> where [(); A::P]:, [(); A::T]:;
    
    fn set_pk(&mut self, path: &PkPath, contest: u32);
    fn set_pk_stmt(&mut self, path: &PkStmtPath, contest: u32, trustee: u32);
    fn get_pk(&self, contest: u32, hash: Hash) -> Option<PublicKey<A::Context>>;

    fn add_ballots(&mut self, path: &BallotsPath, contest: u32);
    fn get_ballots(&self, contest: u32, hash: Hash) -> Option<Ballots<A>> where [(); A::W]:;
    
    fn add_mix(&mut self, path: &MixPath, contest: u32, trustee: u32);
    fn add_mix_stmt(&mut self, path: &MixStmtPath, contest: u32, trustee: u32, other_t: u32);
    fn get_mix(&self, contest: u32, trustee: u32, hash: Hash) -> Option<Mix<A>> where [(); A::W]:;

    fn add_decryption(&mut self, path: &PDecryptionsPath, contest: u32, trustee: u32);
    fn get_decryption(&self, contest: u32, trustee: u32, hash: Hash) -> Option<PartialDecryption<A>> where [(); A::W]:;

    fn set_plaintexts(&mut self, path: &PlaintextsPath, contest: u32);
    fn set_plaintexts_stmt(&mut self, path: &PlaintextsStmtPath, contest: u32, trustee: u32);
    fn get_plaintexts(&self, contest: u32, hash: Hash) -> Option<Plaintexts<A>> where [(); A::W]:;

    fn get_statements(&self) -> Vec<SVerifier>;
    fn get_stmts(&self) -> Vec<String> {
        self.list().into_iter().filter(|s| {
            s.ends_with(".stmt")
        }).collect()
    }
    
}