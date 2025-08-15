use crypto::cryptosystem::naoryung::PublicKey;
use serde::de::DeserializeOwned;
use std::array;
use std::collections::HashMap;
use std::path::Path;
use std::marker::PhantomData;
use crypto::context::Context;

use crate::hashing::{HashBytes, Hash};
use crate::hashing;
use crate::bb::*;
use crate::artifact::*;
use crate::statement::*;
use crate::protocol::SVerifier;
use crate::util;
use crate::localstore::*;

struct MBasicBulletinBoard{
    data: HashMap<String, Vec<u8>>
}

impl MBasicBulletinBoard {
    pub fn new() -> MBasicBulletinBoard {
        MBasicBulletinBoard {
            data: HashMap::new()
        }
    }
    fn list(&self) -> Vec<String> {
        self.data.iter().map(|(a, _)| a.clone()).collect()
    }
    fn get<A: HashBytes + DeserializeOwned>(&self, target: String, hash: Hash) -> Result<A, String> {
        let key = target;
        let bytes = self.data.get(&key).ok_or("Not found")?;

        let artifact = bincode::deserialize::<A>(bytes)
            .map_err(|e| std::format!("serde error {}", e))?;

        let hashed = hashing::hash(&artifact);
        
        if hashed == hash {
            Ok(artifact)
        }
        else {
            Err("Hash mismatch".to_string())
        }
    }
    fn put(&mut self, name: &str, data: &Path) {
        let bytes = util::read_file_bytes(data).unwrap();
        if self.data.contains_key(name) {
            panic!("Attempted to overwrite bulletin board value for key '{}'", name);
        }
        self.data.insert(name.to_string(), bytes);
    }
    fn get_unsafe(&self, target: &str) -> Option<&Vec<u8>> {
        self.data.get(target)
    }
    fn clear(&mut self) {
        self.data.clear();
    }
}

pub struct MemoryBulletinBoard<C: Context, const W: usize, const T: usize, const P: usize> {
    basic: MBasicBulletinBoard,
    phantom_c: PhantomData<C>,
}

impl<C: Context, const W: usize, const T: usize, const P: usize> MemoryBulletinBoard<C, W, T, P> {
    pub fn new() -> MemoryBulletinBoard<C, W, T, P> {
        MemoryBulletinBoard {
            basic: MBasicBulletinBoard::new(),
            phantom_c: PhantomData,
        }
    }
    pub fn clear(&mut self) {
        self.basic.clear();
    }
    fn put(&mut self, name: &str, data: &Path) {
        self.basic.put(name, data);
    }
    fn get<A: HashBytes + DeserializeOwned>(&self, target: String, hash: Hash) -> Result<A, String> {
        self.basic.get(target, hash)
    }
    pub fn get_unsafe(&self, target: String) -> Option<&Vec<u8>> {
        self.basic.get_unsafe(&target)
    }
}

impl<C: Context + DeserializeOwned, const W: usize, const T: usize, const P: usize> BulletinBoard<C, W, T, P> for MemoryBulletinBoard<C, W, T, P> {
    
    fn list(&self) -> Vec<String> {
        self.basic.list()
    }
    fn add_config(&mut self, path: &ConfigPath) {
        self.put(Self::CONFIG, &path.0);
    }
    fn get_config_unsafe(&self) -> Option<CConfig<C>> {
        let bytes = self.basic.get_unsafe(Self::CONFIG)?;
        let ret: CConfig<C> = bincode::deserialize(bytes).unwrap();

        Some(ret)
    }
    
    fn get_config(&self, hash: Hash) -> Option<CConfig<C>> {
        let ret = self.get(Self::CONFIG.to_string(), hash).ok()?;

        Some(ret)
    }
    fn add_config_stmt(&mut self, path: &ConfigStmtPath, trustee: u32) {
        self.put(&Self::config_stmt(trustee), &path.0);
    }
    
    fn add_share(&mut self, path: &KeysharePath, contest: u32, trustee: u32) {
        self.put(&Self::share(contest, trustee), &path.0);
        self.put(&Self::share_stmt(contest, trustee), &path.1);
    }
    fn get_shares(&self, contest: u32, hashes: Vec<Hash>) -> Option<[CKeyshares<C, T, P>; P]> {
        let ret: [CKeyshares<C, T, P>; P] = array::from_fn(|i| {
            let key = Self::share(contest, i as u32).to_string();
            self.get(key, hashes[i]).unwrap()
        });

        Some(ret)
    }
    
    fn set_pk(&mut self, path: &PkPath, contest: u32) {
        // 0: trustee 0 combines shares into pk
        self.put(&Self::public_key(contest, 0), &path.0);
        self.put(&Self::public_key_stmt(contest, 0), &path.1);
    }
    fn set_pk_stmt(&mut self, path: &PkStmtPath, contest: u32, trustee: u32) {
        self.put(&Self::public_key_stmt(contest, trustee), &path.0);
    }
    fn get_pk(&mut self, contest: u32, hash: Hash) -> Option<PublicKey<C>> {
        // 0: trustee 0 combines shares into pk
        let key = Self::public_key(contest, 0).to_string();
        let ret = self.get(key, hash).ok()?;

        Some(ret)
    }

    fn add_ballots(&mut self, path: &BallotsPath, contest: u32) {
        self.put(&Self::ballots(contest), &path.0);
        self.put(&Self::ballots_stmt(contest), &path.1);
    }
    fn get_ballots(&self, contest: u32, hash: Hash) -> Option<CBallots<C, W>> {
        let key = Self::ballots(contest).to_string();
        let ret = self.get(key, hash).ok()?;

        Some(ret)
    }

    fn add_mix(&mut self, path: &MixPath, contest: u32, trustee: u32) {
        self.put(&Self::mix(contest, trustee), &path.0);
        self.put(&Self::mix_stmt(contest, trustee), &path.1);
    }
    fn add_mix_stmt(&mut self, path: &MixStmtPath, contest: u32, trustee: u32, other_t: u32) {
        self.put(&Self::mix_stmt_other(contest, trustee, other_t), &path.0);
    }
    fn get_mix(&self, contest: u32, trustee: u32, hash: Hash) -> Option<CMix<C, W, T>> {
        let key = Self::mix(contest, trustee).to_string();
        let ret = self.get(key, hash).ok()?;

        Some(ret)
    }

    fn add_decryption(&mut self, path: &PDecryptionsPath, contest: u32, trustee: u32) {
        self.put(&Self::decryption(contest, trustee), &path.0);
        self.put(&Self::decryption_stmt(contest, trustee), &path.1);
    }
    fn get_decryption(&self, contest: u32, trustee: u32, hash: Hash) -> Option<CPartialDecryption<C, W>> {
        let key = Self::decryption(contest, trustee).to_string();
        let ret = self.get(key, hash).ok()?;

        Some(ret)
    }

    fn set_plaintexts(&mut self, path: &PlaintextsPath, contest: u32) {
        // 0: trustee 0 combines shares into pk
        self.put(&Self::plaintexts(contest, 0), &path.0);
        self.put(&Self::plaintexts_stmt(contest, 0), &path.1);
    }
    fn set_plaintexts_stmt(&mut self, path: &PlaintextsStmtPath, contest: u32, trustee: u32) {
        self.put(&Self::plaintexts_stmt(contest, trustee), &path.0);
    }
    fn get_plaintexts(&self, contest: u32, hash: Hash) -> Option<CPlaintexts<C, W>> {
        // 0: trustee 0 combines shares into pk
        let key = Self::plaintexts(contest, 0).to_string();
        let ret = self.get(key, hash).ok()?;

        Some(ret)
    }

    fn get_statements(&self) -> Vec<SVerifier> {
        
        let sts = self.get_stmts();
        let mut ret = Vec::new();
        // println!("Statements {:?}", sts);
        
        for s in sts.iter() {
            let s_bytes = self.basic.get_unsafe(s).unwrap().to_vec();
            let (trustee, contest) = artifact_location(s);
            let stmt: SignedStatement = bincode::deserialize(&s_bytes).unwrap();

            let next = SVerifier {
                statement: stmt,
                trustee: trustee,
                contest: contest
            };
            ret.push(next);
        }

        ret
    }
}

impl<C: Context, const W: usize, const T: usize, const P: usize> Names for MemoryBulletinBoard <C, W, T, P>{}

fn artifact_location(path: &str) -> (i32, u32) {
    let p = Path::new(&path);
    let comp: Vec<&str> = p.components()
        .take(2)
        .map(|comp| comp.as_os_str().to_str().unwrap())
        .collect();
    
    let trustee: i32 =
    if comp[0] == "ballotbox" {
        -1
    }
    else {
        comp[0].parse().unwrap()
    };
    // root artifacts (eg config) have no contest
    let contest: u32 = comp[1].parse().unwrap_or(0);

    (trustee, contest)
}