use std::marker::PhantomData;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::fs;
use std::path::Path;

use rand::rngs::OsRng;
use ed25519_dalek::{Keypair, PublicKey as SPublicKey};
use serde::Serialize;
use uuid::Uuid;
use serde::de::DeserializeOwned;

use c2l::statement::SignedStatement;
use c2l::artifact::*;

use c2l::hashing;
use c2l::bb::BulletinBoard;
use c2l::bb::Names;
use c2l::memory_bb::*;
use c2l::protocol::*;
use c2l::util;
use c2l::localstore::*;
use c2l::trustee::Trustee;

use crypto::context::{Context, RistrettoCtx};
use crypto::cryptosystem::naoryung::PublicKey;
use crypto::utils::serialization::VSerializable;
use simplelog::*;

#[test]
fn demo_ristretto() {
    CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Info, simplelog::Config::default(), TerminalMode::Mixed)
        ]
    ).unwrap();
    // demo is hardcoded to 2, 2
    demo::<RistrettoCtx, 3, 2, 2>();
}

fn demo<C: Context + Serialize + DeserializeOwned, const W: usize, const T: usize, const P: usize>() {
    
    let local1 = "./local";
    let local2 = "./local2";
    let local_path = Path::new(&local1);
    fs::remove_dir_all(local_path).ok();
    fs::create_dir(local_path).ok();
    let local_path = Path::new(&local2);
    fs::remove_dir_all(local_path).ok();
    fs::create_dir(local_path).ok();

    let trustee1: Trustee<C, W, T, P> = Trustee::new(local1.to_string());
    let trustee2: Trustee<C, W, T, P> = Trustee::new(local2.to_string());
    let mut csprng = OsRng;
    let bb_keypair = Keypair::generate(&mut csprng);
    let mut bb = MemoryBulletinBoard::<C, W, T, P>::new();
    
    let mut trustee_pks = Vec::new();
    trustee_pks.push(trustee1.keypair.public);
    trustee_pks.push(trustee2.keypair.public);
    
    let contests = 3;
    let cfg = gen_config::<C, W, T, P>(contests, trustee_pks, bb_keypair.public);
    let cfg_b = bincode::serialize(&cfg).unwrap();
    let tmp_file = util::write_tmp(cfg_b).unwrap();
    bb.add_config(&ConfigPath(tmp_file.path().to_path_buf()));
    
    let prot1: Protocol<C, W, T, P, MemoryBulletinBoard<C, W, T, P>> = Protocol::new(trustee1);
    let prot2: Protocol<C, W, T, P,  MemoryBulletinBoard<C, W, T, P>> = Protocol::new(trustee2);

    // mix position 0
    prot1.step(&mut bb);
    // verify mix position 0
    prot2.step(&mut bb);

    // nothing
    prot1.step(&mut bb);
    // mix position 1
    prot2.step(&mut bb);

    // check mix position 1
    prot1.step(&mut bb);
    // partial decryptions
    prot2.step(&mut bb);

    // partial decryptions
    prot1.step(&mut bb);
    // nothing
    prot2.step(&mut bb);

    // combine decryptions
    prot1.step(&mut bb);
    
    let mut all_plaintexts = Vec::with_capacity(contests as usize);
    
    println!("=================== ballots ===================");
    for i in 0..contests {
        let pk_b = bb.get_unsafe(MemoryBulletinBoard::<C, W, T, P>::public_key(i, 0)).unwrap();
        let pk: PublicKey<C> = bincode::deserialize(pk_b).unwrap();
        
        let (plaintexts, ciphertexts) = util::random_encrypt_ballots::<C, W, T>(100, &pk);
        all_plaintexts.push(plaintexts);
        let ballots = CBallots { ciphertexts };
        let ballots_b = bincode::serialize(&ballots).unwrap();
        let ballots_h = hashing::hash(&ballots);
        let cfg_h = hashing::hash(&cfg);
        let ss = SignedStatement::ballots(&cfg_h, &ballots_h, i, &bb_keypair);
        
        let ss_b = bincode::serialize(&ss).unwrap();
        
        let f1 = util::write_tmp(ballots_b).unwrap();
        let f2 = util::write_tmp(ss_b).unwrap();
        println!(">> Adding {} ballots", ballots.ciphertexts.len());
        bb.add_ballots(&BallotsPath(f1.path().to_path_buf(), f2.path().to_path_buf()), i);
    }
    println!("===============================================");

    // mix position 0
    prot1.step(&mut bb);
    // verify mix position 0
    prot2.step(&mut bb);

    // nothing
    prot1.step(&mut bb);
    // mix position 1
    prot2.step(&mut bb);

    // check mix position 1
    prot1.step(&mut bb);
    // partial decryptions
    prot2.step(&mut bb);

    // partial decryptions
    prot1.step(&mut bb);
    // nothing
    prot2.step(&mut bb);

    // combine decryptions
    prot1.step(&mut bb);

    for i in 0..contests {
        let decrypted_b = bb.get_unsafe(MemoryBulletinBoard::<C, W, T, P>::plaintexts(i, 0)).unwrap();
        let decrypted: CPlaintexts<C, W> = bincode::deserialize(decrypted_b).unwrap();
        let decrypted: Vec<Vec<u8>> = decrypted.plaintexts.iter().map(|p| {
            p.0.ser()
        }).collect();

        let plaintexts: Vec<Vec<u8>> = all_plaintexts[i as usize].iter().map(|p| {
            p.0.ser()
        }).collect();
        
        let p1: HashSet<Vec<u8>> = HashSet::from_iter(plaintexts.into_iter());
        let p2: HashSet<Vec<u8>> = HashSet::from_iter(decrypted.into_iter());
        
        print!("Checking plaintexts contest=[{}]...", i);
        assert!(p1 == p2);
        println!("Ok");
    }
}

fn gen_config<C: Context, const W: usize, const T: usize, const P: usize>(contests: u32, trustee_pks: Vec<SPublicKey>,
    ballotbox_pk: SPublicKey) -> c2l::artifact::CConfig<C> {

    let id = Uuid::new_v4();

    let cfg = c2l::artifact::CConfig {
        id: id.as_bytes().clone(),
        contests: contests, 
        ballotbox: ballotbox_pk, 
        trustees: trustee_pks,
        phantom_c: PhantomData
    };

    cfg
}