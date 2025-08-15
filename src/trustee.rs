use std::array;
use std::marker::PhantomData;

use crypto::cryptosystem::elgamal;
use crypto::cryptosystem::Plaintext;
use crypto::dkgd::reconstruct;
use crypto::dkgd::Dealer;
use crypto::cryptosystem::elgamal::Ciphertext;
use crypto::cryptosystem::naoryung::PublicKey;
use crypto::dkgd::DkgCiphertext;
use crypto::dkgd::ParticipantPosition;
use crypto::dkgd::Recipient;
use crypto::traits::CryptoGroup;
use crypto::dkgd::VerifiableShare;
use crypto::context::Context;
use crypto::zkp::shuffle::Shuffler;

use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use log::info;

use crate::hashing;
use crate::artifact::{Config, Keyshares, Ballots, Mix, PartialDecryption, Plaintexts};
use crate::statement::*;
use crate::bb::*;
use crate::util;
use crate::action::Act;
use crate::util::short;
use crate::localstore::LocalStore;
use crate::protocol::*;
use crate::Application;

pub struct Trustee<A: Application> {
    pub keypair: Keypair,
    pub localstore: LocalStore<A>,
}

impl<A: Application> Trustee<A> {
    
    pub fn new(local_store: String) -> Trustee<A> {
        let mut csprng = OsRng;
        let localstore = LocalStore::new(local_store);
        let keypair = Keypair::generate(&mut csprng);

        Trustee {
            keypair,
            localstore,
        }
    }
    
    pub fn run<B: BulletinBoard<A>>(&self, facts: Facts, board: &mut B) -> u32 where [(); A::W]:, [(); A::T]:, [(); A::P]: {
        let self_index = facts.get_self_index();
        let trustees = facts.get_trustee_count();
        let actions = facts.all_actions;
        let ret = actions.len();
        
        info!(">>>> Trustee::run: found {} actions", ret);
        let now = std::time::Instant::now();
        for action in actions {
            match action {
                Act::CheckConfig(cfg) => {
                    info!(">> Action: checking config..");
                    let ss = SignedStatement::config(&cfg, &self.keypair);
                    let stmt_path = self.localstore.set_config_stmt(&action, &ss);
                    board.add_config_stmt(&stmt_path, self_index.unwrap());
                    info!(">> OK");
                }
                Act::PostShare(cfg_h, cnt) => {
                    info!(">> Action: Computing shares (contest=[{}], self=[{}])..", cnt, self_index.unwrap());
                    let _cfg = board.get_config(cfg_h).unwrap();
                    let share = self.share();
                    let share_h = hashing::hash(&share);
                    let ss = SignedStatement::keyshare(&cfg_h, &share_h, cnt, &self.keypair);
                    let share_path = self.localstore.set_share(&action, share, &ss);
                    
                    board.add_share(&share_path, cnt, self_index.unwrap());
                    info!(">> OK");
                }
                Act::CombineShares(cfg_h, cnt, hs) => {
                    info!(">> Action: Combining shares (contest=[{}], self=[{}])..", cnt, self_index.unwrap());
                    let _cfg = board.get_config(cfg_h).unwrap();
                    let hashes = util::clear_zeroes(&hs);
                    assert!(hashes.len() as u32 == trustees.unwrap());
                    let pk = self.get_pk(board, hashes, cnt, self_index.unwrap()).unwrap();
                    let pk_h = hashing::hash(&pk);
                    let ss = SignedStatement::public_key(&cfg_h, &pk_h, cnt, &self.keypair);
                    
                    let pk_path = self.localstore.set_pk(&action, pk, &ss);
                    board.set_pk(&pk_path, cnt);
                    info!(">> OK");
                }
                Act::CheckPk(cfg_h, cnt, pk_h, hs) => {
                    info!(">> Action: Verifying pk (contest=[{}], self=[{}])..", cnt, self_index.unwrap());
                    let _cfg = board.get_config(cfg_h).unwrap();
                    let hashes = util::clear_zeroes(&hs);
                    info!(">> Action: get pk.. (contest=[{}], self=[{}])..", cnt, self_index.unwrap());
                    let pk = self.get_pk(board, hashes, cnt, self_index.unwrap()).unwrap();
                    let pk_h_ = hashing::hash(&pk);
                    assert!(pk_h == pk_h_);
                    let ss = SignedStatement::public_key(&cfg_h, &pk_h, cnt, &self.keypair);
                    
                    let pk_stmt_path = self.localstore.set_pk_stmt(&action, &ss);
                    board.set_pk_stmt(&pk_stmt_path, cnt, self_index.unwrap());
                    info!(">> OK");
                }
                Act::Mix(cfg_h, cnt, ballots_h, pk_h) => {
                    let self_t = self_index.unwrap();
                    info!(">> Computing mix (contest=[{}], self=[{}])..", cnt, self_t);
                    let _cfg = board.get_config(cfg_h).unwrap();
                    let pk = board.get_pk(cnt, pk_h).unwrap();
                    let ciphertexts = self.get_mix_src(board, cnt, self_t, ballots_h, &pk);
                    
                    let h_generators = <<A as Application>::Context as Context>::G::ind_generators(ciphertexts.len(), &vec![]);
                    let pk = elgamal::PublicKey::new(pk.pk_b);
                    let shuffler = Shuffler::new(h_generators, pk);
                    
                    let now_ = std::time::Instant::now();
                    let (e_primes, proof) = shuffler.shuffle(&ciphertexts, &vec![]);
                    
                    let rate = ciphertexts.len() as f32 / now_.elapsed().as_millis() as f32;
                    info!("Shuffle + Proof ({:.1} ciphertexts/s)", 1000.0 * rate);
                    
                    let mix = Mix {
                        mixed_ballots: e_primes,
                        proof: proof,
                        phantom_a: PhantomData,
                    };
                    let mix_h = hashing::hash(&mix);
                    
                    let ss = SignedStatement::mix(&cfg_h, &mix_h, &ballots_h, cnt, &self.keypair, None);
                    
                    let now_ = std::time::Instant::now();
                    let mix_path = self.localstore.set_mix(&action, mix, &ss);
                    let rate = ciphertexts.len() as f32 / now_.elapsed().as_millis() as f32;
                    info!("IO Write ({:.1} ciphertexts/s)", 1000.0 * rate);
                    
                    board.add_mix(&mix_path, cnt, self_index.unwrap());  
                    info!(">> Mix generated {:?} <- {:?}", short(&mix_h), short(&ballots_h));
                }
                Act::CheckMix(cfg_h, cnt, trustee, mix_h, ballots_h, pk_h) => {
                    let _cfg = board.get_config(cfg_h).unwrap();
                    info!(">> Action:: Verifying mix (contest=[{}], self=[{}])..", cnt, self_index.unwrap());
                    let mix = board.get_mix(cnt, trustee, mix_h).unwrap();
                    let pk: PublicKey<A::Context> = board.get_pk(cnt, pk_h).unwrap();
                    let ciphertexts = self.get_mix_src(board, cnt, trustee, ballots_h, &pk);
                    
                    let h_generators = <<A as Application>::Context as Context>::G::ind_generators(ciphertexts.len(), &vec![]);
                    let pk = elgamal::PublicKey::new(pk.pk_b);
                    let shuffler = Shuffler::new(h_generators, pk);
                    let proof = mix.proof;
                    info!("Verifying {:?} <- source {:?}", short(&mix_h), short(&ballots_h));
                    
                    let now_ = std::time::Instant::now();
                    assert!(shuffler.verify(&ciphertexts, &mix.mixed_ballots, &proof, &vec![]));
                    let rate = ciphertexts.len() as f32 / now_.elapsed().as_millis() as f32;
                    info!("Check proof ({:.1} ciphertexts/s)", 1000.0 * rate);
            
                    let ss = SignedStatement::mix(&cfg_h, &mix_h, &ballots_h, cnt, &self.keypair, Some(trustee));
                    let mix_path = self.localstore.set_mix_stmt(&action, &ss);
                    board.add_mix_stmt(&mix_path, cnt, self_index.unwrap(), trustee);
                    
                    info!(">> OK");
                }
                Act::PartialDecrypt(cfg_h, cnt, mix_h, shares_hs) => {
                    info!(">> Action: Computing partial decryptions (contest=[{}], self=[{}])..", cnt, self_index.unwrap());
                    let cfg = board.get_config(cfg_h).unwrap();
                    let mix = board.get_mix(cnt, (cfg.trustees.len() - 1) as u32, mix_h).unwrap();
                    let shares_hs = util::clear_zeroes(&shares_hs);
                    let shares = board.get_shares(cnt, shares_hs).unwrap();
                    
                    let participant = ParticipantPosition::new(self_index.unwrap() + 1);
                    let verifiable_shares: [VerifiableShare<A::Context, {A::T}>; {A::P}] = shares.map(|v| {
                        v.shares.for_participant(&participant)
                    });

                    let recipient = Recipient::new(participant, verifiable_shares);
                    let now_ = std::time::Instant::now();
                    
                    let ciphertexts: Vec<DkgCiphertext<A::Context, {A::W}, {A::T}>> = mix.mixed_ballots.iter()
                        .map(|c| DkgCiphertext(c.clone())).collect();
                    let dfs = recipient.decryption_factor(&ciphertexts, &vec![]);

                    let rate = mix.mixed_ballots.len() as f32 / now_.elapsed().as_millis() as f32;
                    let pd = PartialDecryption {
                        pd_ballots: dfs,
                        phantom_a: PhantomData,
                    };

                    let pd_h = hashing::hash(&pd);
                    let ss = SignedStatement::pdecryptions(&cfg_h, cnt, &pd_h, &self.keypair);
                    let pd_path = self.localstore.set_pdecryptions(&action, pd, &ss);
                    
                    board.add_decryption(&pd_path, cnt, self_index.unwrap());
                    
                    info!(">> OK ({:.1} ciphertexts/s)", 1000.0 * rate);
                }
                Act::CombineDecryptions(cfg_h, cnt, decryption_hs, mix_h, share_hs) => {
                    let cfg = board.get_config(cfg_h).unwrap();
                    info!(">> Action: Combining decryptions (contest=[{}], self=[{}])..", cnt, self_index.unwrap());
                    let now_ = std::time::Instant::now();
                    let d_hs = util::clear_zeroes(&decryption_hs);
                    let s_hs = util::clear_zeroes(&share_hs);
                    let pls = self.get_plaintexts(board, cnt, d_hs, mix_h, s_hs, &cfg, self_index.unwrap()).unwrap();
                    let rate = pls.plaintexts.len() as f32 / now_.elapsed().as_millis() as f32;
                    
                    let p_h = hashing::hash(&pls);
                    let ss = SignedStatement::plaintexts(&cfg_h, cnt, &p_h, &self.keypair);
                    let p_path = self.localstore.set_plaintexts(&action, pls, &ss);
                    board.set_plaintexts(&p_path, cnt);
                    
                    info!(">> OK ({:.1} ciphertexts/s)", 1000.0 * rate);
                }
                Act::CheckPlaintexts(cfg_h, cnt, plaintexts_h, decryption_hs, mix_h, share_hs) => {
                    let cfg = board.get_config(cfg_h).unwrap();
                    info!(">> Action: Checking plaintexts (contest=[{}], self=[{}])", cnt, self_index.unwrap());
                    let now_ = std::time::Instant::now();
                    let s_hs = util::clear_zeroes(&share_hs);
                    let d_hs = util::clear_zeroes(&decryption_hs);
                    let pls = self.get_plaintexts(board, cnt, d_hs, mix_h, s_hs, &cfg, self_index.unwrap()).unwrap();
                    let rate = pls.plaintexts.len() as f32 / now_.elapsed().as_millis() as f32;
                    let pls_board = board.get_plaintexts(cnt, plaintexts_h).unwrap();
                    assert!(pls.plaintexts == pls_board.plaintexts);
            
                    let ss = SignedStatement::plaintexts(&cfg_h, cnt, &plaintexts_h, &self.keypair);
                    let p_path = self.localstore.set_plaintexts_stmt(&action, &ss);
                    board.set_plaintexts_stmt(&p_path, cnt, self_index.unwrap());
                    info!(">> OK ({:.1} ciphertexts/s)", 1000.0 * rate);
                }
            }
        }
         
        info!(">>>> Trustee::run finished in [{}ms]", now.elapsed().as_millis());
        ret as u32
    }
    
    fn get_mix_src<B: BulletinBoard<A>>(&self, board: &B, contest: u32, mixing_trustee: u32, ballots_h: hashing::Hash, pk: &PublicKey<A::Context>) -> Vec<Ciphertext<A::Context, {A::W}>> where [(); A::W]: {

        if mixing_trustee == 0 {
            let ballots = board.get_ballots(contest, ballots_h).unwrap();
            
            let ciphertexts: Vec<Ciphertext<A::Context, {A::W}>> = ballots.ciphertexts.iter().map(|c| {
                let ok = c.proof.verify(&pk.pk_b, &pk.pk_a, &c.u_b, &c.v_b, &c.u_a);
                assert!(ok);
                elgamal::Ciphertext::<A::Context, {A::W}>::new(c.u_b.clone(),c.v_b.clone())
            }).collect();
            
            ciphertexts
        }
        else {
            let mix = board.get_mix(contest, mixing_trustee - 1, ballots_h).unwrap();
            mix.mixed_ballots
        }
    }
    
    fn share(&self) -> Keyshares<A> where [(); A::T]:, [(); A::P]: {
        let dealer = Dealer::generate();
        
        let shares = dealer.get_verifiable_shares();
        Keyshares { shares, phantom_a: PhantomData }
    }

    fn get_plaintexts<B: BulletinBoard<A>>(&self, board: &B, cnt: u32, hs: Vec<hashing::Hash>,
        mix_h: hashing::Hash, share_hs: Vec<hashing::Hash>, cfg: &Config<A>, self_index: u32) -> Option<Plaintexts<A>> where [(); A::W]:, [(); A::T]:, [(); A::P]: {
        
        assert!(hs.len() == share_hs.len());
        
        let last_trustee = cfg.trustees.len() - 1;
        let mix = board.get_mix(cnt, last_trustee as u32, mix_h).unwrap();
        let shares = board.get_shares(cnt, share_hs).unwrap();
        
        let recipients: [Recipient<A::Context, {A::T}, {A::P}>; {A::P}] = array::from_fn(move |i| {
            
            let position = (i + 1) as u32;
            let position = ParticipantPosition::new(position);
            
            let verifiable_shares: [VerifiableShare<A::Context, {A::T}>; {A::P}] = shares.clone().map(|v| {
                v.shares.for_participant(&position)
            });
            
            Recipient::new(position, verifiable_shares)
        });

        let verification_keys: [<A::Context as Context>::Element; {A::T}] =
            array::from_fn(|i| recipients[i].verification_key.clone());

        let dfs = array::from_fn(|i| {
            info!(">> Retrieving decryptions for trustee {}..", i);
            let df = board.get_decryption(cnt, i as u32, hs[i]).unwrap();
            df.pd_ballots
        });

        let ciphertexts: Vec<DkgCiphertext<A::Context, {A::W}, {A::T}>> = mix.mixed_ballots.iter()
                        .map(|c| DkgCiphertext(c.clone())).collect();
        let plaintexts = reconstruct(&ciphertexts, &dfs, &verification_keys, &vec![]);

        let plaintexts = plaintexts.into_iter().map(|p| Plaintext(p)).collect();
        
        let ret = Plaintexts { plaintexts, phantom_a: PhantomData };

        Some(ret)
    }

    fn get_pk<B: BulletinBoard<A>>(&self, board: &B, hs: Vec<hashing::Hash>, cnt: u32, self_index: u32) -> Option<PublicKey<A::Context>> where [(); A::T]:, [(); A::P]: {
        
        let shares = board.get_shares(cnt, hs).unwrap();

        let position = self_index + 1;
        let position = ParticipantPosition::new(position);
            
        let verifiable_shares: [VerifiableShare<A::Context, {A::T}>; {A::P}] = shares.clone().map(|v| {
            v.shares.for_participant(&position)
        });
            
        let recipient = Recipient::new(position, verifiable_shares);

        let pk = recipient.joint_pk.0.clone();
        
        let pk_a = A::Context::generator();
        let ret = PublicKey { pk_b: pk.y, pk_a };

        Some(ret)
    }
}