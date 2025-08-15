use std::fmt;

use crate::util::{short, shortm};
use crate::protocol::*;

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum Act {
    CheckConfig(ConfigHash),
    PostShare(ConfigHash, ContestIndex),
    CombineShares(ConfigHash, ContestIndex, Hashes),
    CheckPk(ConfigHash, ContestIndex, PkHash, Hashes),
    Mix(ConfigHash, ContestIndex, BallotsHash, PkHash),
    CheckMix(ConfigHash, ContestIndex, TrusteeIndex, MixHash, BallotsHash, PkHash),
    PartialDecrypt(ConfigHash, ContestIndex, BallotsHash, Hashes),
    CombineDecryptions(ConfigHash, ContestIndex, Hashes, MixHash, Hashes),
    CheckPlaintexts(ConfigHash, ContestIndex, PlaintextsHash, Hashes, MixHash, Hashes)
}

impl fmt::Debug for Act {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Act::CheckConfig(cfg) => write!(f, "CheckConfig {:?}", short(cfg)),
            Act::PostShare(cfg, cnt) => write!(f, "PostShare cn=[{}] cfg: {:?}", cnt, short(cfg)),
            Act::CombineShares(_cfg, cnt, hs) => write!(f, "CombineShares cn=[{}] shares: {:?}", cnt, shortm(hs)),
            Act::CheckPk(_cfg, cnt, h1, hs) => write!(f, "CheckPk cn=[{}], pk {:?} shares: {:?}", cnt, short(h1), shortm(hs)),
            Act::Mix(cfg, cnt, _bh, _pk_h) => write!(f, "Mix cn=[{}] cfg: {:?}", cnt, short(cfg)),
            Act::CheckMix(_cfg, cnt, t, mh, _bh, _pk_h) => write!(f, "CheckMix cn=[{}] mix={:?} posted by tr=[{}]", cnt, short(mh), t),
            Act::PartialDecrypt(cfg, cnt, _h1, _share_h) => write!(f, "PartialDecrypt cn=[{}] cfg: {:?}", cnt, short(cfg)),
            Act::CombineDecryptions(cfg, cnt, _hs, _mix_h, _share_hs) => write!(f, "CombineDecryptions cn=[{}] cfg: {:?}", cnt, short(cfg)),
            Act::CheckPlaintexts(cfg, cnt, _p_h, _d_hs, _mix_h, _share_hs) => write!(f, "CheckPlaintexts cn=[{}] cfg: {:?}", cnt, short(cfg))
        }
    }
}
