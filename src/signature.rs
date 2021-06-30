//MINTLAYER 2021
//BMARSH - ben at mintlayer dot org


/**
 * 
 * WARNING THIS CODE IS WIP AND HAS NOT BEEN AUDITED
 * 
 * 
 * no_std implementation of BLS sigs, sig aggregation and proof of ownership
 * 
 * Designed to be used with Mintlayer's substrate based core node but should be portable
 * 
 * The code is not constant time
 * 
 * BLS12-381
 * embedding degree 12 - 381 bit prime field
 * z = -0xd201000000010000
 * p = (z-1)^2(z^4-z^2+1)/3+z = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
 * q = z^4 - z^2 + 1 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
 * 
 * https://github.com/nccgroup/pairing-bls12381
 * 
 * 
 **/
use bls12_381_plus::{multi_miller_loop, ExpandMsgXmd, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar, pairing, Gt};
use core::ops::{BitOr, Neg, Not};
use ff::Field;
use group::{Curve, Group};
use subtle::{Choice, CtOption};
use hkdf::HkdfExtract;
use zeroize::Zeroize;

//todo clean this up
pub const SK_SIZE: usize = 32;//sk is 32 bytes
pub const SIG_BYTES: usize = 48;//sig is 48 bytes
pub const PK_BYTES: usize = 96;//pk is 96 bytes - there's a pattern here isn't there :)
pub const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
pub const CSUITE: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
pub const CSUITE_POP: &'static [u8] = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";


#[derive(Clone, Debug, Eq, PartialEq, Zeroize, Default)]//no copy
#[zeroize(drop)]//zeroize on drop automatically
pub struct Sk(pub Scalar);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Sig(pub(crate) G1Projective);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Pk(pub G2Projective);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MSig(pub(crate) G1Projective);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MPk(pub(crate) G2Projective);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SigAgr(pub(crate) G1Projective);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ProfOfPos(pub(crate) G1Projective);//prove ownership

//TODO get 32 rand bytes sk gen
//TODO defaults??

//secret key impl
//NOTE should NOT be shared or stored unsafely
//usage of sk should be checked by bm
impl Sk {
    // Get sk from random data
    pub fn from_rnd<B: AsRef<[u8]>>(rnd: B) -> Option<Self> {
        Self::gen_key(rnd.as_ref())
    }

    // turn sk to big end byte arr
    pub fn to_bytes(&self) -> [u8; SK_SIZE] {
        let mut bytes = self.0.to_bytes();
        bytes.reverse();//reverse byte order
        bytes
    }

    // turn big end byte arr to sk
    pub fn from_bytes(bytes: &[u8; SK_SIZE]) -> CtOption<Self> {
        let mut t = [0u8; SK_SIZE];
        t.clone_from_slice(bytes);
        t.reverse();
        Scalar::from_bytes(&t).map(Sk)
    }

    //get sk from 32 random bytes as per draft rfc
    //ikm passed to gen_key must be random
    //skr is random int 1 <= sk < r
    //TODO make fully compliant
    pub fn gen_key(ikm: &[u8]) -> Option<Sk> {

        //todo check ikm is >= 32 bytes

        const INFO: [u8; 2] = [0u8, 48u8];//empty string

        //use hkdf rfc5869 for key expansion
        let mut hkdfkg = HkdfExtract::<sha2::Sha256>::new(Some(SALT));
        //feed ikm to hkdf-extract
        hkdfkg.input_ikm(ikm);
        hkdfkg.input_ikm(&[0]);//Algorand does this in their ref
        //retunrs rnd key + kkdf
        let (_, hkdfout) = hkdfkg.finalize();

        let mut okm = [0u8; 48];
        if hkdfout.expand(&INFO, &mut okm).is_ok() {
            Some(Sk(Scalar::from_okm(&okm)))
        } else {
            None//uh-oh
        }
    }  
}

//impl of the actual signature
impl Sig {
    //BLS sig
    pub fn new<B: AsRef<[u8]>>(sk: &Sk, msg: B) -> Option<Self> {
        if sk.0.is_zero() {
            return None;
        }
        let a = Self::hash_msg(msg.as_ref());
        Some(Self(a * sk.0))
    }

    pub(crate) fn hash_msg(msg: &[u8]) -> G1Projective {
        // elem of g1 in proj coord space
        G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, CSUITE)
    }

    //is the sig valid?
    pub fn is_valid(&self) -> Choice {
        self.0.is_identity().not().bitor(self.0.is_on_curve())
    }

    // verify sig via pk
    pub fn verify<B: AsRef<[u8]>>(&self, pk: Pk, msg: B) -> Choice {
        if pk.0.is_identity().bitor(self.is_valid()).unwrap_u8() == 0 {//sig is invalid
            return Choice::from(0);
        }
        let a = Self::hash_msg(msg.as_ref());
        //g2 elm in affine coord space - in q order subgrp
        let g2 = G2Affine::generator().neg();

        //series (a1,b1)...(an,bn)
        multi_miller_loop(&[
            (&a.to_affine(), &G2Prepared::from(pk.0.to_affine())),
            (&self.0.to_affine(), &G2Prepared::from(g2)),
        ])
        .final_exponentiation()
        .is_identity()
    }

    // to bytes from sig
    pub fn to_bytes(&self) -> [u8; SIG_BYTES] {
        self.0.to_affine().to_compressed()
    }

    // to sig from bytes
    pub fn from_bytes(bytes: &[u8; SIG_BYTES]) -> CtOption<Self> {
        //affine repr of elem in g1
        G1Affine::from_compressed(&bytes).map(|p| Self(G1Projective::from(&p)))
    }
}

//public key - created from a sk
impl Pk {
    //pk valid?
    pub fn is_valid(&self) -> Choice {
        self.0.is_identity().not().bitor(self.0.is_on_curve())
    }

    //pk to bytes
    pub fn to_bytes(&self) -> [u8; PK_BYTES] {
        self.0.to_affine().to_compressed()
    }

    // pk from bytes
    pub fn from_bytes(bytes: &[u8; PK_BYTES]) -> CtOption<Self> {
        //attempt to deserialize from compressed bytes from g2 elem
        G2Affine::from_compressed(bytes).map(|p| Self(G2Projective::from(&p)))
    }
}

//proof of ownership of sk
impl ProfOfPos {
    pub fn new(sk: &Sk) -> Option<Self> {
        if sk.0.is_zero() {
            return None;
        }
        let pk = Pk::from(sk);
        //g1proj in proj coord space
        let a = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&pk.to_bytes(), CSUITE_POP);
        Some(Self(a * sk.0))
    }

    //verify proof for pk
    pub fn verify(&self, pk: Pk) -> Choice {
        if pk.0.is_identity().unwrap_u8() == 1 {
            return Choice::from(0);
        }
        //gqproj from elpitical curve hash
        let a = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&pk.to_bytes(), CSUITE_POP);
        //fixed generator for group
        //group chosen accorsding to https://docs.rs/bls12_381/0.1.1/bls12_381/notes/design/index.html#fixed-generators
        let g2 = G2Affine::generator().neg();

        //series (a1,b1)...(an,bn)
        multi_miller_loop(&[
            (&a.to_affine(), &G2Prepared::from(pk.0.to_affine())),
            (&self.0.to_affine(), &G2Prepared::from(g2)),
        ])
        .final_exponentiation()
        .is_identity()//final_expon converts result to Gt elem using cyclotomic subgroup Fq6
    }

    // proof as bytes
    pub fn to_bytes(&self) -> [u8; SIG_BYTES] {
        self.0.to_affine().to_compressed()
    }

    // proof from bytes
    pub fn from_bytes(bytes: &[u8; SIG_BYTES]) -> CtOption<Self> {
        let mut t = [0u8; SIG_BYTES];
        t.clone_from_slice(bytes);
        G1Affine::from_compressed(&t).map(|p| Self(G1Projective::from(&p)))
    }
}

//multisig
impl MSig {
    pub fn is_valid(&self) -> Choice {
        self.0.is_identity().not().bitor(self.0.is_on_curve())
    }

    pub fn verify<B: AsRef<[u8]>>(&self, public_key: MPk, msg: B) -> Choice {
        Sig(self.0).verify(Pk(public_key.0), msg)
    }

    pub fn to_bytes(&self) -> [u8; SIG_BYTES] {
        self.0.to_affine().to_compressed()
    }

    pub fn from_bytes(bytes: &[u8; SIG_BYTES]) -> CtOption<Self> {
        let mut t = [0u8; SIG_BYTES];
        t.clone_from_slice(bytes);
        G1Affine::from_compressed(&t).map(|p| Self(G1Projective::from(&p)))
    }
}

//multi public key
impl MPk {
    pub fn is_valid(&self) -> Choice {
        self.0.is_identity().not().bitor(self.0.is_on_curve())
    }

    pub fn to_bytes(&self) -> [u8; PK_BYTES] {
        self.0.to_affine().to_compressed()
    }

    pub fn from_bytes(bytes: &[u8; PK_BYTES]) -> CtOption<Self> {
        let mut t = [0u8; PK_BYTES];
        t.clone_from_slice(bytes);
        G2Affine::from_compressed(&t).map(|p| Self(G2Projective::from(&p)))
    }
}

//signature aggr
impl SigAgr {
    //check if it's a valid pk
    pub fn is_valid(&self) -> Choice {
        self.0.is_identity().not().bitor(self.0.is_on_curve())
    }

    pub fn verify<B: AsRef<[u8]>>(&self, pk_msg_pair: &[(Pk, B)]) -> Choice {
        if self.is_valid().unwrap_u8() == 0 {
            return Choice::from(0u8);
        }

        fn verify_aggr_sig<B: AsRef<[u8]>>(
            sig: &G1Projective,
            pk_msg_pair: &[(Pk, B)],
        ) -> Choice {
            //Gt arithmetic group??
            //FIXME??
            let mut res = Gt::identity();
            //loop through pk,msg pairs and check 'em
            for (key, msg) in pk_msg_pair {
                //key isn't valid so we quit
                if key.is_valid().unwrap_u8() == 0 {
                    return Choice::from(0u8);
                }
                let a = Sig::hash_msg(msg.as_ref());
                res += pairing(&a.to_affine(), &key.0.to_affine());
            }
            res += pairing(&sig.to_affine(), &G2Affine::generator().neg());
            res.is_identity()
        }
        verify_aggr_sig(&self.0, pk_msg_pair)
    }

    //make me bytes
    pub fn to_bytes(&self) -> [u8; SIG_BYTES] {
        self.0.to_affine().to_compressed()
    }
    //get me from bytes
    pub fn from_bytes(bytes: &[u8; SIG_BYTES]) -> CtOption<Self> {
        let mut t = [0u8; SIG_BYTES];
        t.clone_from_slice(bytes);
        G1Affine::from_compressed(&t).map(|p| Self(G1Projective::from(&p)))
    }
}

//convert sk to bytes
impl From<Sk> for [u8; SK_SIZE] {
    fn from(sk: Sk) -> [u8; SK_SIZE] {
        sk.to_bytes()
    }
}

//get pk from sk
impl From<&Sk> for Pk {
    fn from(s: &Sk) -> Self {
        Self(G2Projective::generator() * s.0)
    }
}

//get multisig from sigs
impl From<&[Sig]> for MSig {
    fn from(sigs: &[Sig]) -> Self {
        let mut g = G1Projective::identity();
        for s in sigs {
            g += s.0;
        }
        Self(g)
    }
}

impl From<&[Pk]> for MPk {
    fn from(keys: &[Pk]) -> Self {
        let mut g = G2Projective::identity();
        for k in keys {
            g += k.0;
        }
        Self(g)
    }
}

//get aggregated sig from sigs
impl From<&[Sig]> for SigAgr {
    fn from(sigs: &[Sig]) -> Self {
        let mut g = G1Projective::identity();
        for s in sigs {
            g += s.0;
        }
        Self(g)
    }
}
