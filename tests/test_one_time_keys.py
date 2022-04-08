"""
We test the lattice-crypto.keys.one_time_keys module.
"""
import pytest
from lattice_algebra import is_ntt_friendly_prime
from lattice_crypto.one_time_keys import *
from secrets import randbits
from typing import List

SAMPLE_SIZE: int = 2 ** 0

MIN_LOG2D: int = 5
MAX_LOG2D: int = 7
SOME_LOG2D: List[int] = list(range(MIN_LOG2D, MAX_LOG2D+1))

MAX_Q: int = 2**(MAX_LOG2D+1)

SOME_NTT_FRIENDLY_PAIRS = [(2**log2d, q) for log2d in SOME_LOG2D for q in range(2**(log2d+1)+1, MAX_Q, 2**(log2d+1)) if is_ntt_friendly_prime(modulus=q, degree=2**log2d)]

MIN_LEN: int = 1
MAX_LEN: int = 2**2
SOME_LEN: List[int] = list(range(MIN_LEN, MAX_LEN))

SECRET_SEED_INIT_CASES = []


for secpar in ALLOWABLE_SECPARS:
    for (d, q) in SOME_NTT_FRIENDLY_PAIRS:
        for l in SOME_LEN:
            for _ in range(SAMPLE_SIZE):
                lp: LatticeParameters = LatticeParameters(modulus=q, degree=d, length=l)
                seed = bin(randbits(secpar))[2:].zfill(secpar)
                SECRET_SEED_INIT_CASES += [(secpar, lp, seed, SecretSeed(secpar=secpar, lp=lp, seed=seed)) ]


@pytest.mark.parametrize("secpar,lp,seed,secret_seed", SECRET_SEED_INIT_CASES)
def test_secret_seed_init(secpar, lp, seed, secret_seed):
    assert secret_seed.secpar == secpar
    assert secret_seed.lp == lp
    assert secret_seed.seed == seed


@pytest.mark.parametrize("secpar,lp,seed,secret_seed", SECRET_SEED_INIT_CASES)
def test_secret_seed_eq(secpar, lp, seed, secret_seed):
    assert SecretSeed(secpar=secpar, lp=lp, seed=seed) == secret_seed


DISTRIBUTION: str = UNIFORM_INFINITY_WEIGHT

BD_MIN: int = 1
BD_MAX: int = 2**1
SOME_BDS: List[int] = list(range(BD_MIN, BD_MAX+1))

WT_MIN: int = 1
WT_MAX: int = 2**1
SOME_WTS: List[int] = list(range(WT_MIN, WT_MAX + 1))

ONE_TIME_SECRET_WITNESS_CASES = [
    i + tuple([bd, wt,
        OneTimeSecretWitness(
            secpar=i[0],
            lp=i[1],
            key=random_polynomialvector(
                secpar=i[0],
                lp=i[1],
                distribution=DISTRIBUTION,
                dist_pars={'bd': bd, 'wt': wt},
                num_coefs=wt,
                bti=bits_to_indices(secpar=i[0], degree=i[1].degree, wt=wt),
                btd=bits_to_decode(secpar=i[0], bd=bd),
                const_time_flag=False,
            ))
    ]) for i in SECRET_SEED_INIT_CASES for bd in SOME_BDS for wt in SOME_WTS
]


@pytest.mark.parametrize("secpar,lp,seed,secret_seed,bd,wt,wit", ONE_TIME_SECRET_WITNESS_CASES)
def test_one_time_secret_witness_init(secpar, lp, seed, secret_seed, bd, wt, wit):
    assert isinstance(wit, OneTimeSecretWitness)
    assert wit.secpar == secret_seed.secpar == secpar
    assert wit.lp == secret_seed.lp == lp
    assert isinstance(wit.key, PolynomialVector)
    assert all(k.const_time_flag for k in wit.key.entries)
    cnw = wit.key.get_coef_rep()
    n, w = max(i[1] for i in cnw), max(i[2] for i in cnw)
    assert n <= bd
    assert w <= wt


@pytest.mark.parametrize("secpar,lp,seed,secret_seed,bd,wt,wit", ONE_TIME_SECRET_WITNESS_CASES)
def test_one_time_secret_witness_eq(secpar, lp, seed, secret_seed, bd, wt, wit):
    assert OneTimeSecretWitness(secpar=secpar, lp=lp, key=wit.key) == wit


KEY_CHALLENGES = [
    i + tuple([
        random_polynomialvector(
            secpar=i[0],
            lp=i[1],
            distribution=DISTRIBUTION,
            dist_pars={'bd': i[1].modulus//2, 'wt': i[1].degree},
            num_coefs=i[1].degree,
            bti=bits_to_indices(
                secpar=i[0],
                degree=i[1].degree,
                wt=i[1].degree),
            btd=bits_to_decode(
                secpar=i[0],
                bd=i[1].modulus//2),
            const_time_flag=False)
    ]) for i in ONE_TIME_SECRET_WITNESS_CASES
]
ONE_TIME_PUBSTAT_CASES = [i + tuple([OneTimePublicStatement(secpar=i[0], lp=i[1], key=i[-1] * i[-2].key)]) for i in KEY_CHALLENGES]


@pytest.mark.parametrize("secpar,lp,seed,secret_seed,bd,wt,wit,key_ch,stat", ONE_TIME_PUBSTAT_CASES)
def test_one_time_pubstat_init(secpar, lp, seed, secret_seed, bd, wt, wit, key_ch, stat):
    assert isinstance(key_ch, PolynomialVector)
    assert isinstance(stat, OneTimePublicStatement)
    assert stat.secpar == secpar
    assert stat.lp == lp
    assert isinstance(stat.key, Polynomial)
    assert key_ch * wit.key == stat.key

@pytest.mark.parametrize("secpar,lp,seed,secret_seed,bd,wt,wit,key_ch,stat", ONE_TIME_PUBSTAT_CASES)
def test_one_time_pubstat_eq(secpar, lp, seed, secret_seed, bd, wt, wit, key_ch, stat):
    assert stat == OneTimePublicStatement(secpar=secpar, lp=lp, key=key_ch * wit.key)

ONE_TIME_SIGNING_KEY_CASES = [i + tuple([
    bd,
    wt,
    random_polynomialvector(
        secpar=i[0],
        lp=i[1],
        distribution=DISTRIBUTION,
        dist_pars={'bd': i[1].modulus//2, 'wt': i[1].degree},
        num_coefs=i[1].degree,
        bti=bits_to_indices(
            secpar=i[0],
            degree=i[1].degree,
            wt=i[1].degree),
        btd=bits_to_decode(
            secpar=i[0],
            bd=i[1].modulus//2),
        const_time_flag=False),
    random_polynomialvector(
        secpar=i[0],
        lp=i[1],
        distribution=DISTRIBUTION,
        dist_pars={'bd': i[1].modulus // 2, 'wt': i[1].degree},
        num_coefs=i[1].degree,
        bti=bits_to_indices(
            secpar=i[0],
            degree=i[1].degree,
            wt=i[1].degree),
        btd=bits_to_decode(
            secpar=i[0],
            bd=i[1].modulus // 2),
        const_time_flag=False),
]) for i in ONE_TIME_PUBSTAT_CASES for bd in SOME_BDS for wt in SOME_WTS]

ONE_TIME_SIGNING_KEY_CASES = [i + tuple([
    OneTimeSigningKey(
        secpar=i[0],
        lp=i[1],
        left_key=i[-2],
        right_key=i[-1]
    )
]) for i in ONE_TIME_SIGNING_KEY_CASES]


@pytest.mark.parametrize("secpar,lp,seed,secret_seed,wit_bd,wit_wt,wit,key_ch,stat,sk_bd,sk_wt,left_sk,right_sk,sk", ONE_TIME_SIGNING_KEY_CASES)
def test_one_time_signing_key_init(secpar, lp, seed, secret_seed, wit_bd, wit_wt, wit, key_ch, stat, sk_bd, sk_wt, left_sk, right_sk, sk):
    assert isinstance(sk, OneTimeSigningKey)
    assert sk.secpar == secpar
    assert sk.lp == lp
    assert sk.left_key == left_sk
    assert sk.right_key == right_sk


@pytest.mark.parametrize("secpar,lp,seed,secret_seed,wit_bd,wit_wt,wit,key_ch,stat,sk_bd,sk_wt,left_sk,right_sk,sk", ONE_TIME_SIGNING_KEY_CASES)
def test_one_time_signing_key_eq(secpar, lp, seed, secret_seed, wit_bd, wit_wt, wit, key_ch, stat, sk_bd, sk_wt, left_sk, right_sk, sk):
    x = OneTimeSigningKey(secpar=secpar, lp=lp, left_key=left_sk, right_key=right_sk)
    assert x == sk

VERIFICATION_KEY_CASES = [
    i + tuple([
        i[-7] * i[-1].left_key,
        i[-7] * i[-1].right_key
    ]) for i in ONE_TIME_SIGNING_KEY_CASES
]

VERIFICATION_KEY_CASES = [
    i + tuple([
        OneTimeVerificationKey(
            secpar=i[0],
            lp=i[1],
            left_key=i[-2],
            right_key=i[-1]
        )
    ]) for i in VERIFICATION_KEY_CASES
]


@pytest.mark.parametrize("secpar,lp,seed,secret_seed,wit_bd,wit_wt,wit,key_ch,stat,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk", VERIFICATION_KEY_CASES)
def test_one_time_vf_key_init(secpar, lp, seed, secret_seed, wit_bd, wit_wt, wit, key_ch, stat, sk_bd, sk_wt, left_sk, right_sk, sk, left_vk, right_vk, vk):
    assert isinstance(vk, OneTimeVerificationKey)
    assert vk.secpar == secpar
    assert vk.lp == lp
    assert vk.left_key == left_vk
    assert vk.right_key == right_vk
    assert vk.left_key == key_ch * left_sk
    assert vk.right_key == key_ch * right_sk


@pytest.mark.parametrize("secpar,lp,seed,secret_seed,wit_bd,wit_wt,wit,key_ch,stat,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk", VERIFICATION_KEY_CASES)
def test_one_time_vf_key_getitem(secpar, lp, seed, secret_seed, wit_bd, wit_wt, wit, key_ch, stat, sk_bd, sk_wt, left_sk, right_sk, sk, left_vk, right_vk, vk):
    assert vk[0] == left_vk == vk.left_key
    assert vk[1] == right_vk == vk.right_key


@pytest.mark.parametrize("secpar,lp,seed,secret_seed,wit_bd,wit_wt,wit,key_ch,stat,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk", VERIFICATION_KEY_CASES)
def test_one_time_vf_key_eq(secpar, lp, seed, secret_seed, wit_bd, wit_wt, wit, key_ch, stat, sk_bd, sk_wt, left_sk, right_sk, sk, left_vk, right_vk, vk):
    assert vk == OneTimeVerificationKey(secpar=secpar, lp=lp, left_key=left_vk, right_key=right_vk)


SCHEME_PARAMETERS_CASES = [
    i + tuple([UNIFORM_INFINITY_WEIGHT]) for i in VERIFICATION_KEY_CASES
]


@pytest.mark.parametrize("secpar,lp,seed,secret_seed,wit_bd,wit_wt,wit,key_ch,stat,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk,distn", SCHEME_PARAMETERS_CASES)
def test_schemeparameters_init(mocker, secpar, lp, seed, secret_seed, wit_bd, wit_wt, wit, key_ch, stat, sk_bd, sk_wt, left_sk, right_sk, sk, left_vk, right_vk, vk, distn):
    mocker.patch('lattice_crypto.one_time_keys.random_polynomialvector', return_value=key_ch)
    sp = SchemeParameters(secpar=secpar, lp=lp, distribution=distn, key_ch=None)
    assert sp.secpar == secpar
    assert sp.lp == lp
    assert sp.distribution == distn
    assert sp.key_ch == key_ch
