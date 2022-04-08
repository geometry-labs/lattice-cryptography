"""
We test the lattice-crypto.lm_one_time_sigs module.
"""
import pytest
from lattice_algebra import random_polynomialvector, random_polynomial
from lattice_crypto.one_time_keys import ALLOWABLE_SECPARS, SecretSeed, OneTimeSigningKey, OneTimeVerificationKey, SchemeParameters, bits_to_decode, bits_to_indices
from lattice_crypto.lm_one_time_sigs import PublicParameters, Message, Challenge, Signature, OneTimeKeyTuple, make_setup_parameters, make_one_key, keygen, make_signature_challenge, sign, verify, LPs, SALTs, BDs, WTs, DISTRIBUTION, make_random_seed
from secrets import randbits
from typing import Any, Dict, List

SAMPLE_SIZE: int = 2 ** 0
REQUIRED_SETUP_PARAMETERS = ['scheme_parameters', 'sk_bd', 'sk_wt', 'sk_salt', 'ch_bd', 'ch_wt', 'ch_salt', 'vf_bd', 'vf_wt']
BOUND_NAMES = ['sk_bd', 'ch_bd', 'vf_bd']
WEIGHT_NAMES = ['sk_wt', 'ch_wt', 'vf_wt']
SALT_NAMES = ['sk_salt', 'ch_salt']

# i = 0 : secpar
# i = 1 : sp
# i = 2 : pp
# i = 3 : a random integer for use as a seed
# i = 4 : integer as a binary string
# i = 5 : SecretSeed
# i = 6 : sk_bd
# i = 7 : sk_wt
# i = 8 : left_sk
# i = 9 : right_sk
# i = 10 : sk
# i = 11: left_vk
# i = 12: right_vk
# i = 13: vk
# i = 14 : ch_bd
# i = 15 : ch_wt
# i = 16 : msg
# i = 17 : mocked sig_ch
# i = 18: expected_sig
# i = 19: expected vf bit
MAKE_SCHEME_PARAMETERS_CASES = [(
    secpar,
    SchemeParameters(secpar=secpar, lp=LPs[secpar], distribution=DISTRIBUTION)
) for secpar in ALLOWABLE_SECPARS]
MAKE_SETUP_PARAMETERS_CASES = [
    i + tuple([{
        'scheme_parameters': i[-1],
        'sk_salt': SALTs[i[0]]['sk_salt'],
        'sk_bd': BDs[i[0]]['sk_bd'],
        'sk_wt': WTs[i[0]]['sk_wt'],
        'ch_salt': SALTs[i[0]]['ch_salt'],
        'ch_bd': BDs[i[0]]['ch_bd'],
        'ch_wt': WTs[i[0]]['ch_wt'],
        'vf_bd': max(1, min(
            i[-1].lp.modulus // 2,
            BDs[i[0]]['sk_bd'] * (1 + min(WTs[i[0]]['sk_wt'], WTs[i[0]]['ch_wt']) * BDs[i[0]]['ch_bd']))),
        'vf_wt': max(1, min(i[-1].lp.degree, WTs[i[0]]['sk_wt'] * (1 + WTs[i[0]]['ch_wt']))),
    }]) for i in MAKE_SCHEME_PARAMETERS_CASES
]


@pytest.mark.parametrize("secpar,sp,expected_pp", MAKE_SETUP_PARAMETERS_CASES)
def test_make_setup_parameters(mocker, secpar, sp, expected_pp):
    mocker.patch('lattice_crypto.one_time_keys.random_polynomialvector', return_value=sp.key_ch)
    assert expected_pp == make_setup_parameters(secpar)

MAKE_RANDOM_SEED_CASES = [
    i + tuple([j, bin(j)[2:].zfill(i[0])]) for i in MAKE_SETUP_PARAMETERS_CASES for j in range(2*SAMPLE_SIZE+1)
]
MAKE_RANDOM_SEED_CASES = [
    i + tuple([SecretSeed(secpar=i[0], lp=i[1].lp, seed=i[-1])]) for i in MAKE_RANDOM_SEED_CASES
]


@pytest.mark.parametrize("secpar,sp,pp,expected_int,expected_str,expected_seed", MAKE_RANDOM_SEED_CASES)
def test_make_random_seed(mocker, secpar, sp, pp, expected_int, expected_str, expected_seed):
    mocker.patch('lattice_crypto.lm_one_time_sigs.randbelow', return_value=expected_int)
    observed_seed = make_random_seed(secpar=secpar, pp=pp)
    assert observed_seed == expected_seed
    assert observed_seed.seed == expected_str


BD_MIN: int = 1
BD_MAX: int = 2**1
SOME_BDS: List[int] = list(range(BD_MIN, BD_MAX+1))

WT_MIN: int = 1
WT_MAX: int = 2**1
SOME_WTS: List[int] = list(range(WT_MIN, WT_MAX + 1))

MAKE_ONE_KEY_CASES = [i + tuple([
    sk_bd,
    sk_wt,
    random_polynomialvector(
        secpar=i[0],
        lp=i[1].lp,
        distribution=DISTRIBUTION,
        dist_pars={'bd': sk_bd, 'wt': sk_wt},
        num_coefs=sk_wt,
        bti=bits_to_indices(
            secpar=i[0],
            degree=i[1].lp.degree,
            wt=sk_wt),
        btd=bits_to_decode(
            secpar=i[0],
            bd=sk_bd),
        const_time_flag=False),
    random_polynomialvector(
        secpar=i[0],
        lp=i[1].lp,
        distribution=DISTRIBUTION,
        dist_pars={'bd': sk_bd, 'wt': sk_wt},
        num_coefs=sk_wt,
        bti=bits_to_indices(
            secpar=i[0],
            degree=i[1].lp.degree,
            wt=sk_wt),
        btd=bits_to_decode(
            secpar=i[0],
            bd=sk_bd),
        const_time_flag=False),
]) for i in MAKE_RANDOM_SEED_CASES for sk_bd in SOME_BDS for sk_wt in SOME_WTS]

for i in MAKE_ONE_KEY_CASES:
    i[8].const_time_flag = False
    i[9].const_time_flag = False


MAKE_ONE_KEY_CASES = [i + tuple([
    OneTimeSigningKey(
        secpar=i[0],
        lp=i[1].lp,
        left_key=i[-2],
        right_key=i[-1]
    )
]) for i in MAKE_ONE_KEY_CASES]

for i in MAKE_ONE_KEY_CASES:
    i[-1][0].const_time_flag = False
    i[-1][1].const_time_flag = False


MAKE_ONE_KEY_CASES = [i + tuple([
    i[1].key_ch * i[-3],
    i[1].key_ch * i[-2]
]) for i in MAKE_ONE_KEY_CASES]

MAKE_ONE_KEY_CASES = [i + tuple([
    OneTimeVerificationKey(secpar=i[0], lp=i[1].lp, left_key=i[-2], right_key=i[-1])
]) for i in MAKE_ONE_KEY_CASES]

for i in MAKE_ONE_KEY_CASES:
    i[-1][0].const_time_flag = False
    i[-1][1].const_time_flag = False


@pytest.mark.parametrize("secpar,sp,pp,j,seed,secret_seed,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk", MAKE_ONE_KEY_CASES)
def test_make_one_key(mocker, secpar, sp, pp: Dict[str, Any], j, seed, secret_seed, sk_bd, sk_wt, left_sk, right_sk, sk, left_vk, right_vk, vk):
    mocker.patch('lattice_crypto.lm_one_time_sigs.make_random_seed', return_value=secret_seed)
    mocker.patch('lattice_crypto.lm_one_time_sigs.hash2polynomialvector', side_effect=[left_sk, right_sk])

    observed_key_tuple = make_one_key(pp=pp)
    observed_seed, observed_sk, observed_vk = observed_key_tuple
    assert observed_seed == secret_seed
    assert observed_sk == sk
    assert sk[0] == left_sk
    assert sk[1] == right_sk
    assert observed_sk[0].const_time_flag
    assert observed_sk[1].const_time_flag

    assert not observed_vk[0].const_time_flag
    assert not observed_vk[1].const_time_flag
    assert observed_vk.left_key == pp['scheme_parameters'].key_ch * sk.left_key
    assert observed_vk.right_key == pp['scheme_parameters'].key_ch * sk.right_key

    assert vk == OneTimeVerificationKey(secpar=secpar, lp=pp['scheme_parameters'].lp, left_key=pp['scheme_parameters'].key_ch * sk.left_key, right_key=pp['scheme_parameters'].key_ch * sk.right_key)
    cnw = sk[0].get_coef_rep() + sk[1].get_coef_rep()
    n, w = max(i[1] for i in cnw), max(i[2] for i in cnw)
    assert 1 <= n <= pp['sk_bd']
    assert 1 <= w <= pp['sk_wt']


@pytest.mark.parametrize("secpar,sp,pp,j,seed,secret_seed,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk", MAKE_ONE_KEY_CASES)
def test_keygen(mocker, secpar, sp, pp: Dict[str, Any], j, seed, secret_seed, sk_bd, sk_wt, left_sk, right_sk, sk, left_vk, right_vk, vk):
    mocker.patch('lattice_crypto.lm_one_time_sigs.make_one_key', return_value=(secret_seed, sk, vk))
    key_tuples = keygen(pp=pp, num_keys_to_gen=1, seeds=[secret_seed])
    assert isinstance(key_tuples, list)
    assert len(key_tuples) == 1
    for next_key_tuple in key_tuples:
        assert isinstance(next_key_tuple, tuple)
        assert next_key_tuple[0] == secret_seed
        assert next_key_tuple[1] == sk
        assert next_key_tuple[2] == vk
        assert sp.key_ch == pp['scheme_parameters'].key_ch
        assert sp.key_ch * next_key_tuple[1][0] == vk[0] == vk.left_key
        assert sp.key_ch * next_key_tuple[1][1] == vk[1] == vk.right_key


MAKE_SIGNATURE_CHALLENGE_CASES = []
for i in MAKE_ONE_KEY_CASES:
    for ch_bd in SOME_BDS:
        for ch_wt in SOME_WTS:
            MAKE_SIGNATURE_CHALLENGE_CASES += [
                i + tuple([
                    ch_bd,
                    ch_wt,
                    bin(randbits(i[0]))[2:].zfill(i[0]),
                    random_polynomial(
                        secpar=i[0],
                        lp=i[1].lp,
                        distribution=DISTRIBUTION,
                        dist_pars={'bd': ch_bd, 'wt': ch_wt},
                        num_coefs=ch_wt,
                        bti=bits_to_indices(
                            secpar=i[0],
                            degree=i[1].lp.degree,
                            wt=ch_wt),
                        btd=bits_to_decode(
                            secpar=i[0],
                            bd=ch_bd),
                        const_time_flag=False)])]
for i in MAKE_SIGNATURE_CHALLENGE_CASES:
    i[-1].const_time_flag = False


for i in MAKE_SIGNATURE_CHALLENGE_CASES:
    assert not i[8].const_time_flag
    assert not i[9].const_time_flag
    assert not i[10][0].const_time_flag
    assert not i[10][1].const_time_flag
    assert not i[10].left_key.const_time_flag
    assert not i[10].right_key.const_time_flag
    assert not i[11].const_time_flag
    assert not i[12].const_time_flag
    assert not i[13][0].const_time_flag
    assert not i[13][1].const_time_flag
    assert not i[13].left_key.const_time_flag
    assert not i[13].right_key.const_time_flag
    assert not i[17].const_time_flag


@pytest.mark.parametrize("secpar,sp,pp,j,seed,secret_seed,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk,ch_bd,ch_wt,msg,sig_ch", MAKE_SIGNATURE_CHALLENGE_CASES)
def test_make_signature_challenge(mocker, secpar, sp, pp, j, seed, secret_seed, sk_bd, sk_wt, left_sk, right_sk, sk, left_vk, right_vk, vk, ch_bd, ch_wt, msg, sig_ch):
    mocker.patch('lattice_crypto.lm_one_time_sigs.hash2polynomial', return_value=sig_ch)
    assert make_signature_challenge(pp=pp, otvk=vk, msg=msg) == sig_ch


MAKE_SIGN_CASES = [
    i + tuple([
        i[8] ** i[-1] + i[9],
        True,
        i[10][0] ** i[-1] + i[10][1],
        True
    ]) for i in MAKE_SIGNATURE_CHALLENGE_CASES
]


# i = 0 : secpar
# i = 1 : sp
# i = 2 : pp
# i = 3 : a random integer for use as a seed
# i = 4 : integer as a binary string
# i = 5 : SecretSeed
# i = 6 : sk_bd
# i = 7 : sk_wt
# i = 8 : left_sk
# i = 9 : right_sk
# i = 10 : sk
# i = 11: left_vk
# i = 12: right_vk
# i = 13: vk
# i = 14 : ch_bd
# i = 15 : ch_wt
# i = 16 : msg
# i = 17 : mocked sig_ch
# i = 18: expected_sig
# i = 19: expected vf bit
# i = 20: expected_sig
# i = 21: expected vf bit
@pytest.mark.parametrize("secpar,sp,pp,j,seed,secret_seed,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk,ch_bd,ch_wt,msg,sig_ch,expected_sig_a,expected_valid_a,expected_sig_b,expected_valid_b", MAKE_SIGN_CASES)
def test_sign(mocker, secpar, sp, pp, j, seed, secret_seed, sk_bd, sk_wt, left_sk, right_sk, sk, left_vk, right_vk, vk, ch_bd, ch_wt, msg, sig_ch, expected_sig_a, expected_valid_a, expected_sig_b, expected_valid_b):
    mocker.patch('lattice_crypto.lm_one_time_sigs.make_signature_challenge', return_value=sig_ch)
    sig_ch.const_time_flag = False
    sk[0].const_time_flag = False
    sk[1].const_time_flag = False
    sp.key_ch.const_time_flag = False
    observed_sig = sign(pp=pp, otk=(secret_seed, sk, vk), msg=msg)
    assert observed_sig == sk[0] ** sig_ch + sk[1] == expected_sig_a == expected_sig_b
    assert sp.key_ch == pp['scheme_parameters'].key_ch
    assert sp.key_ch * sk[0] == sp.key_ch * sk.left_key == vk[0] == vk.left_key
    assert sp.key_ch * sk[1] == sp.key_ch * sk.right_key == vk[1] == vk.right_key
    assert sp.key_ch * observed_sig == vk[0] * sig_ch + vk[1]
    cnw = observed_sig.get_coef_rep()
    n, w = max(i[1] for i in cnw), max(i[2] for i in cnw)
    assert 1 <= n <= pp['vf_bd']
    assert 1 <= w <= pp['vf_wt']


@pytest.mark.parametrize("secpar,sp,pp,j,seed,secret_seed,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk,ch_bd,ch_wt,msg,sig_ch,sig_a,valid_a,sig_b,valid_b", MAKE_SIGN_CASES)
def test_vf(mocker, secpar, sp, pp, j, seed, secret_seed, sk_bd, sk_wt, left_sk, right_sk, sk, left_vk, right_vk, vk, ch_bd, ch_wt, msg, sig_ch, sig_a, valid_a, sig_b, valid_b):
    mocker.patch('lattice_crypto.lm_one_time_sigs.make_signature_challenge', return_value=sig_ch)
    assert sig_a == sig_b
    assert sk[0] ** sig_ch + sk[1] == sig_a
    assert sp.key_ch == pp['scheme_parameters'].key_ch
    assert sp.key_ch * sk[0] == sp.key_ch * sk.left_key == vk[0] == vk.left_key
    assert sp.key_ch * sk[1] == sp.key_ch * sk.right_key == vk[1] == vk.right_key
    assert sp.key_ch * sig_a == vk[0] * sig_ch + vk[1]
    cnw = sig_a.get_coef_rep()
    n, w = max(i[1] for i in cnw), max(i[2] for i in cnw)
    assert 1 <= n <= pp['vf_bd']
    assert 1 <= w <= pp['vf_wt']
    assert verify(pp=pp, otvk=vk, msg=msg, sig=sig_a) == valid_a
    assert verify(pp=pp, otvk=vk, msg=msg, sig=sig_b) == valid_b
