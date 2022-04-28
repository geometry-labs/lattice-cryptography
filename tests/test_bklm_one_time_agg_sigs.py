"""
We test the lattice-crypto.bklm_one_time_agg_sigs module.
"""
from copy import deepcopy
from random import shuffle
from secrets import randbits
from typing import Any, List, Dict

import pytest
from lattice_algebra import random_polynomialvector, random_polynomial

from lattice_crypto.bklm_one_time_agg_sigs import make_setup_parameters, make_signature_challenge, \
    prepare_make_agg_coefs, prepare_hash2polyinput, aggregate, aggregate_verify, BDs, WTs, CAPs
from lattice_crypto.lm_one_time_sigs import LPs, SALTs, DISTRIBUTION, make_random_seed, make_one_key, sign, verify, \
    keygen
from lattice_crypto.one_time_keys import ALLOWABLE_SECPARS, SecretSeed, OneTimeSigningKey, OneTimeVerificationKey, \
    SchemeParameters, bits_to_decode, bits_to_indices

SAMPLE_SIZE: int = 2 ** 6
REQUIRED_SETUP_PARAMETERS = ['scheme_parameters', 'sk_bd', 'sk_wt', 'sk_salt', 'ch_bd', 'ch_wt', 'ch_salt', 'vf_bd',
                             'vf_wt', 'ag_bd', 'ag_wt', 'ag_salt', 'avf_bd', 'avf_wt', 'ag_cap']
BOUND_NAMES = ['sk_bd', 'ch_bd', 'vf_bd', 'ag_bd', 'avf_bd']
WEIGHT_NAMES = ['sk_wt', 'ch_wt', 'vf_wt', 'ag_wt', 'avf_wt']
SALT_NAMES = ['sk_salt', 'ch_salt', 'ag_salt']

# i = 0 : secpar
# i = 1 : SchemeParameters
# i = 2 : PublicParameters
SOME_SECPARS_AND_SPS = [(secpar, SchemeParameters(secpar=secpar, lp=LPs[secpar], distribution=DISTRIBUTION)) for secpar
                        in ALLOWABLE_SECPARS]
SOME_PUBLIC_PARAMETERS = [i + tuple([{
    'scheme_parameters': i[-1],
    'sk_salt': SALTs[i[0]]['sk_salt'],
    'sk_bd': BDs[i[0]]['sk_bd'],
    'sk_wt': WTs[i[0]]['sk_wt'],
    'ch_salt': SALTs[i[0]]['ch_salt'],
    'ch_bd': BDs[i[0]]['ch_bd'],
    'ch_wt': WTs[i[0]]['ch_wt'],
    'vf_bd': max(1, min(i[-1].lp.modulus // 2,
                        BDs[i[0]]['sk_bd'] * (1 + BDs[i[0]]['ch_bd'] * min(WTs[i[0]]['sk_wt'], WTs[i[0]]['ch_wt'])))),
    'vf_wt': max(1, min(i[-1].lp.degree, WTs[i[0]]['sk_wt'] * (1 + WTs[i[0]]['ch_wt']))),
    'ag_cap': CAPs[i[0]],
    'ag_salt': SALTs[i[0]]['ag_salt'],
    'ag_bd': BDs[i[0]]['ag_bd'],
    'ag_wt': WTs[i[0]]['ag_wt'],
    'avf_bd': max(1, min(i[-1].lp.modulus // 2, CAPs[i[0]] * min(WTs[i[0]]['ag_wt'], max(1, min(i[-1].lp.degree,
                                                                                                WTs[i[0]]['sk_wt'] * (
                                                                                                            1 +
                                                                                                            WTs[i[0]][
                                                                                                                'ch_wt'])))) *
                         BDs[i[0]]['ag_bd'] * max(1, min(i[-1].lp.modulus // 2, BDs[i[0]]['sk_bd'] * (
                1 + BDs[i[0]]['ch_bd'] * min(WTs[i[0]]['sk_wt'], WTs[i[0]]['ch_wt'])))))),
    'avf_wt': max(1, min(i[-1].lp.degree, CAPs[i[0]] * WTs[i[0]]['ag_wt'] * max(1, min(i[-1].lp.degree,
                                                                                       WTs[i[0]]['sk_wt'] * (
                                                                                                   1 + WTs[i[0]][
                                                                                               'ch_wt']))))),
}]) for i in SOME_SECPARS_AND_SPS]


@pytest.mark.parametrize("secpar,sp,expected_pp", SOME_PUBLIC_PARAMETERS)
def test_make_setup_parameters(mocker, secpar, sp, expected_pp):
    mocker.patch('lattice_crypto.one_time_keys.random_polynomialvector', return_value=sp.key_ch)
    assert expected_pp == make_setup_parameters(secpar)


# i = 3 : integer j
# i = 4 : j as binary_string
# i = 5 : SecretSeed with this string as the seed
MAKE_RANDOM_SEED_CASES = [
    i + tuple([j, bin(j)[2:].zfill(i[0]), SecretSeed(secpar=i[0], lp=i[1].lp, seed=bin(j)[2:].zfill(i[0]))]) for i in
    SOME_PUBLIC_PARAMETERS for j in range(2 * SAMPLE_SIZE + 1)
]


@pytest.mark.parametrize("secpar,sp,pp,expected_int,expected_str,expected_seed", MAKE_RANDOM_SEED_CASES)
def test_make_random_seed(mocker, secpar, sp, pp, expected_int, expected_str, expected_seed):
    mocker.patch('lattice_crypto.lm_one_time_sigs.randbelow', return_value=expected_int)
    observed_seed = make_random_seed(secpar=secpar, pp=pp)
    assert observed_seed == expected_seed
    assert observed_seed.seed == expected_str


BD_MIN: int = 1
BD_MAX: int = 1
SOME_BDS: List[int] = list(range(BD_MIN, BD_MAX + 1))

WT_MIN: int = 1
WT_MAX: int = 1
SOME_WTS: List[int] = list(range(WT_MIN, WT_MAX + 1))

# i = 6: sk_bd
# i = 7: sk_wt
# i = 8: left_sk
# i = 9: right_sk
# i = 10: sk
# i = 11: left_vk
# i = 12: right_vk
# i = 13: vk
MAKE_ONE_KEY_CASES = [i + tuple([
    sk_bd,
    sk_wt,
    random_polynomialvector(
        secpar=i[0],
        lp=i[1].lp,
        distribution=DISTRIBUTION,
        dist_pars={'bd': sk_bd, 'wt': sk_wt},
        num_coefs=sk_wt,
        bti=bits_to_indices(secpar=i[0], degree=i[1].lp.degree, wt=sk_wt),
        btd=bits_to_decode(secpar=i[0], bd=sk_bd),
        const_time_flag=False),
    random_polynomialvector(
        secpar=i[0],
        lp=i[1].lp,
        distribution=DISTRIBUTION,
        dist_pars={'bd': sk_bd, 'wt': sk_wt},
        num_coefs=sk_wt,
        bti=bits_to_indices(secpar=i[0], degree=i[1].lp.degree, wt=sk_wt),
        btd=bits_to_decode(secpar=i[0], bd=sk_bd),
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
        right_key=i[-1])
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


@pytest.mark.parametrize("secpar,sp,pp,j,seed,secret_seed,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk",
                         MAKE_ONE_KEY_CASES)
def test_make_one_key(mocker, secpar: int, sp: SchemeParameters, pp: Dict[str, Any], j, seed, secret_seed, sk_bd, sk_wt,
                      left_sk, right_sk, sk, left_vk,
                      right_vk, vk):
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

    assert vk == OneTimeVerificationKey(secpar=secpar, lp=pp['scheme_parameters'].lp,
                                        left_key=pp['scheme_parameters'].key_ch * sk.left_key,
                                        right_key=pp['scheme_parameters'].key_ch * sk.right_key)
    cnw = sk[0].get_coef_rep() + sk[1].get_coef_rep()
    n, w = max(i[1] for i in cnw), max(i[2] for i in cnw)
    assert 1 <= n <= pp['sk_bd']
    assert 1 <= w <= pp['sk_wt']


@pytest.mark.parametrize("secpar,sp,pp,j,seed,secret_seed,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk",
                         MAKE_ONE_KEY_CASES)
def test_keygen(mocker, secpar, sp, pp: Dict[str, Any], j, seed, secret_seed, sk_bd, sk_wt, left_sk, right_sk, sk,
                left_vk, right_vk,
                vk):
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


# i = 14: ch_bd
# i = 15: ch_wt
# i = 16: msg
# i = 17: sig_ch
MAKE_SIGNATURE_CHALLENGE_CASES = []
for i in MAKE_ONE_KEY_CASES:
    for j in SOME_BDS:
        for k in SOME_WTS:
            MAKE_SIGNATURE_CHALLENGE_CASES += [
                i + tuple([
                    j,
                    k,
                    bin(randbits(i[0]))[2:].zfill(i[0]),
                    random_polynomial(
                        secpar=i[0],
                        lp=i[1].lp,
                        distribution=DISTRIBUTION,
                        dist_pars={'bd': j, 'wt': k},
                        num_coefs=k,
                        bti=bits_to_indices(secpar=i[0], degree=i[1].lp.degree, wt=k),
                        btd=bits_to_decode(secpar=i[0], bd=j),
                        const_time_flag=False)])]


@pytest.mark.parametrize(
    "secpar,sp,pp,j,seed,secret_seed,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk,ch_bd,ch_wt,msg,exp_sig_ch",
    MAKE_SIGNATURE_CHALLENGE_CASES)
def test_make_signature_challenge(mocker, secpar, sp, pp, j, seed, secret_seed, sk_bd, sk_wt, left_sk, right_sk, sk,
                                  left_vk, right_vk, vk, ch_bd, ch_wt, msg, exp_sig_ch):
    mocker.patch('lattice_crypto.lm_one_time_sigs.hash2polynomial', return_value=exp_sig_ch)
    obs_sig_ch = make_signature_challenge(pp=pp, otvk=vk, msg=msg)
    assert obs_sig_ch == exp_sig_ch
    c, n, w = obs_sig_ch.get_coef_rep()
    assert isinstance(c, dict)
    assert all(isinstance(i, int) for i in c)
    assert all(isinstance(c[i], int) for i in c)
    assert 1 <= n <= ch_bd
    assert 1 <= w <= ch_wt


# i = 18 : manual_sig one
# i = 19 : manual_sig two
# i = 20 : valid bit

MAKE_SIGN_CASES = [
    i + tuple([
        i[8] ** i[-1] + i[9],
        i[10][0] ** i[-1] + i[10][1],
        True,
    ]) for i in MAKE_SIGNATURE_CHALLENGE_CASES
]


#
# # i = 0 : secpar
# # i = 1 : sp
# # i = 2 : pp
# # i = 3 : a random integer for use as a seed
# # i = 4 : integer as a binary string
# # i = 5 : SecretSeed
# # i = 6 : sk_bd
# # i = 7 : sk_wt
# # i = 8 : left_sk
# # i = 9 : right_sk
# # i = 10 : sk
# # i = 11: left_vk
# # i = 12: right_vk
# # i = 13: vk
# # i = 14 : ch_bd
# # i = 15 : ch_wt
# # i = 16 : msg
# # i = 17 : mocked sig_ch
# # i = 18: manual_sig one
# # i = 19: manual_sig two
# # i = 20: expected vf bit
@pytest.mark.parametrize(
    "secpar,sp,pp,j,seed,secret_seed,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk,ch_bd,ch_wt,msg,sig_ch,expected_sig_a,expected_sig_b,expected_valid",
    MAKE_SIGN_CASES)
def test_sign(mocker, secpar, sp, pp, j, seed, secret_seed, sk_bd, sk_wt, left_sk, right_sk, sk, left_vk, right_vk, vk,
              ch_bd, ch_wt, msg, sig_ch, expected_sig_a, expected_sig_b, expected_valid, ):
    mocker.patch('lattice_crypto.lm_one_time_sigs.make_signature_challenge', return_value=sig_ch)
    sig_ch.const_time_flag = False
    sk[0].const_time_flag = False
    sk[1].const_time_flag = False
    sp.key_ch.const_time_flag = False
    observed_sig = sign(pp=pp, otk=(secret_seed, sk, vk), msg=msg)
    assert sk[0] == left_sk
    assert sk[1] == right_sk
    assert expected_sig_b == sk[0] ** sig_ch + sk[1]
    assert expected_sig_a == sk[0] ** sig_ch + sk[1]
    assert observed_sig == sk[0] ** sig_ch + sk[1]
    assert observed_sig == expected_sig_a == expected_sig_b
    assert sp.key_ch == pp['scheme_parameters'].key_ch
    assert sp.key_ch * sk[0] == sp.key_ch * sk.left_key == vk[0] == vk.left_key
    assert sp.key_ch * sk[1] == sp.key_ch * sk.right_key == vk[1] == vk.right_key
    assert sp.key_ch * observed_sig == vk[0] * sig_ch + vk[1]
    cnw = observed_sig.get_coef_rep()
    n, w = max(i[1] for i in cnw), max(i[2] for i in cnw)
    assert 1 <= n <= pp['vf_bd']
    assert 1 <= w <= pp['vf_wt']


@pytest.mark.parametrize(
    "secpar,sp,pp,j,seed,secret_seed,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk,ch_bd,ch_wt,msg,sig_ch,sig_a,sig_b,valid",
    MAKE_SIGN_CASES)
def test_vf(mocker, secpar, sp, pp, j, seed, secret_seed, sk_bd, sk_wt, left_sk, right_sk, sk, left_vk, right_vk, vk,
            ch_bd, ch_wt, msg, sig_ch, sig_a, sig_b, valid):
    mocker.patch('lattice_crypto.lm_one_time_sigs.make_signature_challenge', return_value=sig_ch)
    assert sk[0] ** sig_ch + sk[1] == sig_a == sig_b
    assert sp.key_ch == pp['scheme_parameters'].key_ch
    assert sp.key_ch * sk[0] == sp.key_ch * sk.left_key == vk[0] == vk.left_key
    assert sp.key_ch * sk[1] == sp.key_ch * sk.right_key == vk[1] == vk.right_key
    assert vk[0] * sig_ch + vk[1] == sp.key_ch * sig_a == sp.key_ch * sig_b
    cnw = sig_a.get_coef_rep()
    n, w = max(i[1] for i in cnw), max(i[2] for i in cnw)
    assert 1 <= n <= pp['vf_bd']
    assert 1 <= w <= pp['vf_wt']
    assert verify(pp=pp, otvk=vk, msg=msg, sig=sig_a) == valid


A_SIZE: int = 32
LIST_OF_LISTS_OF_UNQ_STRINGS = []
while len(LIST_OF_LISTS_OF_UNQ_STRINGS) < SAMPLE_SIZE:
    next_key_list = []
    while len(next_key_list) < SAMPLE_SIZE:
        next_key = bin(randbits(A_SIZE))[2:].zfill(A_SIZE)
        if next_key not in next_key_list:
            next_key_list += [next_key]
    LIST_OF_LISTS_OF_UNQ_STRINGS += [next_key_list]

PREPARE_MAKE_AGG_COEFS_CASES = [
    (i, [bin(randbits(A_SIZE))[2:].zfill(A_SIZE) for _ in range(SAMPLE_SIZE)]) for i in LIST_OF_LISTS_OF_UNQ_STRINGS
]
PREPARE_MAKE_AGG_COEFS_CASES = [
    i + tuple([
        list(zip(i[-2], i[-1]))
    ]) for i in PREPARE_MAKE_AGG_COEFS_CASES
]
PREPARE_MAKE_AGG_COEFS_CASES = [
    i + tuple([
        sorted(i[-1], key=lambda x: str(x[0]))
    ]) for i in PREPARE_MAKE_AGG_COEFS_CASES
]
PREPARE_MAKE_AGG_COEFS_CASES = [
    i + tuple([
        [j[0] for j in i[-1]],
        [j[1] for j in i[-1]]
    ]) for i in PREPARE_MAKE_AGG_COEFS_CASES
]


@pytest.mark.parametrize("unq_keys,ran_msgs,zipped_keys_and_msgs,srt_zipped_keys_and_msgs,exp_srt_keys,exp_srt_msgs",
                         PREPARE_MAKE_AGG_COEFS_CASES)
def test_prepare_make_agg_coefs(unq_keys, ran_msgs, zipped_keys_and_msgs, srt_zipped_keys_and_msgs, exp_srt_keys,
                                exp_srt_msgs):

    obs_srt_keys, obs_srt_msgs = prepare_make_agg_coefs(otvks=unq_keys, msgs=ran_msgs)
    assert all(next_key in unq_keys for next_key in obs_srt_keys)
    assert all(next_key in unq_keys for next_key in exp_srt_keys)
    assert all(next_msg in ran_msgs for next_msg in obs_srt_msgs)
    assert all(next_msg in ran_msgs for next_msg in exp_srt_msgs)
    assert len(obs_srt_keys) == len(unq_keys)
    assert len(obs_srt_msgs) == len(ran_msgs)
    assert obs_srt_keys == exp_srt_keys
    assert obs_srt_msgs == exp_srt_msgs
    shuffled_keys, shuffled_msgs = deepcopy(unq_keys), deepcopy(ran_msgs)
    shuffle(shuffled_keys)
    shuffle(shuffled_msgs)
    obs_srt_keys, obs_srt_msgs = prepare_make_agg_coefs(otvks=unq_keys, msgs=ran_msgs)
    assert all(next_key in unq_keys for next_key in obs_srt_keys)
    assert all(next_key in unq_keys for next_key in exp_srt_keys)
    assert all(next_msg in ran_msgs for next_msg in obs_srt_msgs)
    assert all(next_msg in ran_msgs for next_msg in exp_srt_msgs)
    assert len(obs_srt_keys) == len(unq_keys)
    assert len(obs_srt_msgs) == len(ran_msgs)
    assert obs_srt_keys == exp_srt_keys
    assert obs_srt_msgs == exp_srt_msgs


PREPARE_HASH2POLYINPUT_CASES = [i + j for i in SOME_PUBLIC_PARAMETERS for j in PREPARE_MAKE_AGG_COEFS_CASES]
PREPARE_HASH2POLYINPUT_CASES = [
    i + tuple([
        bits_to_decode(secpar=i[0], bd=i[2]['ag_bd']),
        bits_to_indices(secpar=i[0], degree=i[1].lp.degree, wt=i[2]['ag_wt']),
        str(zip(i[7], i[8])),
        {
            'secpar': i[1].secpar,
            'lp': i[1].lp,
            'distribution': i[1].distribution,
            'dist_pars': {
                'bd': i[2]['ag_bd'],
                'wt': i[2]['ag_wt']},
            'num_coefs': i[2]['ag_wt'],
            'bti': bits_to_indices(secpar=i[0], degree=i[1].lp.degree, wt=i[2]['ag_wt']),
            'btd': bits_to_decode(secpar=i[0], bd=i[2]['ag_bd']),
            'msg': str(list(zip(i[7], i[8]))),
            'const_time_flag': False
        }
    ]) for i in PREPARE_HASH2POLYINPUT_CASES]


@pytest.mark.parametrize(
    "secpar,sp,pp,unq_keys,ran_msgs,zipped_keys_and_msgs,srt_zipped_keys_and_msgs,exp_srt_keys,exp_srt_msgs,btd,bti,msg,exp_h2pinput",
    PREPARE_HASH2POLYINPUT_CASES)
def test_prepare_hash2polyinput(secpar, sp, pp, unq_keys, ran_msgs, zipped_keys_and_msgs, srt_zipped_keys_and_msgs,
                                exp_srt_keys, exp_srt_msgs, btd, bti, msg, exp_h2pinput):
    obs_h2pinput = prepare_hash2polyinput(pp=pp, otvks=unq_keys, msgs=ran_msgs)
    assert obs_h2pinput == exp_h2pinput


@pytest.mark.parametrize("secpar,sp,pp", SOME_PUBLIC_PARAMETERS)
def test_all(secpar, sp, pp):
    for i in range(SAMPLE_SIZE):
        # Sample some new one-time keys
        some_signing_keys = keygen(pp=pp, num_keys_to_gen=pp['ag_cap'])
        some_msgs = [bin(randbits(A_SIZE))[2:].zfill(A_SIZE) for _ in some_signing_keys]
        some_sigs = [sign(pp=pp, otk=i, msg=j) for i, j in zip(some_signing_keys, some_msgs)]
        assert all(verify(pp=pp, otvk=i[2], msg=j, sig=k) for i, j, k in zip(some_signing_keys, some_msgs, some_sigs))
        ag_sig = aggregate(pp=pp, otvks=[i[2] for i in some_signing_keys], msgs=some_msgs, sigs=some_sigs)
        assert aggregate_verify(pp=pp, otvks=[i[2] for i in some_signing_keys], msgs=some_msgs, ag_sig=ag_sig)
