"""
We test the lattice-crypto.lm_one_time_sigs module.
"""
import pytest
from lattice_algebra import random_polynomialvector
from lattice_cryptography.one_time_keys import ALLOWABLE_SECPARS, SecretSeed, OneTimeSigningKey, OneTimeVerificationKey, \
    OneTimeSecretWitness, OneTimePublicStatement, SchemeParameters, bits_to_decode, bits_to_indices
from lattice_cryptography.adaptor_sigs import PublicParameters, OneTimeKeyTuple, OneTimeWitStatPair, make_setup_parameters, \
    make_one_key, keygen, witgen, presign, preverify, adapt, extract, sign, verify, witness_verify, LPs, SALTs, BDs, \
    WTs, DISTRIBUTION, make_random_seed
from typing import Any, Dict, List

SAMPLE_SIZE: int = 2 ** 0
REQUIRED_SETUP_PARAMETERS = ['scheme_parameters', 'sk_bd', 'sk_wt', 'sk_salt', 'ch_bd', 'ch_wt', 'ch_salt', 'wit_bd',
                             'wit_wt', 'wit_salt', 'vf_bd', 'vf_wt', 'pvf_bd', 'pvf_wt', 'ext_wit_bd', 'ext_wit_wt']
BOUND_NAMES = ['sk_bd', 'ch_bd', 'wit_bd', 'vf_bd', 'pvf_bd', 'ext_wit_bd']
WEIGHT_NAMES = ['sk_wt', 'ch_wt', 'wit_wt', 'vf_wt', 'pvf_wt', 'ext_wit_wt']
SALT_NAMES = ['sk_salt', 'ch_salt', 'wit_salt']

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
        'wit_salt': SALTs[i[0]]['wit_salt'],
        'wit_bd': BDs[i[0]]['wit_bd'],
        'wit_wt': WTs[i[0]]['wit_wt'],
        'pvf_bd': max(1, min((i[-1].lp.modulus - 1) // 2, BDs[i[0]]['sk_bd'] * (
                    1 + min(i[-1].lp.degree, WTs[i[0]]['sk_wt'], WTs[i[0]]['ch_wt']) * BDs[i[0]]['ch_bd']))),
        'pvf_wt': max(1, min(i[-1].lp.degree, WTs[i[0]]['sk_wt'] * (1 + WTs[i[0]]['ch_wt']))),
        'vf_bd': max(1, min((i[-1].lp.modulus - 1) // 2, BDs[i[0]]['sk_bd'] * (
                    1 + min(i[-1].lp.degree, WTs[i[0]]['sk_wt'], WTs[i[0]]['ch_wt']) * BDs[i[0]]['ch_bd']) + BDs[i[0]][
                                'wit_bd'])),
        'vf_wt': max(1, min(i[-1].lp.degree, WTs[i[0]]['sk_wt'] * (1 + WTs[i[0]]['ch_wt']) + WTs[i[0]]['wit_wt'])),
        'ext_wit_bd': max(1, min((i[-1].lp.modulus - 1) // 2, BDs[i[0]]['sk_bd'] * (
                    1 + min(i[-1].lp.degree, WTs[i[0]]['sk_wt'], WTs[i[0]]['ch_wt']) * BDs[i[0]]['ch_bd']) + BDs[i[0]][
                                     'sk_bd'] * (1 + min(i[-1].lp.degree, WTs[i[0]]['sk_wt'], WTs[i[0]]['ch_wt']) *
                                                 BDs[i[0]]['ch_bd']) + BDs[i[0]]['wit_bd'])),
        'ext_wit_wt': max(1, min(i[-1].lp.degree, WTs[i[0]]['sk_wt'] * (1 + WTs[i[0]]['ch_wt']) + WTs[i[0]]['sk_wt'] * (
                    1 + WTs[i[0]]['ch_wt']) + WTs[i[0]]['wit_wt'])),
    }]) for i in MAKE_SCHEME_PARAMETERS_CASES
]


@pytest.mark.parametrize("secpar,sp,expected_pp", MAKE_SETUP_PARAMETERS_CASES)
def test_make_setup_parameters(mocker, secpar, sp, expected_pp):
    mocker.patch('lattice_cryptography.one_time_keys.random_polynomialvector', return_value=sp.key_ch)
    assert expected_pp == make_setup_parameters(secpar)


MAKE_RANDOM_SEED_CASES = [
    i + tuple([j, bin(j)[2:].zfill(i[0])]) for i in MAKE_SETUP_PARAMETERS_CASES for j in range(2 * SAMPLE_SIZE + 1)
]
MAKE_RANDOM_SEED_CASES = [
    i + tuple([SecretSeed(secpar=i[0], lp=i[1].lp, seed=i[-1])]) for i in MAKE_RANDOM_SEED_CASES
]


@pytest.mark.parametrize("secpar,sp,pp,expected_int,expected_str,expected_seed", MAKE_RANDOM_SEED_CASES)
def test_make_random_seed(mocker, secpar, sp, pp, expected_int, expected_str, expected_seed):
    mocker.patch('lattice_cryptography.adaptor_sigs.randbelow', return_value=expected_int)
    observed_seed = make_random_seed(secpar=secpar, pp=pp)
    assert observed_seed == expected_seed
    assert observed_seed.seed == expected_str


BD_MIN: int = 1
BD_MAX: int = 2 ** 1
SOME_BDS: List[int] = list(range(BD_MIN, BD_MAX + 1))

WT_MIN: int = 1
WT_MAX: int = 2 ** 1
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


@pytest.mark.parametrize("secpar,sp,pp,j,seed,secret_seed,sk_bd,sk_wt,left_sk,right_sk,sk,left_vk,right_vk,vk",
                         MAKE_ONE_KEY_CASES)
def test_make_one_key(mocker, secpar, sp, pp: Dict[str, Any], j, seed, secret_seed, sk_bd, sk_wt, left_sk, right_sk, sk,
                      left_vk, right_vk, vk):
    mocker.patch('lattice_cryptography.adaptor_sigs.make_random_seed', return_value=secret_seed)
    mocker.patch('lattice_cryptography.adaptor_sigs.hash2polynomialvector', side_effect=[left_sk, right_sk])

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
                left_vk, right_vk, vk):
    mocker.patch('lattice_cryptography.adaptor_sigs.make_one_key', return_value=(secret_seed, sk, vk))
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


def test_general():
    for secpar in ALLOWABLE_SECPARS:
        pp: PublicParameters = make_setup_parameters(secpar=secpar)
        some_key: OneTimeKeyTuple = keygen(pp=pp, num_keys_to_gen=1)[0]
        some_otvk: OneTimeVerificationKey = some_key[2]
        some_wit_st_pair: OneTimeWitStatPair = witgen(pp=pp, num_wits_to_gen=1)[0]
        some_wit: OneTimeSecretWitness = some_wit_st_pair[1]
        some_st: OneTimePublicStatement = some_wit_st_pair[2]
        message = "Blessed are the cheesemakers."

        presig = presign(pp=pp, otk=some_key, msg=message, st=some_st)
        assert preverify(pp=pp, otvk=some_otvk, msg=message, st=some_st, presig=presig)

        adapted_presig = adapt(presig=presig, wit=some_wit)
        assert verify(pp=pp, otvk=some_otvk, msg=message, st=some_st, sig=adapted_presig)
        ext_wit = extract(pp=pp, sig=adapted_presig, presig=presig)
        assert witness_verify(pp=pp, wit=ext_wit, st=some_st)

        signed_sig = sign(pp=pp, otk=some_key, msg=message, wit_st_pair=some_wit_st_pair)
        assert verify(pp=pp, otvk=some_otvk, msg=message, st=some_st, sig=signed_sig)
        ext_wit = extract(pp=pp, sig=signed_sig, presig=presig)
        assert witness_verify(pp=pp, wit=ext_wit, st=some_st)
