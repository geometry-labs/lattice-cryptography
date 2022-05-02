from lattice_algebra import Polynomial, PolynomialVector, LatticeParameters, hash2polynomialvector, hash2polynomial
from lattice_cryptography.one_time_keys import ALLOWABLE_SECPARS, SecretSeed, OneTimeSecretWitness, \
    OneTimeSigningKey, OneTimeVerificationKey, SchemeParameters, bits_to_decode, bits_to_indices, \
    UNIFORM_INFINITY_WEIGHT, OneTimePublicStatement
from typing import Any, Dict, Tuple, List
from secrets import randbelow

# Typing
SecurityParameter = int
PublicParameters = Dict[str, Any]
OneTimeKeyTuple = Tuple[SecretSeed, OneTimeSigningKey, OneTimeVerificationKey]
OneTimeWitStatPair = Tuple[SecretSeed, OneTimeSecretWitness, OneTimePublicStatement]
Message = str
Challenge = Polynomial
PreSignature = PolynomialVector
Signature = PolynomialVector

# COMPARE THE PARAMETERS HERE WITH OUR PARAMETER ANALYSIS
LPs: Dict[int, LatticeParameters] = dict()
LPs[128] = LatticeParameters(modulus=11777, degree=2 ** 8, length=13)
LPs[256] = LatticeParameters(modulus=39937, degree=2 ** 8, length=23)

BDs: Dict[int, Dict[str, int]] = dict()
BDs[128] = {'sk_bd': 45, 'ch_bd': 1, 'wit_bd': 1}
BDs[256] = {'sk_bd': 65, 'ch_bd': 1, 'wit_bd': 1}

WTs: Dict[int, Dict[str, int]] = dict()
WTs[128] = {'sk_wt': 256, 'ch_wt': 20, 'wit_wt': 20}
WTs[256] = {'sk_wt': 256, 'ch_wt': 50, 'wit_wt': 20}

SALTs: Dict[int, Dict[str, str]] = {i: {'sk_salt': 'SK_SALT', 'ch_salt': 'CH_SALT', 'wit_salt': 'WIT_SALT'} for i in
                                    ALLOWABLE_SECPARS}

DISTRIBUTION: str = UNIFORM_INFINITY_WEIGHT


def make_setup_parameters(secpar: SecurityParameter) -> PublicParameters:
    result: PublicParameters = dict()

    result['scheme_parameters']: SchemeParameters = SchemeParameters(
        secpar=secpar, lp=LPs[secpar],
        distribution=DISTRIBUTION
    )

    result['sk_salt']: Message = SALTs[secpar]['sk_salt']
    result['sk_bd']: int = BDs[secpar]['sk_bd']
    result['sk_wt']: int = min(LPs[secpar].degree, WTs[secpar]['sk_wt'])

    result['ch_salt']: Message = SALTs[secpar]['ch_salt']
    result['ch_bd']: int = BDs[secpar]['ch_bd']
    result['ch_wt']: int = min(LPs[secpar].degree, WTs[secpar]['ch_wt'])

    result['wit_salt']: Message = SALTs[secpar]['wit_salt']
    result['wit_bd']: int = BDs[secpar]['wit_bd']
    result['wit_wt']: int = min(LPs[secpar].degree, WTs[secpar]['wit_wt'])

    result['pvf_wt']: int = max(1, min(result['scheme_parameters'].lp.degree, result['sk_wt'] * (1 + result['ch_wt'])))
    result['pvf_bd']: int = max(1, min((result['scheme_parameters'].lp.modulus - 1) // 2, result['sk_bd'] * (
                1 + min(LPs[secpar].degree, result['sk_wt'], result['ch_wt']) * result['ch_bd'])))

    result['vf_wt']: int = max(1, min(
        result['scheme_parameters'].lp.degree,
        result['sk_wt'] * (1 + result['ch_wt']) + result['wit_wt']))
    result['vf_bd']: int = max(1, min((result['scheme_parameters'].lp.modulus - 1) // 2, result['sk_bd'] * (
                1 + min(LPs[secpar].degree, result['sk_wt'], result['ch_wt']) * result['ch_bd']) + result['wit_bd']))

    result['ext_wit_wt']: int = max(1, min(result['scheme_parameters'].lp.degree, result['vf_wt'] + result['pvf_wt']))
    result['ext_wit_bd']: int = max(1, min((result['scheme_parameters'].lp.modulus - 1) // 2,
                                           result['vf_bd'] + result['pvf_bd']))

    return result


def make_random_seed(secpar: SecurityParameter, pp: PublicParameters) -> SecretSeed:
    # TODO: Move to one_time_keys.py
    seed = bin(randbelow(2 ** secpar))[2:].zfill(secpar)
    return SecretSeed(secpar=secpar, lp=pp['scheme_parameters'].lp, seed=seed)


def make_one_wit(pp: PublicParameters, seed: SecretSeed = None) -> OneTimeWitStatPair:
    secpar = pp['scheme_parameters'].secpar
    lp = pp['scheme_parameters'].lp
    x = seed
    if not x:
        x = make_random_seed(secpar=secpar, pp=pp)
    wit_data: PolynomialVector = hash2polynomialvector(
        secpar=secpar, lp=lp,
        distribution=DISTRIBUTION,
        dist_pars={'bd': pp['wit_bd'], 'wt': pp['wit_wt']},
        num_coefs=pp['wit_wt'],
        bti=bits_to_indices(secpar=secpar, degree=lp.degree, wt=pp['wit_wt']),
        btd=bits_to_decode(secpar=secpar, bd=pp['wit_bd']),
        salt=pp['wit_salt'],
        msg=x.seed,
        const_time_flag=True
    )
    wit: OneTimeSecretWitness = OneTimeSecretWitness(secpar=secpar, lp=lp, key=wit_data)
    key_ch = pp['scheme_parameters'].key_ch
    key_ch.const_time_flag = True
    stat: OneTimePublicStatement = OneTimePublicStatement(secpar=secpar, lp=lp, key=key_ch * wit.key)
    return x, wit, stat


def make_one_key(pp: PublicParameters, seed: SecretSeed = None) -> OneTimeKeyTuple:
    secpar = pp['scheme_parameters'].secpar
    lp = pp['scheme_parameters'].lp
    x = seed
    if not x:
        x = make_random_seed(secpar=secpar, pp=pp)
    left_signing_key: PolynomialVector = hash2polynomialvector(
        secpar=secpar, lp=lp,
        distribution=DISTRIBUTION,
        dist_pars={'bd': pp['sk_bd'], 'wt': pp['sk_wt']},
        num_coefs=pp['sk_wt'],
        bti=bits_to_indices(secpar=secpar, degree=lp.degree, wt=pp['sk_wt']),
        btd=bits_to_decode(secpar=secpar, bd=pp['sk_bd']),
        salt=pp['sk_salt'] + 'LEFT',
        msg=x.seed,
        const_time_flag=True
    )
    right_signing_key: PolynomialVector = hash2polynomialvector(
        secpar=secpar, lp=lp,
        distribution=DISTRIBUTION,
        dist_pars={'bd': pp['sk_bd'], 'wt': pp['sk_wt']},
        num_coefs=pp['sk_wt'],
        bti=bits_to_indices(secpar=secpar, degree=lp.degree, wt=pp['sk_wt']),
        btd=bits_to_decode(secpar=secpar, bd=pp['sk_bd']),
        salt=pp['sk_salt'] + 'RIGHT',
        msg=x.seed,
        const_time_flag=True
    )
    otsk = OneTimeSigningKey(secpar=secpar, lp=lp, left_key=left_signing_key, right_key=right_signing_key)
    key_ch = pp['scheme_parameters'].key_ch
    key_ch.const_time_flag = True
    otvk = OneTimeVerificationKey(secpar=secpar, lp=lp, left_key=key_ch * left_signing_key,
                                  right_key=key_ch * right_signing_key)
    return x, otsk, otvk


def witgen(pp: PublicParameters, num_wits_to_gen: int = 1, seeds: List[SecretSeed] = None) -> List[OneTimeWitStatPair]:
    if num_wits_to_gen < 1:
        raise ValueError('Can only generate a natural number worth of witnesses.')
    elif seeds is not None and len(seeds) != num_wits_to_gen:
        raise ValueError('Must either roll witnesses with no seeds, or with a seed for each key.')
    elif seeds is None and num_wits_to_gen == 1:
        return [make_one_wit(pp=pp)]
    elif seeds is not None and num_wits_to_gen == 1:
        return [make_one_wit(pp=pp, seed=seeds[0])]
    elif seeds is None:
        return [make_one_wit(pp=pp) for _ in range(num_wits_to_gen)]
    return [make_one_wit(pp=pp, seed=next_seed) for next_seed in seeds]


def keygen(pp: PublicParameters, num_keys_to_gen: int = 1, seeds: List[SecretSeed] = None) -> List[OneTimeKeyTuple]:
    if num_keys_to_gen < 1:
        raise ValueError('Can only generate a natural number worth of keys.')
    elif seeds is not None and len(seeds) != num_keys_to_gen:
        raise ValueError('Must either roll keys with no seeds, or with a seed for each key.')
    elif seeds is None and num_keys_to_gen == 1:
        return [make_one_key(pp=pp)]
    elif seeds is not None and num_keys_to_gen == 1:
        return [make_one_key(pp=pp, seed=seeds[0])]
    elif seeds is None:
        return [make_one_key(pp=pp) for _ in range(num_keys_to_gen)]
    return [make_one_key(pp=pp, seed=next_seed) for next_seed in seeds]


def make_signature_challenge(pp: PublicParameters, otvk: OneTimeVerificationKey, msg: Message,
                             st: OneTimePublicStatement) -> Challenge:
    return hash2polynomial(
        secpar=pp['scheme_parameters'].secpar,
        lp=pp['scheme_parameters'].lp,
        distribution=DISTRIBUTION,
        dist_pars={'bd': pp['ch_bd'], 'wt': pp['ch_wt']},
        salt=pp['ch_salt'],
        msg=str(st) + ', ' + str(otvk) + ', ' + msg,
        num_coefs=pp['ch_wt'],
        bti=bits_to_indices(
            secpar=pp['scheme_parameters'].secpar,
            degree=pp['scheme_parameters'].lp.degree,
            wt=pp['ch_wt']
        ),
        btd=bits_to_decode(
            secpar=pp['scheme_parameters'].secpar,
            bd=pp['ch_bd']
        ),
        const_time_flag=True
    )


def presign(pp: PublicParameters, otk: OneTimeKeyTuple, msg: Message, st: OneTimePublicStatement) -> PreSignature:
    c: Challenge = make_signature_challenge(pp=pp, otvk=otk[2], msg=msg, st=st)
    presignature: PreSignature = otk[1][0] ** c + otk[1][1]
    presignature.const_time_flag = True
    return presignature


def preverify(pp: PublicParameters, otvk: OneTimeVerificationKey, msg: Message, st: OneTimePublicStatement,
              presig: PreSignature) -> bool:
    presig.const_time_flag = True  # verifying pre-signatures in non-constant time
    cnws = presig.get_coef_rep()
    n, w = max(i[1] for i in cnws), max(i[2] for i in cnws)
    if n > pp['pvf_bd'] or w > pp['pvf_wt']:
        return False

    key_ch = pp['scheme_parameters'].key_ch
    c: Challenge = make_signature_challenge(pp=pp, otvk=otvk, msg=msg, st=st)

    key_ch.const_time_flag = True
    c.const_time_flag = True
    otvk.left_key.const_time_flag = True
    otvk.right_key.const_time_flag = True

    lhs = key_ch * presig
    rhs = otvk[0] * c + otvk[1]

    return lhs == rhs


def adapt(presig: PreSignature, wit: OneTimeSecretWitness) -> Signature:
    return presig + wit.key


def extract(pp: PublicParameters, presig: PreSignature, sig: Signature) -> OneTimeSecretWitness:
    ext_wit: PolynomialVector = sig - presig
    return OneTimeSecretWitness(secpar=pp['scheme_parameters'].secpar, lp=pp['scheme_parameters'].lp, key=ext_wit)


def witness_verify(pp: PublicParameters, wit: OneTimeSecretWitness, st: OneTimePublicStatement) -> bool:
    wit.const_time_flag = True  # keep true to ensure timing attacks can't be used to extract witnesses
    cnws = wit.key.get_coef_rep()
    n, w = max(i[1] for i in cnws), max(i[2] for i in cnws)
    if n > pp['ext_wit_bd'] or w > pp['ext_wit_wt']:
        return False

    key_ch = pp['scheme_parameters'].key_ch
    return key_ch * wit.key == st.key


def sign(pp: PublicParameters, otk: OneTimeKeyTuple, msg: Message, wit_st_pair: OneTimeWitStatPair) -> Signature:
    wit: OneTimeSecretWitness = wit_st_pair[1]
    st: OneTimePublicStatement = wit_st_pair[2]
    presig = presign(pp=pp, otk=otk, msg=msg, st=st)
    return adapt(presig=presig, wit=wit)


def verify(pp: PublicParameters, otvk: OneTimeVerificationKey, msg: Message, st: OneTimePublicStatement,
           sig: Signature) -> bool:
    sig.const_time_flag = True
    cnws = sig.get_coef_rep()
    n, w = max(i[1] for i in cnws), max(i[2] for i in cnws)
    if n > pp['vf_bd'] or w > pp['vf_wt']:
        return False

    key_ch = pp['scheme_parameters'].key_ch
    c: Challenge = make_signature_challenge(pp=pp, otvk=otvk, msg=msg, st=st)

    key_ch.const_time_flag = True
    c.const_time_flag = True
    otvk.left_key.const_time_flag = True
    otvk.right_key.const_time_flag = True

    lhs = key_ch * sig
    rhs = otvk[0] * c + otvk[1] + st.key

    return lhs == rhs
