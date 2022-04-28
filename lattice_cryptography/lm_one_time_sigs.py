from math import ceil

from lattice_algebra import Polynomial, PolynomialVector, LatticeParameters, hash2polynomialvector, hash2polynomial
from lattice_cryptography.one_time_keys import SecretSeed, OneTimeSigningKey, OneTimeVerificationKey, ALLOWABLE_SECPARS, \
    SchemeParameters, UNIFORM_INFINITY_WEIGHT, bits_to_indices, bits_to_decode
from typing import Any, Tuple, Dict, List
from secrets import randbelow
from multiprocessing import Pool, cpu_count

# Typing
SecurityParameter = int
PublicParameters = Dict[str, Any]
OneTimeKeyTuple = Tuple[SecretSeed, OneTimeSigningKey, OneTimeVerificationKey]
Message = str
Challenge = Polynomial
Signature = PolynomialVector

# COMPARE THE PARAMETERS HERE WITH OUR PARAMETER ANALYSIS
LPs: Dict[int, LatticeParameters] = dict()
LPs[128] = LatticeParameters(modulus=11777, degree=2 ** 8, length=13)
LPs[256] = LatticeParameters(modulus=39937, degree=2 ** 8, length=23)

BDs: Dict[int, Dict[str, int]] = dict()
BDs[128] = {'sk_bd': 45, 'ch_bd': 1}
BDs[256] = {'sk_bd': 65, 'ch_bd': 1}

WTs: Dict[int, Dict[str, int]] = dict()
WTs[128] = {'sk_wt': 256, 'ch_wt': 20}
WTs[256] = {'sk_wt': 256, 'ch_wt': 50}

SALTs: Dict[int, Dict[str, str]] = {i: {'sk_salt': 'SK_SALT', 'ch_salt': 'CH_SALT'} for i in ALLOWABLE_SECPARS}

DISTRIBUTION: str = UNIFORM_INFINITY_WEIGHT


def make_setup_parameters(secpar: SecurityParameter) -> PublicParameters:
    result: PublicParameters = {}

    result['scheme_parameters']: SchemeParameters = SchemeParameters(
        secpar=secpar, lp=LPs[secpar],
        distribution=DISTRIBUTION
    )

    result['sk_salt']: Message = SALTs[secpar]['sk_salt']
    result['sk_bd']: int = BDs[secpar]['sk_bd']
    result['sk_wt']: int = WTs[secpar]['sk_wt']

    result['ch_salt']: Message = SALTs[secpar]['ch_salt']
    result['ch_bd']: int = BDs[secpar]['ch_bd']
    result['ch_wt']: int = WTs[secpar]['ch_wt']

    result['vf_wt']: int = max(1, min(result['scheme_parameters'].lp.degree, result['sk_wt'] * (1 + result['ch_wt'])))
    result['vf_bd']: int = max(1, min(result['scheme_parameters'].lp.modulus // 2,
                                      result['sk_bd'] * (1 + min(result['sk_wt'], result['ch_wt']) * result['ch_bd'])))
    return result


def make_random_seed(secpar: SecurityParameter, pp: PublicParameters) -> SecretSeed:
    # TODO: Move to one_time_keys.py
    seed = bin(randbelow(2 ** secpar))[2:].zfill(secpar)
    return SecretSeed(secpar=secpar, lp=pp['scheme_parameters'].lp, seed=seed)


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


def keygen(pp: PublicParameters, num_keys_to_gen: int = 1, seeds: List[SecretSeed] = None,
           multiprocessing: bool = None) -> List[OneTimeKeyTuple]:
    """ Wraps keygen_core to handle workload distribution for batch generation """

    # Only default to parallelization if more than a few keys are needed (to avoid unnecessary overhead)
    if multiprocessing is None:
        multiprocessing: bool = num_keys_to_gen >= 16
    num_workers: int = cpu_count()

    # Pass straight through to keygen_core() if there is no reason or desire to parallelize (to avoid extra overhead)
    if (not multiprocessing) or (num_keys_to_gen == 1) or (num_workers == 1):
        return keygen_core(pp=pp, num_keys_to_gen=num_keys_to_gen, seeds=seeds)

    # Prepare inputs for the pool
    if not seeds:
        iterable: List[Tuple[Dict[str, Any], int]] = [(pp, ceil(num_keys_to_gen / num_workers))] * num_workers
    else:
        seed_batches: List[List[Any]] = distribute_tasks(tasks=seeds)
        iterable: List[tuple] = list(zip([pp] * len(seed_batches), [len(x) for x in seed_batches], seed_batches))

    # Generate the keys and return the flattened results
    with Pool(num_workers) as pool:
        nested_keys: List[List[OneTimeKeyTuple]] = pool.starmap(func=keygen, iterable=iterable)
    return [item for sublist in nested_keys for item in sublist][:num_keys_to_gen]


def keygen_core(pp: PublicParameters, num_keys_to_gen: int = 1,
                seeds: List[SecretSeed] = None) -> List[OneTimeKeyTuple]:
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


def make_signature_challenge(pp: PublicParameters, otvk: OneTimeVerificationKey, msg: Message) -> Challenge:
    return hash2polynomial(
        secpar=pp['scheme_parameters'].secpar,
        lp=pp['scheme_parameters'].lp,
        distribution=DISTRIBUTION,
        dist_pars={'bd': pp['ch_bd'], 'wt': pp['ch_wt']},
        salt=pp['ch_salt'],
        msg=str(otvk) + ', ' + msg,
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


def sign(pp: PublicParameters, otk: OneTimeKeyTuple, msg: Message) -> Signature:
    c: Challenge = make_signature_challenge(pp=pp, otvk=otk[2], msg=msg)
    # assert otk[1][0].const_time_flag
    # assert otk[1][1].const_time_flag
    # assert c.const_time_flag
    signature: Signature = otk[1][0] ** c + otk[1][1]
    signature.const_time_flag = False
    return signature


def verify(pp: PublicParameters, otvk: OneTimeVerificationKey, msg: Message, sig: Signature) -> bool:
    sig.const_time_flag = False
    cnws = sig.get_coef_rep()
    n, w = max(i[1] for i in cnws), max(i[2] for i in cnws)
    if n > pp['vf_bd'] or w > pp['vf_wt']:
        return False

    key_ch = pp['scheme_parameters'].key_ch
    c: Challenge = make_signature_challenge(pp=pp, otvk=otvk, msg=msg)

    key_ch.const_time_flag = False
    c.const_time_flag = False
    otvk.left_key.const_time_flag = False
    otvk.right_key.const_time_flag = False

    lhs = key_ch * sig
    rhs = otvk[0] * c + otvk[1]

    return lhs == rhs


def distribute_tasks(tasks: List[Any], num_workers: int = None) -> List[List[Any]]:
    """
    Helper function that distributes a list of arbitrary tasks among a specific number of workers

    :param tasks: iterable containing list of tasks to carry out
    :param num_workers: number of workers available in the pool (usually = number of CPU cores)
    :return: task list broken up into num_workers segments
    """
    if not num_workers:
        num_workers = cpu_count()

    # Determine how the jobs should be split up per core
    r: int = len(tasks) % num_workers  # number of leftover jobs once all complete batches are processed
    job_counts: List[int] = r * [1 + (len(tasks) // num_workers)] + (num_workers - r) * [len(tasks) // num_workers]

    # Distribute the tasks accordingly
    i: int = 0
    task_list_all: List[List[Any]] = []
    for load_amount in job_counts:
        task_list_all.append(tasks[i:i + load_amount])
        i += load_amount
    return task_list_all
