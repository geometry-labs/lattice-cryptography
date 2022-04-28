from lattice_algebra import Polynomial, is_bitstring
from typing import Dict, List, Tuple
from lattice_cryptography.lm_one_time_sigs import SecurityParameter, PublicParameters, Message, Signature, \
    make_setup_parameters as setup_pars, make_signature_challenge, BDs, WTs, SALTs, hash2polynomial
from lattice_cryptography.one_time_keys import ALLOWABLE_SECPARS, OneTimeVerificationKey, bits_to_decode, bits_to_indices





# Typing
AggCoef = Polynomial

# COMPARE THE PARAMETERS HERE WITH OUR PARAMETER ANALYSIS
BDs[128]['ag_bd'] = 1
BDs[256]['ag_bd'] = 1

WTs[128]['ag_wt'] = 1
WTs[256]['ag_wt'] = 1

CAPs: Dict[int, int] = {i: 2 for i in ALLOWABLE_SECPARS}

for i in ALLOWABLE_SECPARS:
    SALTs[i]['ag_salt'] = 'AG_SALT'


def make_setup_parameters(secpar: SecurityParameter) -> PublicParameters:
    # Start with LMSigs parameters
    result = setup_pars(secpar=secpar)

    # Augment with aggregation parameters
    result['ag_cap']: int = CAPs[secpar]
    result['ag_salt']: Message = SALTs[secpar]['ag_salt']
    result['ag_bd']: int = BDs[secpar]['ag_bd']
    result['ag_wt']: int = WTs[secpar]['ag_wt']
    result['avf_wt']: int = max(1, min(
        result['scheme_parameters'].lp.degree,
        result['ag_cap'] * result['ag_wt'] * result['vf_wt']
    ))
    result['avf_bd']: int = max(1, min(
        result['scheme_parameters'].lp.modulus // 2,
        result['ag_cap'] * min(result['ag_wt'], result['vf_wt']) * result['ag_bd'] * result['vf_bd']
    ))
    return result


def prepare_make_agg_coefs(otvks: List[OneTimeVerificationKey], msgs: List[Message]) -> Tuple[
    List[OneTimeVerificationKey], List[Message]]:
    # TODO: Refactor to verify types, and then modify test to take this into account
    if len(otvks) != len(msgs):
        raise ValueError("Cannot prepare_make_agg_coefs without two input vectors of equal length.")
    elif not all(is_bitstring(msg) for msg in msgs):
        raise ValueError("Input messages must be bitstrings.")
    zipped_data = zip(otvks, msgs)
    zipped_data_srt_by_key = sorted(zipped_data, key=lambda x: str(x[0]))
    srt_keys, srt_msgs = ([i[j] for i in zipped_data_srt_by_key] for j in range(2))
    return srt_keys, srt_msgs


def prepare_hash2polyinput(pp: PublicParameters, otvks: List[OneTimeVerificationKey], msgs: List[Message]) -> dict:
    srt_keys, srt_msgs = prepare_make_agg_coefs(otvks=otvks, msgs=msgs)
    btd = bits_to_decode(secpar=pp['scheme_parameters'].secpar, bd=pp['ag_bd'])
    bti = bits_to_indices(secpar=pp['scheme_parameters'].secpar, degree=pp['scheme_parameters'].lp.degree,
                          wt=pp['ag_wt'])
    msg = str(list(zip(srt_keys, srt_msgs)))
    return {
        'secpar': pp['scheme_parameters'].secpar,
        'lp': pp['scheme_parameters'].lp,
        'distribution': pp['scheme_parameters'].distribution,
        'dist_pars': {'bd': pp['ag_bd'], 'wt': pp['ag_wt']},
        'num_coefs': pp['ag_wt'],
        'bti': bti,
        'btd': btd,
        'msg': msg,
        'const_time_flag': False}


def make_agg_coefs(pp: PublicParameters, otvks: List[OneTimeVerificationKey],
                   msgs: List[Message]) -> List[AggCoef]:
    hash2polyinput = prepare_hash2polyinput(pp=pp, otvks=otvks, msgs=msgs)
    return [hash2polynomial(**hash2polyinput, salt=pp['ag_salt'] + str(i)) for i in range(len(otvks))]


def prepare_aggregate(otvks: List[OneTimeVerificationKey], msgs: List[Message], sigs: List[Signature]) -> Tuple[
    List[OneTimeVerificationKey], List[Message], List[Signature]]:
    zipped_data = list(zip(otvks, msgs, sigs))
    zipped_data_srt_by_key = sorted(zipped_data, key=lambda x: str(x[0]))
    srt_keys, srt_msgs, srt_sigs = ([i[j] for i in zipped_data_srt_by_key] for j in range(len(zipped_data[0])))
    return srt_keys, srt_msgs, srt_sigs


def aggregate(pp: PublicParameters, otvks: List[OneTimeVerificationKey], msgs: List[Message],
              sigs: List[Signature]) -> Signature:
    srt_keys, srt_msgs, srt_sigs = prepare_aggregate(otvks=otvks, msgs=msgs, sigs=sigs)
    ag_coefs = make_agg_coefs(pp=pp, otvks=otvks, msgs=msgs)
    return sum([sig ** ag_coef for sig, ag_coef in zip(srt_sigs, ag_coefs)])


def aggregate_verify(pp: PublicParameters, otvks: List[OneTimeVerificationKey], msgs: List[Message],
                     ag_sig: Signature) -> bool:
    cnw: List[Tuple[Dict[int, int], int, int]] = ag_sig.get_coef_rep()
    n, w = max(i[1] for i in cnw), max(i[2] for i in cnw)
    if n < 1 or n > pp['avf_bd'] or w < 1 or w > pp['avf_wt'] or len(otvks) < 1 or \
            len(otvks) > pp['ag_cap'] or len(otvks) != len(msgs):
        return False

    challenges: List[Polynomial] = [make_signature_challenge(pp=pp, otvk=otvk, msg=msg) for otvk, msg in
                                    zip(otvks, msgs)]
    zipped_keys_msgs_and_challs = list(zip(otvks, msgs, challenges))
    srt_otvks, sorted_msgs, sorted_challs = (
        [i[j] for i in sorted(zipped_keys_msgs_and_challs, key=lambda x: str(x[0]))]
        for j in range(len(zipped_keys_msgs_and_challs[0])))
    ag_coefs = make_agg_coefs(pp=pp, otvks=srt_otvks, msgs=sorted_msgs)
    sum_of_otvks: Polynomial = sum(
        [(otvk[0] * c + otvk[1]) * ag_coef for ag_coef, c, otvk in zip(ag_coefs, sorted_challs, srt_otvks)])
    return pp['scheme_parameters'].key_ch * ag_sig == sum_of_otvks
