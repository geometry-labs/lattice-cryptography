"""
We benchmark the lattice-crypto.lm_one_time_sigs.lm_one_time_sigs module.
"""
from timeit import default_timer as timer
from lattice_cryptography.lm_one_time_sigs import *
from multiprocessing import Pool, cpu_count
from math import ceil

# Benchmarking params
SAMPLE_SIZE: int = 2 ** 8
allowable_secpars = [128, 256]
multiprocessing: bool = True  # << Set to False to disable multiprocessing (WIP)

# Parallelization params
num_cores: int = 64
if multiprocessing and num_cores > 1:
    num_workers = min((num_cores, cpu_count()))
    sample_size_per_core: int = ceil(SAMPLE_SIZE / num_workers)
    print(f"Beginning benchmarks (multiprocessing keygen with {num_workers} workers)")
else:
    num_workers = sample_size_per_core = 0  # N/A
    print(f"Beginning benchmarks (multiprocessing disabled)")


# Helper function
def flatten(some_nested_list: List[List[Any]]) -> List[Any]:
    return [item for sublist in some_nested_list for item in sublist]


# Benchmark parameter setup
for secpar in allowable_secpars:
    print(f"Benchmarking for secpar = {secpar}.")
    print(f"\tParameter generation benchmarking for secpar = {secpar}.")
    print(f"\t\tGenerating parameters.  ")
    start = timer()
    pp = make_setup_parameters(secpar=secpar)
    end = timer()
    print(f"\t\tElapsed time = {end - start}.")

    print(f"\tKey generation benchmarking for secpar = {secpar} without input seeds.")
    print(f"\t\tGenerating {SAMPLE_SIZE} keys.  ")
    start = timer()
    some_keys_without_seeds = keygen(pp=pp, num_keys_to_gen=SAMPLE_SIZE, multiprocessing=multiprocessing)
    end = timer()
    print(f"\t\tElapsed time = {end - start}, averaging {(end - start) / SAMPLE_SIZE} per item.")

    time_with_seeds = 0.
    print(f"\tKey generation benchmarking for secpar = {secpar} with these random seeds.")
    print(f"\t\tRandom seed generation benchmarking for {SAMPLE_SIZE} new random bitstrings.  ")
    start = timer()
    some_seed_strings = [bin(randbelow(2 ** secpar))[2:].zfill(secpar) for _ in range(SAMPLE_SIZE)]
    end = timer()
    time_with_seeds += end - start
    print(f"\t\tElapsed time = {end - start}, averaging {(end - start) / SAMPLE_SIZE} per item.")

    print(f"\t\tInstantiating SecretSeed object with these seeds.  ")
    start = timer()
    some_seeds = [SecretSeed(secpar=secpar, lp=pp['scheme_parameters'].lp, seed=next_seed_str) for next_seed_str in
                  some_seed_strings]
    end = timer()
    time_with_seeds += end - start
    print(f"\t\tElapsed time = {end - start}, averaging {(end - start) / SAMPLE_SIZE} per item.")

    print(f"\t\tGenerating keys from these SecretSeed objects.")
    start = timer()
    some_keys_with_seeds = keygen(pp=pp, num_keys_to_gen=SAMPLE_SIZE, seeds=some_seeds, multiprocessing=multiprocessing)
    end = timer()
    time_with_seeds += end - start
    print(f"\t\tElapsed time = {end - start}, averaging {(end - start) / SAMPLE_SIZE} per item.")
    print(f"\t\tTotal elapsed time = {time_with_seeds}, averaging {time_with_seeds / SAMPLE_SIZE} per item.")

    print(f"\tSignature benchmarking for secpar = {secpar} with keys produced without random seeds.")
    print(f"\t\tRandom message generation benchmarking for {SAMPLE_SIZE} new random bitstrings.  ")
    start = timer()
    some_msgs_for_keys_without_seeds = [bin(randbelow(2 ** secpar))[2:].zfill(secpar) for _ in range(SAMPLE_SIZE)]
    end = timer()
    print(f"\t\tElapsed time = {end - start}, averaging {(end - start) / SAMPLE_SIZE} per item.")

    print(f"\t\tSigning these messages with associated keys.  ")
    start = timer()
    sign_multiprocessing: bool = False  # STILL A WIP - MAY NOT WORK
    sign_input_tuples = [(pp, key, msg) for key, msg in zip(some_keys_without_seeds, some_msgs_for_keys_without_seeds)]
    if sign_multiprocessing and num_cores > 1:
        with Pool(num_workers) as pool:
            some_sigs_for_keys_without_seeds = pool.starmap(func=sign, iterable=sign_input_tuples)
    else:
        some_sigs_for_keys_without_seeds = [sign(*args) for args in sign_input_tuples]
    end = timer()
    print(f"\t\tElapsed time = {end - start}, averaging {(end - start) / SAMPLE_SIZE} per item.")

    print(f"\tSignature benchmarking for secpar = {secpar} with keys produced with random seeds.")
    print(f"\t\tRandom message generation benchmarking for {SAMPLE_SIZE} new random bitstrings.  ")
    start = timer()
    some_msgs_for_keys_with_seeds = [bin(randbelow(2 ** secpar))[2:].zfill(secpar) for _ in range(SAMPLE_SIZE)]
    end = timer()
    print(f"\t\tElapsed time = {end - start}, averaging {(end - start) / SAMPLE_SIZE} per item.")

    print(f"\t\tSigning these messages with associated keys.  ")
    start = timer()
    sign_input_tuples = [(pp, key, msg) for key, msg in zip(some_keys_with_seeds, some_msgs_for_keys_with_seeds)]
    if sign_multiprocessing and num_cores > 1:
        with Pool(num_workers) as pool:
            some_sigs_for_keys_with_seeds = pool.starmap(func=sign, iterable=sign_input_tuples)
    else:
        some_sigs_for_keys_with_seeds = [sign(*args) for args in sign_input_tuples]
    end = timer()
    print(f"\t\tElapsed time = {end - start}, averaging {(end - start) / SAMPLE_SIZE} per item.")

    print(f"\tVerification benchmarking for secpar = {secpar} with keys produced without random seeds.  ")
    start = timer()

    verify_multiprocessing = False  # STILL A WIP - MAY NOT WORK
    verify_input_tuples = [(pp, otk[2], m, sig) for pp, otk, m, sig in
                           zip([pp] * len(some_keys_without_seeds), some_keys_without_seeds,
                               some_msgs_for_keys_without_seeds, some_sigs_for_keys_without_seeds)]
    if verify_multiprocessing and num_cores > 1:
        with Pool(num_workers) as pool:
            results_without_seeds = pool.starmap(func=verify, iterable=verify_input_tuples)
    else:
        results_without_seeds = [verify(*args) for args in verify_input_tuples]
    end = timer()
    print(f"\t\tElapsed time = {end - start}, averaging {(end - start) / SAMPLE_SIZE} per item.")

    print(f"\tVerification benchmarking for secpar = {secpar} with keys produced with random seeds.  ")
    start = timer()
    verify_input_tuples = [(pp, otk[2], m, sig) for pp, otk, m, sig in
                           zip([pp] * len(some_keys_with_seeds), some_keys_with_seeds,
                               some_msgs_for_keys_with_seeds, some_sigs_for_keys_with_seeds)]
    if verify_multiprocessing and num_cores > 1:
        with Pool(num_workers) as pool:
            results_with_seeds = pool.starmap(func=verify, iterable=verify_input_tuples)
    else:
        results_with_seeds = [verify(*args) for args in verify_input_tuples]
    end = timer()
    print(f"\t\tElapsed time = {end - start}, averaging {(end - start) / SAMPLE_SIZE} per item.")

    # Should get all true
    assert all(_ for _ in results_with_seeds + results_without_seeds)
