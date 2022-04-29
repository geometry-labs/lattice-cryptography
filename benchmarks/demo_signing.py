""" Little demo that signs and then verifies a message. """
from lattice_cryptography.lm_one_time_sigs import *

# Pick your message
message: str = "QRL is awesome!"

# Step 0: Create setup parameters (with 256 bits of post-quantum security).
public_parameters = make_setup_parameters(secpar=256)

# Step 1: Key generation
secret_seed, signing_key, verification_key = keygen(pp=public_parameters, num_keys_to_gen=1)[0]

# Step 2: Sign a message
signature = sign(pp=public_parameters, otk=(secret_seed, signing_key, verification_key), msg=message)

# Step 3: Verify the signature
if verify(pp=public_parameters, otvk=verification_key, sig=signature, msg=message):
    print("Signature is valid")
else:
    print("!! Signature is NOT valid")
