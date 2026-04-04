import hashlib
from pyfrost.frost import verify_group_signature

# 1. The data from your actual API response
# This matches the output from the signing process, including the message which is the hash of the document and timestamp.
aggregated_result = {
    "nonce": "0x66014Fc2efEcf7968FF8c57568a89EF387aD8e95",
    "public_nonce": {
        "x": "0x69a3f3e6dab19c11c385e95ed3586983f01a9da39f564ae6172581d6ec961535",
        "y_parity": 1
    },
    "public_key": {
        "x": "0xbdf70d2326227e25ef1aa1aaa2a5cc25b35fc8a0127bb6389e892cfe447ceff1",
        "y_parity": 0
    },
    "signature": 115622850418098922954286497366521769672350860602840090711835616549965031143138,
    "message": "981436aff70a48cbfed4b7c1ae1ab3353b262e1b2216bd3f3d55fe34383aae7b",
    "key_type": "ETH"
}

# 2. User inputs to verify
# These should match the original inputs used to create the signature. 
doc_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
timestamp = "2026-03-20T14:36:41.335377+00:00"

def verify_proof(h, ts, sig_obj):
    # Reconstruct the binding to verify integrity
    binding = f"{h}|{ts}"
    expected_message = hashlib.sha256(binding.encode()).hexdigest()
    
    if expected_message != sig_obj["message"]:
        return False, "Binding mismatch: Timestamp or Hash tampered."
    
    # Pass the entire dictionary if the function expects 1 argument
    is_valid = verify_group_signature(sig_obj)
    
    return is_valid, "Signature is valid." if is_valid else "Mathematical verification failed."
# Run
valid, reason = verify_proof(doc_hash, timestamp, aggregated_result)
print(f"Result: {'Success' if valid else 'Failed'} {reason}")