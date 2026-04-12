import hashlib
from pyfrost.frost import verify_group_signature

# 1. The data from your actual API response
# This matches the output from the signing process, including the message which is the hash of the document and timestamp.
aggregated_result = {
    "nonce": "0xB09F951B22b4b6C35f6E79B888bdD84108cB3Cd8",
    "public_nonce": {
      "x": "0xdd8819de5929079e174d4b1149e2633996b9b90e156baed1ade3166f66387eac",
      "y_parity": 1
    },
    "public_key": {
      "x": "0x137e3ccf69b87c10f4e05bf0b7b3b231f704f0a9ce014dd54a38c7fd4b685e0d",
      "y_parity": 1
    },
    "signature": int("0xf3a33e039ad7b8433323279c1c77ae8639da4111c327dfbace4bdb3efaeff4c0",16),
    "message": "7c221ec2079af76cfd3223a00162bbbd9ee011c07866a8c615ba762c2ad4554a",
    "key_type": "ETH"
}

# 2. User inputs to verify
# These should match the original inputs used to create the signature. 
doc_hash = "b89a0ba09908823b02a5db3c273249521101f3aeaea3275c067db4743d10b740"
timestamp = "2026-04-12T08:41:38.414214+00:00"

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