import hashlib
from pyfrost.frost import verify_group_signature

# 1. The data from your actual API response
# This matches the output from the signing process, including the message which is the hash of the document and timestamp.
aggregated_result = {
    "nonce": "0x731c8391E258100b800B06B5954DF557262B002E",
    "public_nonce": {
      "x": "0x510d343909dd6d82439edd2966480e50b450c6493e5b9850daefcf7ed51e35ce",
      "y_parity": 0
    },
    "public_key": {
      "x": "0x9f988b4e0fb34935439440060fa05064f7a5efe2d657d1421baab06b9d991462",
      "y_parity": 0
    },
    "signature": int("0x27418c1c6fb5f7fabd0bd46a20496f19ad63b1496fc819427263ca64be1055bc",16),
    "message": "ad32087ea0293edcb2332c8a12489b92a9ee7a1ea21903bc0be280209695cb9c",
    "key_type": "BTC"
  
}

# 2. User inputs to verify
# These should match the original inputs used to create the signature. 
doc_hash = "c5255366bf9202e5aac8796ba2568b015ee4c99c4f7121d66bf2cacf88d7c00b"
timestamp = "2026-04-08T08:52:43.857002+00:00"

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