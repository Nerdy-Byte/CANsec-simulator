# Global key store and current keys dictionary
key_store = {}  # Dictionary to store keys by (association_number, channel_id)
current_keys = {}  # Dictionary to track current keys for association numbers

# Global ASSOCIATION_NUMBER variable
ASSOCIATION_NUMBER = 0  # Initially set to 0


def add_key(channel_id, key):
    """Add a new key for the current global association number and channel."""
    global key_store, current_keys, ASSOCIATION_NUMBER

    # Validate key length for AES (16, 24, or 32 bytes)
    if len(key) not in {16, 24, 32}:
        raise ValueError("Invalid key size! Key must be 16, 24, or 32 bytes long.")

    key_store[(ASSOCIATION_NUMBER, channel_id)] = key
    current_keys[ASSOCIATION_NUMBER] = key
    print(f"Key added for Association Number {ASSOCIATION_NUMBER}, Channel ID {channel_id}.")


def get_key(association_number, channel_id):
    """Retrieve the current key for the global association number and channel."""
    global key_store
    return key_store.get((association_number, channel_id), None)


def rotate_key(channel_id, new_key):
    """Rotate the key for the global association number and channel, and toggle the association number."""
    global key_store, current_keys, ASSOCIATION_NUMBER

    # Rotate the global ASSOCIATION_NUMBER (flip between 0 and 1)
    ASSOCIATION_NUMBER = 1 - ASSOCIATION_NUMBER

    # Check if the key exists for the current ASSOCIATION_NUMBER
    if (ASSOCIATION_NUMBER, channel_id) in key_store:
        key_store[(ASSOCIATION_NUMBER, channel_id)] = new_key
        current_keys[ASSOCIATION_NUMBER] = new_key
        print(f"Key rotated for Association Number {ASSOCIATION_NUMBER}, Channel ID {channel_id}.")
    else:
        print(f"No existing key found for Association Number {ASSOCIATION_NUMBER}, Channel ID {channel_id}.")


def get_current_key():
    """Retrieve the current key for the global association number."""
    global current_keys, ASSOCIATION_NUMBER
    return current_keys.get(ASSOCIATION_NUMBER, None)


def print_all_keys():
    """Print all keys stored in key_store and current_keys."""
    global key_store, current_keys

    print("All keys in key_store:")
    if key_store:
        for (association_number, channel_id), key in key_store.items():
            print(f"Association Number: {association_number}, Channel ID: {channel_id}, Key: {key.hex()}")
    else:
        print("No keys found in key_store.")

    print("\nCurrent keys in current_keys:")
    if current_keys:
        for association_number, key in current_keys.items():
            print(f"Association Number: {association_number}, Key: {key.hex()}")
    else:
        print("No keys found in current_keys.")
