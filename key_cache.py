from typing import Optional

keys = {0: {}, 1: {}}
# Global ASSOCIATION_NUMBER variable
# ASSOCIATION_NUMBER = 0  # Initially set to 0


def add_key(an: int, channel_id: bytes, key: bytes):
    """
    Add a key for the specified channel_id under the current ASSOCIATION_NUMBER.

    Args:
        :param key: The key to be added for the channel.
        :param channel_id: The channel identifier.
        :param an: Association Number
    """
    # Convert the channel_id to an integer to use as the dictionary key
    channel_id_int = int.from_bytes(channel_id, byteorder='big')

    # Add or update the key in the keys dictionary under the current ASSOCIATION_NUMBER
    keys[an][channel_id_int] = key
    print(f"Key added for channel {channel_id_int} under association number {an}.")


def get_key(association_number: int, channel_id: bytes) -> Optional[bytes]:
    """
    Retrieve the current key for the specified association number and channel.

    Args:
        association_number (int): The association number to use (0 or 1).
        channel_id (bytes): The channel identifier (in bytes).

    Returns:
        Optional[bytes]: The key if found, or raises an exception if not.

    Raises:
        ValueError: If no key is found for the specified association number and channel_id.
    """
    # Convert the channel_id to an integer
    channel_id_int = int.from_bytes(channel_id, byteorder='big')

    # Try to retrieve the key from the keys dictionary
    key: Optional[bytes] = keys.get(association_number, {}).get(channel_id_int)

    if key is None:
        raise ValueError(f"No key found for Association Number {association_number}, Channel ID {channel_id.hex()}")

    return key


# def print_all_keys():
#     """Print all keys stored in key_store and current_keys."""
#     global key_store, current_keys
#
#     print("All keys in key_store:")
#     if key_store:
#         for (association_number, channel_id), key in key_store.items():
#             print(f"Association Number: {association_number}, Channel ID: {channel_id.hex()}, Key: {key.hex()}")
#     else:
#         print("No keys found in key_store.")
#
#     print("\nCurrent keys in current_keys:")
#     if current_keys:
#         for association_number, key in current_keys.items():
#             print(f"Association Number: {association_number}, Key: {key.hex()}")
#     else:
#         print("No keys found in current_keys.")
