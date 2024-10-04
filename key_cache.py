class KeyCache:
    def __init__(self):
        """Initialize the KeyCache with an empty key store."""
        self.key_store = {}  # Dictionary to store keys by (association_number, channel_id)
        self.current_keys = {}  # Dictionary to track current keys for association numbers

    def add_key(self, association_number, channel_id, key):
        """Add a new key for a specific association number and channel."""
        self.key_store[(association_number, channel_id)] = key
        self.current_keys[association_number] = key
        print(f"Key added for Association Number {association_number}, Channel ID {channel_id}.")

    def get_key(self, association_number, channel_id):
        """Retrieve the current key for a specific association number and channel."""
        return self.key_store.get((association_number, channel_id), None)

    def rotate_key(self, association_number, channel_id, new_key):
        """Rotate the key for a specific association number and channel."""
        if (association_number, channel_id) in self.key_store:
            self.key_store[(association_number, channel_id)] = new_key
            self.current_keys[association_number] = new_key
            print(f"Key rotated for Association Number {association_number}, Channel ID {channel_id}.")
        else:
            print(f"No existing key found for Association Number {association_number}, Channel ID {channel_id}.")

    def get_current_key(self, association_number):
        """Retrieve the current key for a specific association number."""
        return self.current_keys.get(association_number, None)
