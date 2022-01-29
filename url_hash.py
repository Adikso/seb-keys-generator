from hashlib import sha256


def generate_url_hash(url, key):
    hashed = sha256()
    hashed.update(url.encode())
    hashed.update(key.encode())
    return hashed.hexdigest()
