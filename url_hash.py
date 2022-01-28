from hashlib import sha256


def generate_url_hash(url, browser_key):
    hashed = sha256()
    hashed.update(url.encode())
    hashed.update(browser_key.encode())
    return hashed.hexdigest()
