import base64
import hashlib
import hmac

from config_key import generate_config_key
from pe_utils import get_signer_certificate_hash, get_file_version


def generate_browser_key(pe, config):
    key = bytes()
    if 'examKeySalt' in config:
        key = base64.b64decode(config['examKeySalt'])

    payload = get_signer_certificate_hash(pe) + get_file_version(pe) + generate_config_key(config).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()
