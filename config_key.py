import json
import plistlib
import zlib
import rncryptor

from hashlib import sha256
from sortedcontainers import SortedDict


class RNCryptor_modified(rncryptor.RNCryptor):
    def post_decrypt_data(self, data):
        data = data[:-(data[-1])]
        return data


def decrypt_config(data, password):
    cryptor = RNCryptor_modified()
    decrypted_data = cryptor.decrypt(data[4:], password)
    return zlib.decompress(decrypted_data, 15 + 32)


class SortedDictCaseInsensitive(SortedDict):
    def __init__(self):
        super().__init__(str.lower)


def convert_config_to_dict(xml_data):
    json_data = plistlib.loads(xml_data, dict_type=SortedDictCaseInsensitive)

    if 'originatorVersion' in json_data:
        del json_data['originatorVersion']

    return json_data


def generate_config_key(json_data):
    json_text = json.dumps(json_data, separators=(',', ':'))
    return sha256(json_text.encode()).hexdigest()
