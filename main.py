import gzip
import fire
import pefile

from browser_key import generate_browser_key
from config_key import decrypt_config, generate_config_key, convert_config_to_dict
from url_hash import generate_url_hash


def load_config(file_name, password):
    with open(file_name, 'rb') as file:
        file_content = file.read()

    if not file_content.startswith(b'<?xml'):
        file_content = gzip.decompress(file_content)
        file_content = decrypt_config(file_content, password)

    return convert_config_to_dict(file_content)


class Application(object):
    def config(self, url, file_name, password):
        config = load_config(file_name, password)
        config_key = generate_config_key(config)

        return generate_url_hash(url, config_key)

    def browser(self, exe_file_name, config_file_name, config_password):
        config = load_config(config_file_name, config_password)

        pe = pefile.PE(exe_file_name)
        return generate_browser_key(pe, config)

    def request(self, url, exe_file_name, config_file_name, config_password):
        config = load_config(config_file_name, config_password)

        pe = pefile.PE(exe_file_name)
        browser_key = generate_browser_key(pe, config)

        return generate_url_hash(url, browser_key)


if __name__ == '__main__':
    fire.Fire(Application())
