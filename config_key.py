import json
import zlib
import rncryptor

from hashlib import sha256
from xml.dom import minidom
from sortedcontainers import SortedDict

types = ['string', 'real', 'integer', 'date', 'true', 'false', 'data', 'array', 'dict']


class RNCryptor_modified(rncryptor.RNCryptor):
    def post_decrypt_data(self, data):
        data = data[:-(data[-1])]
        return data


def decrypt_config(data, password):
    cryptor = RNCryptor_modified()
    decrypted_data = cryptor.decrypt(data[4:], password)
    return zlib.decompress(decrypted_data, 15 + 32)


def convert_config_to_dict(xml_data):
    doc = minidom.parseString(xml_data)
    dictionary = doc.lastChild.getElementsByTagName('dict')[0]
    json_data = build_node(dictionary)

    if 'originatorVersion' in json_data:
        del json_data['originatorVersion']

    return json_data


def generate_config_key(json_data):
    json_text = json.dumps(json_data, separators=(',', ':'))
    return sha256(json_text.encode()).hexdigest()


def build_node(parent_node):
    if parent_node.nodeName == 'array':
        json_data = []
    else:
        json_data = SortedDict(str.lower)

    if not parent_node:
        return json_data

    for node in parent_node.childNodes:
        if node.nodeName not in types:
            continue

        ps = node.previousSibling
        while ps and ps.nodeName == '#text' and ps.previousSibling:
            ps = ps.previousSibling

        key = None
        if ps and ps.nodeName == 'key':
            key = ps.firstChild.nodeValue

        value = node.firstChild.nodeValue if node.childNodes else None
        if node.nodeName == 'date':
            pass
        elif node.nodeName == 'data':
            pass
        elif node.nodeName == 'string':
            if value is None:
                value = ''
        elif node.nodeName == 'real':
            value = float(value)
        elif node.nodeName == 'integer':
            value = int(value)
        elif node.nodeName == 'true' or node.nodeName == 'false':
            value = node.nodeName == 'true'
        elif node.nodeName == 'array':
            value = build_node(node)
            if value is None:
                value = []
        elif node.nodeName == 'dict':
            value = build_node(node)

        if parent_node.nodeName == 'array':
            json_data.append(value)
        else:
            json_data[key] = value

    return json_data
