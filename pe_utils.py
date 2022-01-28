import pefile
from OpenSSL import crypto
from OpenSSL.crypto import _lib, _ffi, X509


def get_certificates(self):
    certs = _ffi.NULL
    if self.type_is_signed():
        certs = self._pkcs7.d.sign.cert
    elif self.type_is_signedAndEnveloped():
        certs = self._pkcs7.d.signed_and_enveloped.cert

    pycerts = []
    for i in range(_lib.sk_X509_num(certs)):
        pycert = X509.__new__(X509)
        pycert._x509 = _lib.sk_X509_value(certs, i)
        pycerts.append(pycert)

    if not pycerts:
        return None

    return tuple(pycerts)


def get_signer_certificate_hash(pe):
    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ].VirtualAddress

    signature = pe.write()[address + 8:]

    pkcs = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, bytes(signature))
    certs = get_certificates(pkcs)

    c = crypto.dump_certificate(crypto.FILETYPE_PEM, certs[-1])
    a = crypto.load_certificate(crypto.FILETYPE_PEM, c)
    return a.digest("sha1").replace(b':', b'').upper()


def get_file_version(pe):
    for entry in pe.FileInfo[0]:
        if entry.name != 'StringFileInfo':
            continue

        for st in entry.StringTable:
            for sub_entry in st.entries.items():
                if sub_entry[0] == b'FileVersion':
                    return sub_entry[1]

    return None
