# -*- coding: utf-8 -*-

"""
            xstrip_auth.py:
Cryptographically strong pseudorandom key
generator based on the `XStrip Algorithm`
"""

__author__ = "Miraculous Owonubi"
__copyright__ = "Copyright 2019"
__credits__ = ["Miraculous Owonubi"]
__license__ = "Apache-2.0"
__version__ = "0.1.0"
__maintainer__ = "Miraculous Owonubi"
__email__ = "omiraculous@gmail.com"
__status__ = "Development"


def noop(key):
    return key


class XStripKey():
    import base64 as __base64
    import re as __re

    __compiled_export = __re.compile(
        r'(?P<iterations>\d+):(?P<salt>[a-z0-9]+)/(?P<key>[a-f0-9]+)')

    def __init__(self, h_ash, salt, iterations=int(10e4), hf="sha256"):
        self.__hf = hf
        self.__salt = bytes(salt)
        self.__encoded = bytes(h_ash)
        self.__iterations = iterations

    @classmethod
    def __parseComponents(self, content):
        return self.__compiled_export.match(self.__base64.b64decode(content.encode() if type(content) is str else bytes(content)).decode()).groupdict()

    def __repr__(self):
        return "[\x1b[32m%s\x1b[0m](\x1b[36m%d\x1b[0m): \x1b[33m%a\x1b[0m" % (self.__hf, len(self.__encoded), self.hex.decode())

    def __eq__(self, other):
        return type(other) == XStripKey and self.__salt == other.__salt and self.__iterations == other.__iterations and self.__hf == self.__hf and self.__encoded == self.__encoded

    @property
    def hex(self):
        return self.__encoded.hex().encode()

    @property
    def hf(self):
        return self.__hf

    @property
    def salt(self):
        return self.__salt

    @property
    def iterations(self):
        return self.__iterations

    def verify(self, key, encoder=noop):
        return self.__encoded == XStripKeyConstruct(key, iterations=self.iterations).generateKey(salt=self.salt, encoder=encoder).__encoded

    def matchExec(self, key, fn, *args, encoder=noop):
        return fn(*args) if self.verify(key, encoder) else None

    def mismatchExec(self, key, fn, *args, encoder=noop):
        return fn(*args) if not self.verify(key, encoder) else None

    def codes(self):
        return [code for code in self.__encoded]

    def export(self):
        xprt = "%d:%s/%s" % (self.__iterations,
                             self.__salt.hex(), self.__encoded.hex())
        return self.__base64.b64encode(bytes(xprt, 'utf8'))

    @classmethod
    def parse(self, content):
        components = self.__parseComponents(content)
        return XStripKey(bytes.fromhex(components["key"]), bytes.fromhex(components["salt"]), int(components["iterations"]))


class XStripKeyConstruct():
    from os import urandom as __urandom
    from random import choice as __choice
    from hashlib import pbkdf2_hmac as __pbkdf2

    def __init__(self, key, iterations=None):
        self.__content = key.encode() if type(key) is str else bytes(key)
        self.__iterations = iterations if iterations else int(10e4)

    def generateKey(self, hf='sha256', salt=bytes(), encoder=noop):
        salt = salt if salt else self.__urandom(10)
        return XStripKey(encoder(self.__pbkdf2(
            hf, self.__content, salt, self.__iterations)), salt, self.__iterations, hf=hf)


if __name__ == "__main__":
    raise Exception(
        "This is a library not meant to be executed as a standalone script")
