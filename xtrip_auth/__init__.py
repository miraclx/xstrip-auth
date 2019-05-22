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

import binascii
import hashlib
import random
import base64
import os


def noop(key):
    return key


class XStripKey():
    def __init__(self, h_ash, salt, iterations):
        self.__salt = salt
        self.__encoded = h_ash
        self.__iterations = iterations

    @property
    def content(self):
        return self.__encoded

    def verify(self, key, encoder=noop):
        return self.__encoded == XStripKeyConstruct(key).generateKey(salt=self.__salt, iterations=self.__iterations, encoder=encoder).content

    def hexlify(self):
        return binascii.hexlify(self.content)


class XStripKeyConstruct():
    def __init__(self, key):
        self.__content = key.encode()

    def generateKey(self, iterations=int(), salt=bytes(), encoder=noop):
        iterations = iterations if iterations else random.choice(
            range(10000, 100000))
        salt = salt if salt else os.urandom(10)
        return XStripKey(encoder(hashlib.pbkdf2_hmac(
            'sha512', self.__content, salt, iterations)), salt, iterations)
