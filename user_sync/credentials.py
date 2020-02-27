import logging
import os
import sys

from ruamel.yaml import YAML
import keyrings.cryptfile.cryptfile
from keyring.errors import KeyringError

from user_sync.error import AssertionException

keyrings.cryptfile.cryptfile.CryptFileKeyring.keyring_key = "none"

import keyring

if (isinstance(keyring.get_keyring(), keyring.backends.fail.Keyring) or
        isinstance(keyring.get_keyring(), keyring.backends.chainer.ChainerBackend)):
    keyring.set_keyring(keyrings.cryptfile.cryptfile.CryptFileKeyring())


class CredentialManager:

    def __init__(self):
        self.username = 'user_sync'
        self.logger = logging.getLogger("credential_manager")
        self.keyring_name = keyring.get_keyring().name

    def get(self, identifier, username=None):
        try:
            self.logger.debug("Using keyring '{0}' to retrieve '{1}'".format(self.keyring_name, identifier))
            return keyring.get_password(identifier, username or self.username)
        except KeyringError as e:
            raise AssertionException("Error retrieving value for identifier '{0}': {1}".format(identifier, str(e)))

    def set(self, identifier, value):
        try:
            self.logger.debug("Using keyring '{0}' to set '{1}'".format(self.keyring_name, identifier))
            keyring.set_password(identifier, self.username, value)
        except KeyringError as e:
            raise AssertionException("Error in setting credentials '{0}' : {1}".format(identifier, str(e)))
        except Exception as e:
            if "stub received bad data" in str(e):
                raise AssertionException("Value for {0} too long for backend to store: {1}".format(identifier, str(e)))
            raise e

    def store(self):
        yaml = YAML()
        stream = open(os.path.abspath(r'C:\Users\Dale.Dybvig\repos\user-sync.py\user_sync\resources\connector-ldap.yml'))
        another_stream = open(os.path.relpath(r'resources\connector-ldap.yml'))
        ldap = yaml.load(another_stream)
        # for key, value in ldap.items():
        #     if key == 'password':
        #         value = 'secure: XXXXXXX'
        password = ldap['password']
        ldap = yaml.dump(ldap, sys.stdout)
        return ldap
