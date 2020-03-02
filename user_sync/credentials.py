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

yaml = YAML()


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

    def store_umapi(self, filename):
        data = self.read(filename)
        data['enterprise']['org_id'] = {'secure': 'XXXXXXXX'}
        data['enterprise']['api_key'] = {'secure': 'XXXXXXXX'}
        data['enterprise']['client_secret'] = {'secure': 'XXXXXXXX'}
        data['enterprise']['tech_acct'] = {'secure': 'XXXXXXXX'}
        self.write(filename, data)

    def store_ldap(self, filename):
        data = self.read(filename)
        data['password'] = {'secure': 'XXXXXXXX'}
        self.write(filename, data)

    def store_okta(self, filename):
        data = self.read(filename)
        data['host'] = {'secure': 'XXXXXXXX'}
        data['api_token'] = {'secure': 'XXXXXXXX'}
        self.write(filename, data)

    def store_console(self, filename):
        data = self.read(filename)
        data['integration']['org_id'] = {'secure': 'XXXXXXXX'}
        data['integration']['api_key'] = {'secure': 'XXXXXXXX'}
        data['integration']['client_secret'] = {'secure': 'XXXXXXXX'}
        data['integration']['tech_acct'] = {'secure': 'XXXXXXXX'}
        self.write(filename, data)

    def read(self, filename):
        with open(filename) as file:
            file_dict = yaml.load(file)
        return file_dict

    def write(self, filename, data):
        with open(filename, 'w') as file:
            yaml.dump(data, file)

    def retrieve(self, filename):
        credentials = self.read(filename)
        # some logic to remove the irrelevant keys
        return credentials

    def revert(self):
        pass
