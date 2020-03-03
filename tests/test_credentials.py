import uuid

import pytest

from user_sync.credentials import *
from user_sync.error import AssertionException


def test_set():
    identifier = 'TestId'
    value = 'TestValue'
    cm = CredentialManager()
    cm.set(identifier, value)


def test_get():
    identifier = 'TestId2'
    value = 'TestValue2'
    cm = CredentialManager()
    # Assume set works
    cm.set(identifier, value)
    assert cm.get(identifier) == value


def test_set_long():
    identifier = 'TestId3'
    cm = CredentialManager()
    value = "".join([str(uuid.uuid4()) for x in range(500)])

    if isinstance(keyring.get_keyring(), keyring.backends.Windows.WinVaultKeyring):
        with pytest.raises(AssertionException):
            cm.set(identifier, value)
    else:
        cm.set(identifier, value)
        assert cm.get(identifier) == value


def test_get_not_valid():
    # This is an identifier which should not exist in your backed.
    identifier = 'DoesNotExist'
    # keyring.get_password returns None when it cannot find the identifier (such as the case of a typo). No exception
    # is thrown in this case. This case is handled in app.py, which will throw an AssertionException if
    # CredentialManager.get() returns None.
    assert CredentialManager().get(identifier) is None


def test_store_umapi():
    umapi_path = os.path.relpath(r'fixture\connector-umapi.yml')
    credman = CredentialManager()
    unchanged_umapi_dict = credman.read(umapi_path)
    credman.store_umapi(umapi_path)
    secure_umapi_dict = credman.read(umapi_path)
    assert secure_umapi_dict['enterprise']['org_id'] == {'secure': 'XXXXXXXX'}
    assert secure_umapi_dict['enterprise']['api_key'] == {'secure': 'XXXXXXXX'}
    assert secure_umapi_dict['enterprise']['client_secret'] == {'secure': 'XXXXXXXX'}
    assert secure_umapi_dict['enterprise']['tech_acct'] == {'secure': 'XXXXXXXX'}
    credman.write(umapi_path, unchanged_umapi_dict)


def test_store_ldap():
    ldap_path = os.path.relpath(r'fixture\connector-ldap.yml')
    credman = CredentialManager()
    unchanged_ldap_dict = credman.read(ldap_path)
    credman.store_ldap(ldap_path)
    secure_ldap_dict = credman.read(ldap_path)
    assert secure_ldap_dict['password'] == {'secure': 'XXXXXXXX'}
    credman.write(ldap_path, unchanged_ldap_dict)


def test_store_okta():
    okta_path = os.path.relpath(r'fixture\connector-okta.yml')
    credman = CredentialManager()
    unchanged_okta_dict = credman.read(okta_path)
    credman.store_okta(okta_path)
    secure_okta_dict = credman.read(okta_path)
    assert secure_okta_dict['host'] == {'secure': 'XXXXXXXX'}
    assert secure_okta_dict['api_token'] == {'secure': 'XXXXXXXX'}
    credman.write(okta_path, unchanged_okta_dict)


def test_store_console():
    console_path = os.path.relpath(r'fixture\connector-adobe-console.yml')
    credman = CredentialManager()
    unchanged_console_dict = credman.read(console_path)
    credman.store_console(console_path)
    secure_console_dict = credman.read(console_path)
    assert secure_console_dict['integration']['org_id'] == {'secure': 'XXXXXXXX'}
    assert secure_console_dict['integration']['api_key'] == {'secure': 'XXXXXXXX'}
    assert secure_console_dict['integration']['client_secret'] == {'secure': 'XXXXXXXX'}
    assert secure_console_dict['integration']['tech_acct'] == {'secure': 'XXXXXXXX'}
    credman.write(console_path, unchanged_console_dict)