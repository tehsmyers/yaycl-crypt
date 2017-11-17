import hashlib
import os
import sys
import traceback
import warnings
from collections import namedtuple

try:
    # py2
    from cStringIO import StringIO
except ImportError:
    # py3
    from io import StringIO

import lya
import yaml
from Crypto.Cipher import AES

YamlNames = namedtuple('YamlNames', ['unencrypted', 'encrypted'])


class YayclCryptError(Exception):
    """Exception type for yaycl_crypt errors"""
    pass


class YayclCryptWarning(UserWarning):
    """Warning issued by yaycl_crypt when it's confused"""
    pass


def _yamls(file_path):
    # boilerplate for getting yaml and eyaml files
    file_dir, file_base = os.path.split(file_path)
    file, extension = os.path.splitext(file_base)
    if extension:
        # if there's an extension, slap an 'e' after the period
        # so e.g. .yaml become .eyaml
        encrypted_extension = extension.replace('.', '.e', 1)
    else:
        # if there's no extension, make one up (.e)
        encrypted_extension = '.e'
    file_encrypted = os.path.join(file_dir, '{}{}'.format(file, encrypted_extension))
    return YamlNames(file_path, file_encrypted)


def encrypt_yaml(conf, conf_key, delete=True):
    """Write a config to the conf dir as encrypted yaml

    By default, this removes the unencrypted version on a config after encypting."""
    yaml_file = _yamls(conf.file_path(conf_key))
    cipher = crypt_cipher(**conf._yaycl)

    # write out the encrypted yaml
    yaml_output = StringIO()
    # force a reload before encrypting
    del(conf[conf_key])
    conf[conf_key].dump(yaml_output)
    yaml_output.seek(0)
    with open(yaml_file.encrypted, 'wb') as eyaml:
        output = yaml_output.read()
        # pad the output to match the key len
        output += ' ' * (16 - (len(output) % 16))
        eyaml.write(cipher.encrypt(output))

    # remove the unencrypted yaml if it exists
    if delete and os.path.exists(yaml_file.unencrypted):
        os.remove(yaml_file.unencrypted)


def decrypt_yaml(conf, conf_key, delete=True):
    """Write an encrypted config to the conf dir as unencrypted yaml"""
    yaml_file = _yamls(conf.file_path(conf_key))
    cipher = crypt_cipher(**conf._yaycl)

    if os.path.exists(yaml_file.unencrypted):
        raise YayclCryptError('Unencrypted conf conf exists; refusing to overwrite it')

    # decrypt the target yaml without loading it
    with open(yaml_file.unencrypted, 'wb') as yaml, open(yaml_file.encrypted, 'rb') as eyaml:
        yaml.write(cipher.decrypt(eyaml.read()))

    # remove the encrypted yaml if it exists
    if delete and os.path.exists(yaml_file.encrypted):
        os.remove(yaml_file.encrypted)


def crypt_key_hash(data=None, **options):
    """Retrieve the key hash used for encryption/decryption

    This behaves several different ways to support loading a file to generate the key hash.
    For usage, it's best to use keyword arguments, and then one at a time. Otherwise,
    use one of the YAYCL_CRYPT_* environment variables.

    * If ``crypt_key`` kwarg is set, its value will be hashed
    * If ``crypt_key_file`` kwarg is set, its value will be loaded and hashed
    * If the YAYCL_CRYPT_KEY env var is set, its value will be hashed
    * If the YAYCL_CRYPT_KEY_FILE env var is set, its contents will be loaded and hashed

    All values are stripped before hashing.

    This should make it as flexible as possible to load a key from just about anywhere,
    and if not it should be trivial to extend this function to make it possible.

    Note:

        Values in ``options`` kwargs should be set when instantiating the yaycl.Config object,
        e.g.:

            conf = yaycl.Config('/path/to/config_dir', crypt_key='my_super_secret')
            # or
            conf = yaycl.Config('/path/to/config_dir', crypt_key_file='/path/to/key_file')

    """
    # If the key data can be, do so, otherwise define key_file and get data from there
    if 'crypt_key' in options:
        data = options['crypt_key']
    elif 'crypt_key_file' in options:
        key_file = options['crypt_key_file']
    elif "YAYCL_CRYPT_KEY" in os.environ:
        data = os.environ["YAYCL_CRYPT_KEY"]
    elif "YAYCL_CRYPT_KEY_FILE" in os.environ:
        key_file = os.environ["YAYCL_CRYPT_KEY_FILE"]
    else:
        raise YayclCryptError('Unable to load key for yaml decryption')

    # if data isn't set, key_file is;
    # get the key data to hash from key_file
    if not data:
        with open(str(key_file).strip(), 'rb') as f:
            # data is read as bytes
            data = f.read()
    else:
        # key data came from string inputs, convert to bytes
        data = data.encode('utf-8')

    return hashlib.sha256(data)


def crypt_cipher(data=None, **options):
    key = crypt_key_hash(data, **options)
    # TODO: cipher should be configurable; just need to come up with a
    # decent way to pull the type and mode out of a config
    return AES.new(key.digest(), AES.MODE_ECB)


def load_yaml(file_path, **options):
    yaml_file = _yamls(file_path)

    # If the encrypted yaml doesn't exist, bail out
    if not os.path.exists(yaml_file.encrypted):
        return

    # If there's an unencyrpted yaml, issue a warning and bail out
    if os.path.exists(yaml_file.unencrypted):
        warn_msg = ('yaml "{}" and eyaml present for "{}" config. '
            'Ignoring encrypted yaml.').format(*yaml_file)
        warnings.warn(warn_msg, YayclCryptWarning)
        return

    # set up the crypt!
    cipher = crypt_cipher(**options)

    # Sanity achieved; attempt decryption
    loaded_yaml = lya.AttrDict()
    with open(yaml_file.encrypted, 'rb') as eyaml:
        decrypted_yaml = cipher.decrypt(eyaml.read())
    try:
        loaded_conf = yaml.load(decrypted_yaml, Loader=lya.OrderedDictYAMLLoader)
    except Exception as exc:
        msg = '{} when loading {}, yaycl crypt key may be incorrect. Original traceback:\n{}'
        raise YayclCryptError(msg.format(type(exc), yaml_file.encrypted, exc))
    loaded_yaml.update(loaded_conf)

    return loaded_yaml
