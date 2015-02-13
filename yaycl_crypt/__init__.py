import hashlib
import os
from collections import namedtuple
from cStringIO import StringIO
from warnings import warn

import lya
import yaml
from Crypto.Cipher import AES

YamlNames = namedtuple('YamlNames', ['unencrypted', 'encrypted'])


class YaycleCryptError(Exception):
    """Exception type for yaycl_crypt errors"""
    pass

def _yamls(conf, conf_key):
    # boilerplate for getting yaml and eyaml filenames
    filename_base = os.path.join(conf._yaycl.config_dir, conf_key)
    filename_unencrypted = '{}.yaml'.format(filename_base)
    filename_encrypted = '{}.eyaml'.format(filename_base)
    return YamlNames(filename_unencrypted, filename_encrypted)


def encrypt_yaml(conf, conf_key, delete=True):
    """Write a config to the conf dir as encrypted yaml

    By default, this removes the unencrypted version on a config after encypting."""
    yaml_file = _yamls(conf, conf_key)
    cipher = crypt_cipher(conf)

    # write out the encrypted yaml
    yaml_output = StringIO()
    conf[conf_key].dump(yaml_output)
    yaml_output.seek(0)
    with open(yaml_file.encrypted, 'w') as eyaml:
        output = yaml_output.read()
        # pad the output to match the key len
        output += ' ' * (16 - (len(output) % 16))
        eyaml.write(cipher.encrypt(output))

    # remove the unencrypted yaml if it exists
    if delete and os.path.exists(yaml_file.unencrypted):
        os.remove(yaml_file.unencrypted)


def decrypt_yaml(conf, conf_key, delete=True):
    """Write an encrypted config to the conf dir as unencrypted yaml"""
    yaml_file = _yamls(conf, conf_key)

    if os.path.exists(yaml_file.unencrypted):
        raise YayclCryptError('Unencrypted conf conf exists; refusing to overwrite it')

    conf.save(conf_key)

    # remove the encrypted yaml if it exists
    if delete and os.path.exists(yaml_file.encrypted):
        os.remove(yaml_file.encrypted)


def crypt_key_hash(conf, data=None):
    """Retrieve the key hash used for encryption/decryption

    This behaves several different ways to support loading a file to generate the key hash.
    For usage, it's best to use keyword arguments, and then one at a time. Otherwise,
    use one of the YAYCL_CRYPT_* environment variables.

    * If ``conf._yaycl.crypt_key`` is set, its value will be hashed
    * If ``conf._yaycl.crypt_key_file`` is set, its value will be loaded and hashed
    * If the YAYCL_CRYPT_KEY env var is set, its value will be hashed
    * If the YAYCL_CRYPT_KEY_FILE env var is set, its contents will be loaded and hashed

    All values are stripped before hashing.

    This should make it as flexible as possible to load a key from just about anywhere,
    and if not it should be trivial to extend this function to make it possible.

    Note:

        Values in ``conf._yaycl`` should be set when instantiating the yaycl.Config object,
        e.g.:

            conf = yaycl.Config('/path/to/config_dir', crypt_key='my_super_secret')
            # or
            conf = yaycl.Config('/path/to/config_dir', crypt_key_file='/path/to/key_file')

    """
    # If the key data can be, do so, otherwise define key_file and get data from there
    if 'crypt_key' in conf._yaycl:
        data = conf._yaycl.crypt_key
    elif 'crypt_key_file' in conf._yaycl:
        key_file = conf._yaycl.crypt_key_file
    elif "YAYCL_CRYPT_KEY" in os.environ:
        data = os.environ["YAYCL_CRYPT_KEY"]
    elif "YAYCL_CRYPT_KEY_FILE" in os.environ:
        key_file = os.environ["YAYCL_CRYPT_KEY_FILE"]
    else:
        raise YayclCryptError('Unable to load key for yaml decryption')

    # if data isn't set, key_file is;
    # get the key data to hash from key_file
    if not data:
        with open(str(key_file).strip()) as f:
            data = f.read()

    return hashlib.sha256(str(data).strip())


def crypt_cipher(conf, data=None):
    key = crypt_key_hash(conf, data)
    # TODO: cipher should be configurable; just need to come up with a
    # decent way to pull the type and mode out of a config
    return AES.new(key.digest(), AES.MODE_ECB)


def load_yaml(conf, conf_key, warn_on_fail=True):
    yaml_file = _yamls(conf, conf_key)

    # If the encrypted yaml doesn't exist, bail out
    if not os.path.exists(yaml_file.encrypted):
        return

    # If there's an unencypted yaml, issue a warning and bail out
    if os.path.exists(yaml_file.unencrypted):
        warn_msg = ('Encrypted eyaml and unencrypted yaml present for "{}" config. '
            'Ignoring encrypted yaml.').format(conf_key)
        warn(warn_msg)
        return

    # set up the crypt!
    cipher = crypt_cipher(conf)

    # Sanity achieved; attempt decryption
    loaded_yaml = lya.AttrDict()
    with open(yaml_file.encrypted) as eyaml:
        decrypted_yaml = cipher.decrypt(eyaml.read())
    loaded_yaml.update(yaml.load(decrypted_yaml, Loader=lya.OrderedDictYAMLLoader))

    return loaded_yaml
