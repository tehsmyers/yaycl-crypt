import os
import warnings

import pytest

import yaycl
import yaycl_crypt


TEST_KEY = 'test key'
# hashlib.sha256(str(data).strip()).hexdigest()
TEST_KEY_HASH = 'fa2bdca424f01f01ffb48df93acc35d439c7fd331a1a7fba6ac2fd83aa9ab31a'


def delete_path(path):
    if path.check():
        path.remove()


@pytest.fixture(scope='session')
def conf_dir(request):
    dir = request.session.fspath.join('tests', 'conf')
    dir.ensure(dir=True)
    request.addfinalizer(lambda: delete_path(dir))
    return dir


@pytest.fixture
def conf(conf_dir):
    # a basic conf object
    return yaycl.Config(conf_dir.strpath)


@pytest.fixture
def test_conf(conf, tmpdir):
    """A written-out config file for encrypt/decrypt testing"""
    # switch the conf dir over to the tmpdir, set the encryption key
    conf._yaycl.config_dir = tmpdir.strpath
    conf._yaycl.crypt_key = TEST_KEY
    conf.runtime['test'] = {'test_key': 'test value'}
    conf.save('test')
    # del the test key to ensure a load when conf.test is accessed
    del(conf['test'])
    return yaycl_crypt._yamls(conf, 'test')


def test_load_hash_from_nowhere(conf):
    with pytest.raises(Exception):
        assert yaycl_crypt.crypt_key_hash(conf).hexdigest() == TEST_KEY_HASH


def test_load_hash_from_conf(conf):
    conf._yaycl.crypt_key = TEST_KEY
    assert yaycl_crypt.crypt_key_hash(conf).hexdigest() == TEST_KEY_HASH


def test_load_hash_file_from_conf(conf, tmpdir):
    key_file = tmpdir.join('key_file')
    key_file.write(TEST_KEY)
    conf._yaycl.crypt_key_file = key_file.strpath
    assert yaycl_crypt.crypt_key_hash(conf).hexdigest() == TEST_KEY_HASH


def test_load_hash_from_env(request, conf):
    os.environ['YAYCL_CRYPT_KEY'] = TEST_KEY
    request.addfinalizer(lambda: os.environ.pop('YAYCL_CRYPT_KEY'))
    assert yaycl_crypt.crypt_key_hash(conf).hexdigest() == TEST_KEY_HASH


def test_load_hash_file_from_env(request, conf, tmpdir):
    key_file = tmpdir.join('key_file')
    key_file.write(TEST_KEY)
    os.environ['YAYCL_CRYPT_KEY_FILE'] = key_file.strpath
    request.addfinalizer(lambda: os.environ.pop('YAYCL_CRYPT_KEY_FILE'))
    assert yaycl_crypt.crypt_key_hash(conf).hexdigest() == TEST_KEY_HASH


def test_encrypt_decrypt_yaml(request, conf, test_conf, tmpdir):
    assert os.path.exists(test_conf.unencrypted)

    # encryption deletes the unenecrypted yaml
    yaycl_crypt.encrypt_yaml(conf, 'test')
    assert os.path.exists(test_conf.encrypted)
    assert not os.path.exists(test_conf.unencrypted)
    del(conf['test'])

    # decryption deletes the encrypted yaml
    yaycl_crypt.decrypt_yaml(conf, 'test')
    assert os.path.exists(test_conf.unencrypted)
    assert not os.path.exists(test_conf.encrypted)
    del(conf['test'])

    # decryption refuses to delete an unencrypted yaml
    with pytest.raises(Exception):
        yaycl_crypt.decrypt_yaml(conf, 'test')


def test_load_warnings(conf, test_conf, recwarn, tmpdir):
    # encrypt without deleting to create the eyaml next to the yaml
    yaycl_crypt.encrypt_yaml(conf, 'test', delete=False)
    del(conf['test'])
    assert os.path.exists(test_conf.encrypted)
    assert os.path.exists(test_conf.unencrypted)

    # test env is sane, clear warnings and make sure one is caught on yaml load
    warnings.resetwarnings()
    assert conf.test.test_key == 'test value'
    assert recwarn.pop(UserWarning)
