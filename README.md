# yaycl Encrypted Yaml Support

A (yaycl)[https://github.com/seandst/yaycl] plugin to seamlessly load encypted yamls,
as well as helper methods for encrypting and decrypting yaycl yamls.

# Usage

```python
# Set the crypt key one of these ways:
conf = yaycl.Config('/path/to/yamls', crypt_key='my secret')
conf = yaycl.Config('/path/to/yamls', crypt_key_file='/path/to/a/file/containing/my/secret')

# Or set them after instantiating conf if you like (but it's a little less pretty):
conf._yaycl['crypt_key'] = 'my secret'
conf._yaycl['crypt_key_file'] = '/path/to/a/file/containing/my/secret'

# Or set the correspnding environment vars before loading python:
# - YAYCL_CRYPT_KEY corresponds to 'crypt_key' kwarg
# - YAYCL_CRYPT_KEY_FILE corresponds to 'crypt_key_file' kwarg

# Assuming you've loaded "test.yaml" from your yaml conf dir,
# this will encrypt it and remove the unencrypted version:

yaycl_crypt.encrypt_yaml(conf, 'test')

# Encrypted yamls have the extension '.eyaml', and (assuming the crypt key is set)
# will be loaded just like an unencrypted yaml.

# To decrypt:
yaycl_crypt.decrypt_yaml(conf, 'test')

# As before (but going the other way), the .eyaml file will be deleted,
# leaving just the unencrypted yaml file in the conf dir
```

# Notes

- If both an encrypted an unencrypted yaml exist, `yaycl_crypt` will issue a warning
  and punt to the next `yaycl` loader, which is most likely the default loader. This
  means the unencrypted yaml gets loaded, under the assumption that an unencrypted yaml
  next to an encrypted yaml probably means the unencrypted yaml is being actively edited.
- If `yaycl_crypt.decrypt_yaml` is called, and an unencrypted yaml already exists, 
  `yaycl_crypt` will refuse to overwrite the existing unencrypted conf, again under the
  assumption that the unencrypted conf is being actively worked on. If it isn't, the
  simplest way to remove it is likely to encrypt it first to delete the unencrypted file,
  then decrypt it.
- `yaycl_crypt.encrypt_yaml` has no similar qualms about overwriting encrypted yamls, since
  the most likely reason for using this function is to write config changes in a recently
  unencrypted config file.
- Both `encrypt_yaml` and `decrypt_yaml` take a `delete` kwarg, which defaults to `True`.
  If set to `False`, `encrypt_yaml` will *not* delete the unencrypted config of the same
  name, and `decrypt_yaml` will similarly *not* delete its encrypted counterpart.
- `yaml_crypt` isn't guaranteed to be completely "secure"; its main goal is to obfuscate
  configuration files with private data in a way that is not trivial to circumvent.
  Anyone with access to a python interpreter that can read your eyaml files has access
  to your secret key.

```
