# xstrip-auth

> Cryptographically strong pseudorandom key generator based on the XStrip Algorithm

[![PyPI Version][pypi-image]][pypi-url]
![License][license-image]
![Python Version][version-image]

## Installing

Via [PyPI][pypi-url]:

``` bash
pip install xstrip_auth
```

## Usage

Generate a 256-bit key for use

``` python
from xstrip_auth import XStripKeyConstruct

key = "#P@$$W0R9"
construct = XStripKeyConstruct(key)

# Creating a 16Bit key for use from the key under a md5 hash implementation
construct.generateKey(hf='md5')
# Prints
#   [md5](16): 'ec1a93e0f8d41d75ffb77914e7a31cbf'

# Create a 256bit key for use from the key under the sha256 hash implementation
construct.generateKey(hf='sha256')
# Prints
#   [sha256](32): 'd6b05d17e2e15152c478825ca6e7adafd0045b0c7fd92850ead98bad0cced9a4'
```

## API

### <a id="xstripkey"></a> Class: `XStripKey`(hash, salt[, iterations][, hf])

* `hash`: &lt;bytes&gt; The key, final content to be encapsulated by the instance
* `salt`: &lt;bytes&gt; The salt used to intensify the operation
* `iterations`: &lt;number&gt; Number of iterations undergone to generate the `hash`. Default: **`100000`**
* `hf`: &lt;string&gt; Hash function used for the operation. Default: **`'sha256'`**

Encapsulate a generated key within an interfacing instance for managing the inherent content

The `XStripKey` class is defined and exposed publicly by the module:
``` python
from xstrip_auth import XStripKey

key = XStripKey(bytes.fromhex('d4d64d71c71ed5365ddde126ca8e6a17301e5f9601a15119e53c2f91def21f11'),
                bytes.fromhex('422f487975c57bb648f3'))

print(key.verify("#P@$$W0R9"))

# Prints
#   True
```

#### XStripKey::`hex`<sub>(getter)</sub>

Shows the encapsulated key in byte hex format

#### XStripKey::`hf`<sub>(getter)</sub>

Returns the hash function of the key

#### XStripKey::`salt`<sub>(getter)</sub>

Returns the salt of the key in bytes

#### XStripKey::`iterations`<sub>(getter)</sub>

Returns the number of iterations used in encoding the key

#### <a id="xstripkey_verify"></a> XStripKey::`verify`(key[, encoder])

* `key`: &lt;string&gt;
* `encoder`: &lt;function&gt;

Returns: &lt;boolean&gt;

Verify whether or not the specified `key` matches the inherent key of the [`self`](#xstripkey) instance
`encoder` is defined by any transformers that was used used in generating the construct else, this falls back to a `noop` function that returns its parameters
Returns a boolean for the condition result

#### <a id="xstripkey_matchexec"></a> XStripKey::`matchExec`(key, fn[, *args][, encoder])

* `key`: &lt;string&gt;
* `fn`: &lt;function&gt;
* `*args`: &lt;any&gt;
* `encoder`: &lt;function&gt;

Returns: &lt;any&gt;

Execute the `fn` function if the `key` matches the inherent key of the [`self`](#xstripkey) instance by checking [`self.verify`](#xstripkey_verify)(`key`, `encoder`)
fn is called by arguments defined in `args` (if-any)
`encoder` is defined by any transformers that was used used in generating the construct else, this falls back to a `noop` function that returns its parameters
Returns the return content of the function `fn`

``` python
def fn(value):
  print("Password Matches, arg: %d" % value)

key.matchExec("#P@$$W0R9", fn, 10)

# Prints
#   Password Matches, arg: 10
```

#### <a id="xstripkey_mismatchexec"></a> XStripKey::`mismatchExec`(key, fn[, *args][, encoder])

* `key`: &lt;string&gt;
* `fn`: &lt;function&gt;
* `*args`: &lt;any&gt;
* `encoder`: &lt;function&gt;

Returns: &lt;any&gt;

Execute the `fn` function if the `key` does not match the inherent key of the [`self`](#xstripkey) instance by checking [`self.verify`](#xstripkey_verify)(`key`, `encoder`)
fn is called by arguments defined in `args` (if-any)
`encoder` is defined by any transformers that was used used in generating the construct else, this falls back to a `noop` function that returns its parameters
Returns the return content of the function `fn`

``` python
def fn(value):
  print("Password Matches, arg: %d" % value)

key.mismatchExec("something", fn, 19)

# Prints
#   Password Matches, arg: 19
```

#### <a id="xstripkey_codes"></a> XStripKey::`codes`()

Returns the octal representation of each character in a list

#### <a id="xstripkey_export"></a> XStripKey::`export`()

Exports the entire key construct in base64 encoding parsable by [`XStripKey.parse()`](#xstripkey_parse)

``` python
print(key.export())

# Prints
#   b'MTAwMDAwOjQyMmY0ODc5NzVjNTdiYjY0OGYzL2Q0Z...OGU2YTE3MzAxZTVmOTYwMWExNTExOWU1M2MyZjkxZGVmMjFmMTE='
```

#### <a id="xstripkey_parse"></a> XStripKey.`parse`(content)

* `fn`: &lt;string | bytes&gt; The exported construct to be parsed
Returns: &lt;[XStripKey](#xstripkey)&gt;

Parse the base64 exported data from [`XStripKey::export`](#xstripkey_export)

``` python

print(XStripKey.parse(key.export()))
print(key == XStripKey.parse(key.export()))

# Prints
#   [sha256](32): 'd4d64d71c71ed5365ddde126ca8e6a17301e5f9601a15119e53c2f91def21f11'
#   True
```

### <a id="xstripkeyconstruct"></a> Class: `XStripKeyConstruct`(key[, iterations])

* `key`: &lt;string | bytes&gt; The key to be constructed on
* `iterations`: &lt;number&gt; The number of times the kdf should apply the hash function to the key in the transformative process

Class to generate series of hashed keys for a single key
Making the product pseudorandomly secure for every use of the same key

The `XStripKey` class is defined and exposed publicly by the module:
``` python
from xstrip_auth import XStripKeyConstruct
```

#### <a id="xstripkeyconstruct_generatekey"></a> XStripKey::`generateKey`([hf][, salt][, encoder])

* `hf`: &lt;string&gt; The hash function to process the key on. Default: **`'sha256'`**
* `salt`: &lt;string | bytes&gt; The hash to be used on the key when randomising the data. Default: [**<py:os/random>**][pyosrandom]
* `encoder`: &lt;function&gt; The middleware transformative function. Default: **noop**

Returns: &lt;[XStripKey](#xstripkey)&gt;

Generates a special key for the encapsulated key under special conditions making the product completely random and untied to the operation
Hence, generating cryptographically secure keys everytime this method is called
`encoder` is defined by any transformers that was used used in generating the construct else, this falls back to a `noop` function that returns its parameters

``` python
construct = XStripKeyConstruct("t0y$t0ry")

construct.generateKey()
 # [sha256](32): '5e53edcff3bc4dc5e06b243dd206e4dbba1be625361bd2db3c9599edec217f01'
construct.generateKey()
 # [sha256](32): '907d183f27a75c23830906063494ff073942e3f74d21605f7b19b16a7d94df06'
construct.generateKey('md5')
 # [md5](16): 'd38518dccec4a4ef1767c01e48095a2c'
construct.generateKey('sha1')
 # [sha1](20): '42f405740cd7a35a283b44c1ee0bbf0c9812015b'
```

## Development

### Building

Feel free to clone, use in adherance to the [license](#license) and perhaps send pull requests

``` bash
git clone https://github.com/miraclx/xstrip-auth.git
cd xstrip-auth
# hack on code
pip3 install . --user
```

## License

[Apache 2.0][license] © **Miraculous Owonubi** ([@miraclx][author-url]) &lt;omiraculous@gmail.com&gt;

[license]:  LICENSE 'Apache 2.0 License'
[author-url]: https://github.com/miraclx

[pypi-url]: https://pypi.org/project/xstrip-auth
[pypi-image]: https://img.shields.io/pypi/v/xstrip-auth.svg?color=red&label=xstrip-auth&style=popout-square
[license-image]: https://img.shields.io/pypi/l/xstrip-auth.svg?color=green&label=License&style=popout-square
[version-image]: https://img.shields.io/pypi/pyversions/xstrip-auth.svg?color=blue&label=PythonVersion&style=popout-square

[pyosrandom]: https://pypi.org/project/xstrip-auth
