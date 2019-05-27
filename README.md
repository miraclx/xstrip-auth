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

# Creating a 512Bit key for use from the key
construct.generateKey(hf='sha512').hex
# Prints
#   c201752639895937dc30902d9571ca37

# Create a 256bit key for use from the key
construct.generateKey(hf='sha256').hex
# Prints
#   d15782a240f8a2efa6f0a5d9904aabd5bfac6fbdf46fcf15c7efd8a73389728e
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
