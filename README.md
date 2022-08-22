# KEK-cli
![Python](https://img.shields.io/badge/Python->=3.7-orange)
![gnukek](https://img.shields.io/badge/gnukek-==1.0.0-yellow)
![License](https://img.shields.io/pypi/l/gnukek-cli)
![Status](https://img.shields.io/pypi/status/gnukek-cli)

Kinetic Encryption Key CLI

----------

Cross-platform command-line interface for [KEK](https://pypi.org/project/gnukek/).

----------

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install [KEK-cli](https://pypi.org/project/gnukek-cli/).

```bash
pip install gnukek-cli
```

## Usage

Show help:

```bash
kek --help
```

Generate new key:

```bash
kek generate
```

Encrypt file:

```bash
kek encrypt {FILE}
```

Decrypt file:

```bash
kek decrypt {FILE}
```

List existing keys:

```bash
kek list
```

Set default private key:

```bash
kek default {KEY_ID}
```

Export key to file:

```bash
kek export {KEY_ID}
```

Import key from file:

```bash
kek import {FILE}
```

For more information see:

```bash
kek {sub-command} --help
```

## License

[GPLv3 license](https://github.com/SweetBubaleXXX/KEK-cli/blob/main/LICENSE)
