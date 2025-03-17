# KEK-cli

![Python](https://img.shields.io/badge/Python->=3.10-orange)
![License](https://img.shields.io/pypi/l/gnukek)

## Installation

To install KEK-cli:

```sh
pip install gnukek-cli
```

To install with **S3** storage support:

```sh
pip install gnukek-cli[s3]
```

## Usage

```sh
kek --help
```

### Encrypt a file

```sh
kek encrypt <input_file> <output_file>
```

### Decrypt a file

```sh
kek decrypt <input_file> <output_file>
```

### Generate a new key pair

```sh
kek generate
```

### Import keys

```sh
kek import <key_files>...
```

### Export a key

```sh
kek export <key_id> <file>
```

### List saved keys

```sh
kek list
```

### Delete a key

```sh
kek delete <key_ids>...
```

### Sign a file

```sh
kek sign <input_file> <output_file>
```

### Verify a signature

```sh
kek verify <signature_file> <original_file>
```

### Open encrypted file in editor

```sh
kek edit <file>
```

### Upload a file to S3

```sh
kek s3-upload <input_file> <file_location>
```

### Download a file from S3

```sh
kek s3-download <file_location> <output_file>
```

> `file_location` - the S3 object location in the format `bucket_name/object_name`

### Shell completions

Run to install bash completions:

```sh
eval "$(_KEK_COMPLETE=bash_source kek)"
```

This line can be added to `~/.bashrc`.

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.
