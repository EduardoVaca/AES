# AES
AES implementation for Information Security course


Script that encrypts and decrypts any file using AES with CBC (Cipher Block Chaining).

Example:

`python3 aes_encrypt.py any_file.txt`

Output:

`Your file has been encrypted with AES!`

`KEY`
`0xa1 0x83 0x72 0x20 0x95 0x2a 0xda 0xdf 0xdf 0x26 0x7f 0x2b 0x34 0xb5 0xb9 0x11`

`Cipher contained in file: cipher.txt`

As the message says, the cipher bytes are located in a new file called _ciphet.txt_

Also two other files are generated:
- _cipher_key.txt_ containg the key used (which is random).
- _cipher_ext.txt_ the extension of the file encrypted.

To decrypt just run:

`python3 aes_decrypt.txt`

Output:

`Your file has been decrypted!`

`Please check file: result.txt`

And result.(any extension) will be identical as your original file.

