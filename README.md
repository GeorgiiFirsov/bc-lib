# bc-lib

> **Warning** 
> This library is implemented for research purposes only! It *intentionally* doesn't verify some parameters 
> for validity. In real world all parameters MUST be properly verified.

[![Tests](https://github.com/GeorgyFirsov/bc-lib/actions/workflows/run-tests.yaml/badge.svg)](https://github.com/GeorgyFirsov/bc-lib/actions/workflows/run-tests.yaml)
[![codecov](https://codecov.io/github/GeorgyFirsov/bc-lib/branch/main/graph/badge.svg?token=XGoAIJdblk)](https://codecov.io/github/GeorgyFirsov/bc-lib)

## Supported block ciphers

This library implements not so many cryptographic algorithms, because, as it was said above, it was
developed during my research about full disk encryption (FDE) and does't aim to seize all existing
block ciphers.

### Kuznyechik (GOST 34.12-2018)

For algorithm specification you shuld refer to [GOST 34.12-2018][1]. Here is usage example:

```c
//
// Initialize block cipher interface (this is the only way to use ciphers)
//

BLOCK_CIPHER cipher;
kuznyechik_initialize_interface(&cipher);

//
// Create encryption and decryption key schedules from a 256-bit binary key
//

KEY ekey;
KEY dkey;
cipher->initialize_encrypt_key(binary_key, &ekey);
cipher->initialize_decrypt_key(binary_key, &dkey);

//
// And now encrypt plaintext block
//

__m128i plaintext_block  = ...;
__m128i ciphertext_block = ...;
cipher->encrypt_block(plaintext_block, &ekey, &ciphertext_block);

//
// Decryption is straightforward too
//

__m128i decrypted_block = ...;
cipher->decrypt_block(ciphertext_block, &dkey, &decrypted_block);
```

[1]: https://tc26.ru/standarts/mezhgosudarstvennye-dokumenty-po-standartizatsii/gost-34-12-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-blochnye-shifry.html
