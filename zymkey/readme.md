# zymkey

Zymkey 4i has three unique ECDSA private/public key pairs,
It has one on it
It can encrypt and decrypt files
So general use for protecting keys etc is encrypt something, decrypt when needed, reencrypt. Or use the key on the device

Unlike a tpm which can store encrypted blobs of the keys, load the encrypted key blob into the tpm, unencrypt the keyblob in the tpm, and use the key to encrypt/sign/decrypt. essentiall just moving storage off the tpm but encryption and plaintext still happen and stay within the tpm

Multifactor Device ID & Authentication
Data Encryption & Signing
Key Storage & Generation
Physical Tamper Detection
Hardware Root of Trust

TRNG (NIST SP800-22) - random num gen
ECC NIST P-256 (secp256r1) - main use
ECDSA (FIPS186-3) - just ECC
AES-256 (FIPS 197) - encryption

my model is ZYMKEY 4i

there might already be 3 keys generated. check if this is true or if I make a new one
