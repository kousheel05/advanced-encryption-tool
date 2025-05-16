# ADVANCED ENCRYPTION TOOL

*COMAPNY*: CODTECH IT SOLUTIONS

*NAME*: MADIPADIGA KOUSHEEL

*INTERN ID*: CT04DL611

*DOMAIN*: CYBER SECURITY & ETHICAL HACKING

*DURATION*: 4WEEKS

*MENTOR*: NEELA SANTOSH 

# ADVANCED ENCRYPTION TOOL DESCRIPTION
An Advanced Encryption Tool is a software application designed to secure data by converting readable information (plaintext) into an unreadable format (ciphertext) and vice versa.
The tool typically supports multiple cryptographic algorithms, enabling users to encrypt sensitive information for confidentiality and decrypt it when needed. 
This kind of tool is essential for protecting data in transit or at rest, especially in modern communication systems, cloud storage, and secure file sharing.
The tool described here focuses primarily on AES-256 (Advanced Encryption Standard with 256-bit keys), a symmetric encryption algorithm widely recognized for its security and efficiency.
It also supports hashing algorithms like SHA for data integrity verification, although hashing is one-way and cannot be reversed like encryption.

# CORE LOGIC
The main cryptographic logic in this tool revolves around AES-256 encryption and decryption in CBC (Cipher Block Chaining) mode, 
along with proper handling of keys, initialization vectors (IVs), and padding.
AES-256 Algorithm: It encrypts data in fixed-size blocks (128 bits), using a 256-bit key for the encryption process. 
This algorithm applies multiple rounds of substitutions and permutations, making it highly secure.
CBC Mode: This mode chains each plaintext block with the previous ciphertext block before encrypting, adding randomness and making patterns less detectable.
Key and IV Management: Both are randomly generated during encryption and shared along with the ciphertext to allow proper decryption. 
Keys and IVs are encoded in base64 to ensure safe transmission in textual form.
Padding: Since AES operates on fixed block sizes, the plaintext is padded (using PKCS7 padding) to align to the block size before encryption and unpadded after decryption.
The encryption function takes plaintext input and outputs three base64-encoded strings: ciphertext, key, and IV. The decryption function takes these three base64 strings, decodes them,
and attempts to reconstruct the original plaintext. Error handling ensures that malformed or incorrect inputs result in clear error messages instead of crashes.

# ALGORITHMS USED 
1.AES-256 (Symmetric Encryption):
Uses a 256-bit key and 128-bit block size.
Provides confidentiality by encrypting data in blocks using substitution and permutation rounds.
CBC mode adds randomness by chaining blocks with XOR operations before encryption.

2.Base64 Encoding:
Converts binary data (key, IV, ciphertext) into ASCII strings, making them safe for textual transfer.

3.Padding (PKCS7):
Ensures that plaintext length matches the AES block size by adding extra bytes before encryption.

4.SHA-256 (Hashing):
A cryptographic hash function that produces a fixed 256-bit digest of any input data.
Used for integrity verification but cannot be reversed to plaintext.

AES-128 using Fernet (easy symmetric encryption with authentication)
AES-256 using CBC mode (manual key, IV management)
RSA (2048-bit) for asymmetric encryption/decryption
SHA-256 and SHA-512 hashing
Base64 encoding and decoding

# APPLICABILITY
This Advanced Encryption Tool is applicable in various scenarios, including:
Secure Communication: Encrypting messages before sending them over insecure channels (internet, emails, messaging apps).
Data Storage: Protecting sensitive files or database entries from unauthorized access by encrypting them.
Authentication: Hashing passwords or verifying data integrity using hashing algorithms.
Learning and Research: A practical implementation to understand cryptography concepts and algorithms.
Development: Embedding encryption/decryption features into web applications, APIs, and backend services.
The tool can be extended by adding other algorithms such as RSA (asymmetric encryption) or hashing functions like SHA-256 for comprehensive cryptographic operations.

# CONCLUSIUON
This Advanced Encryption Tool effectively demonstrates modern symmetric encryption principles with AES-256, wrapped in a user-friendly interface. 
While it offers robust data confidentiality and is practical for many use cases, users must handle keys and IVs carefully and consider adding 
authentication and asymmetric algorithms for a complete cryptographic solution. The modular design allows easy future enhancements like supporting RSA encryption,
hashing, digital signatures, or authenticated encryption modes.

# OUTPUTS
![Image](https://github.com/user-attachments/assets/d4f419c1-119d-4b11-aaea-7876369bf45b)

![Image](https://github.com/user-attachments/assets/05d7641b-843a-472a-9523-5cbfc8f38c32)


