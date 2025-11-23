# Encryption Demonstration: Symmetric vs. Asymmetric Methods

This project demonstrates the core differences between **symmetric** and **asymmetric** encryption using Python.  
It fulfills the assignment requirement to:

- Encrypt and decrypt a short message using both methods  
- Display the keys used  
- Display the input message  
- Display the encrypted and decrypted outputs  
- Provide a brief explanation of how the code works  

---

##  1. Symmetric Encryption (Fernet / AES)

### How it works
The symmetric portion of the program uses the **Fernet** implementation from the `cryptography` library.  
Fernet is built on top of **AES-128 in CBC mode** with HMAC for integrity.

A **single shared key** is generated and used for both:
- Encrypting the message  
- Decrypting the ciphertext  

### Strengths
- Very fast  
- Good for encrypting larger amounts of data  
- Easy to implement  

### Weaknesses
- **Key distribution problem** — both parties must somehow securely share the same key  
- If the key is exposed, confidentiality is lost  

---

##  2. Asymmetric Encryption (RSA)

### How it works
The asymmetric portion uses **RSA (2048-bit)** with **OAEP padding** and **SHA-256**.

RSA uses two keys:
- **Public key** → used for encryption  
- **Private key** → used for decryption  

This eliminates the need to share a secret key.

### Strengths
- No shared secret required  
- Commonly used for secure key exchange  
- Powers many security systems (HTTPS, TLS, certificates)

### Weaknesses
- Much slower than symmetric methods  
- Not ideal for encrypting large messages directly  
- Key sizes are larger and more computationally expensive  

---

##  3. What the Script Prints

Running the script outputs:

- The **original message**
- The **generated symmetric key**
- Symmetric ciphertext (Base64)
- Symmetric decrypted output  
- RSA **public key (PEM format)**
- RSA **private key (PEM format)**
- RSA ciphertext (hex)
- RSA decrypted output

This provides clear evidence of both encryption systems functioning correctly.

---

##  4. How to Run

### Install required libraries:

```bash
pip install cryptography

