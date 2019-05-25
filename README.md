# XRSA

OpenSSL RSA Encryption, Decryption, and Key Generation. 

- JAVA, PHP, GoLang, Python, Javascript Support
- Large Data Support

**Features:**

- Algorithm: RSA Encrypt/Decrypt by chunk
- RSA Padding: `PKCS#1`
- RSA Sign Method: `SHA256`
- Chunk Encoding: `URL Safe Base64`


**Encryption Procedure:**

1. Split string to chunks
2. Encrypt chunk by chunk with `RSA`
3. Merge encrypted chunks
4. Encrypt merged result with `URL Safe Base64` encoding

**Decryption Procedure:**

1. Decrypt merged result with `URL Safe Base64` encoding
2. Split to chunks
3. Decrypt chunk by chunk with `RSA`
4. Merge decrypted chunks

## Installation

### Php

*Make sure `openssl` extension is enabled*.
Just copy `php/XRsa.php` to your project. 


### GoLang

*Make sure your golang version is greater than `1.10.3`*.
Just Copy `golang/rsa.go` and `golang/xrsa.go` to your project.


### Java

*Make sure your JAVA version is greater than `JAVA 8`*.
Just Copy `XRsa.java` to your project.


## Usage

### Php

```php
    $keys = XRsa::createKeys(2048);
    $rsa = new XRsa($keys['public_key'], $keys['private_key']);
    
    $data = "Hello, RSA";
    $encrypted = $rsa->publicEncrypt($data);
    $decrypted = $rsa->privateDecrypt($encrypted);
    $sign = $rsa->sign($data);
    $is_valid = $rsa->verify($data, $sign);
```

### GoLang

```go
    publicKey, privateKey, err := CreateKeys(publicKey, privateKey, 2048)
    if err != nil {
        return err
    }
    xrsa, err := NewXRsa(publicKey, privateKey)
    if err != nil {
        return err
    }

    data := "Hello, RSA"
    encrypted, _ := xrsa.PublicEncrypt(data)
    decrypted, _ := xrsa.PrivateDecrypt(encrypted) 
    sign, err := xrsa.Sign(data)
    err = xrsa.Verify(data, sign)
```
    
### Java

```java
    Map<String, String> keys = XRsa.createKeys(2048);
    XRsa rsa = new XRsa(keys.get("publicKey"), keys.get("privateKey"));
    
    String data = "Hello, RSA";
    String encrypted = rsa.publicEncrypt(data);
    String decrypted = rsa.privateDecrypt(encrypted);
    String sign = rsa.sign(data);
    Boolean isValid = rsa.verify(data, sign);
```
