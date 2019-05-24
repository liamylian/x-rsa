# XRSA

OpenSSL RSA Encryption, Decryption, and Key Generation. 
Java, Php GoLang, Python Support, Large Data Support.

- Algorithm: RSA Encrypt/Decrypt by chunk
- RSA Padding: `PKCS#1`
- RSA Sign Method: `SHA256`
- Chunk Encoding: `URL Safe Base64`

## Installation

### Php

*Make sure `openssl` extension is enabled*.
Just copy `php/XRsa.php` and `php/helpers.php` to your project. 


### GoLang

*Make sure your golang version is greater than `1.10.3`*.
Just Copy `golang/rsa.go` and `golang/xrsa.go` to your project, or use command:

```cmd
go get github.com/liamylian/x-rsa
```


### Java

Just Copy `XRsa.java` to your project


## Usage

### Php

```php
    $keys = XRsa::createKeys(2048);
    $rsa = new XRsa($keys['public_key'], $keys['private_key']);
    
    $data = "Hello, World";
    $encrypted = $rsa->publicEncrypt($data);
    $decrypted = $rsa->privateDecrypt($encrypted);
    $sign = $rsa->sign($data);
    $is_valid = $rsa->verify($data, $sign);
```

### GoLang

```go
    publicKey := bytes.NewBufferString("")
    privateKey := bytes.NewBufferString("")

    err := CreateKeys(publicKey, privateKey, 2048)
    if err != nil {
        return
    }
    xrsa, err := NewXRsa(publicKey.Bytes(), privateKey.Bytes())
    if err != nil {
        return
    }

    data := "Hello, World"
    encrypted, _ := xrsa.PublicEncrypt(data)
    decrypted, _ := xrsa.PrivateDecrypt(encrypted) 
    sign, err := xrsa.Sign(data)
    err = xrsa.Verify(data, sign)
```
    
### Java

```java
    Map<String, String> keys = XRsa.createKeys(2048);
    XRsa rsa = new XRsa(keys.get("publicKey"), keys.get("privateKey"));
    
    String data = "hello world";
    String encrypted = rsa.publicEncrypt(data);
    String decrypted = rsa.privateDecrypt(encrypted);
    String sign = rsa.sign(data);
    Boolean isValid = rsa.verify(data, sign);
```
