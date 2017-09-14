# x-rsa
OpenSSL RSA Encryption, Decryption, and Key Generation. Java, Php GoLang Supported, Large Data Support.

## Installation

### Php
```cmd
    composer require williamylian/x-rsa
```

### GoLang
```cmd
    go get github.com/williamylian/x-rsa
```

### Java
    Just Copy XRsa.java to your project

## Usage

### Php
```php
    $keys = XRsa::createKeys(2048);
    $rsa = new XRsa($keys['publicKey'], $keys['privateKey']);
    
    $data = "Hello, World";
    $encrypted = $rsa->publicEncrypt($data);
    $decrypted = $rsa->privateDecrypt($encrypted);
    $sign = $rsa->privateSign($data);
    $is_valid = $rsa->verifySign($data, $sign);
```
### GoLang
```golang
    var publicKey *bytes.Buffer = bytes.NewBufferString("")
    var privateKey *bytes.Buffer = bytes.NewBufferString("")
    var xrsa *XRsa

    err := CreateKeys(publicKey, privateKey, 2048)
    if err != nil {
        t.Error(err.Error())
    }
    xrsa, err = NewXRsa(publicKey.Bytes(), privateKey.Bytes())
    if err != nil {
        t.Error(err.Error())
    }

    data := "Hello, World"
    encrypted, err := xrsa.PublicEncrypt(data)
    if err != nil {
        t.Fatal(err.Error())
    }
    decrypted, err := xrsa.PrivateDecrypt(encrypted)
    if err != nil {
        t.Fatal(err.Error())
    }

    $sign = $rsa->privateSign($data);
    $is_valid = $rsa->verifySign($data, $sign);
```
    
### Java
```java
    Map<String, String> keys = XRsa.createKeys(2048);
    XRsa rsa = new XRsa(keys.get("publicKey"), keys.get("privateKey"));
    
    String data = "hello world";
    String encrypted = rsa.publicEncrypt(data);
    String decrypted = rsa.privateDecrypt(encrypted);
    String sign = rsa.privateSign(data);
    Boolean isValid = rsa.verifySign(data, sign);
```