package liamylian.xrsa;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64;


public class XRsa {
    private static final Base64.Encoder urlSafeBase64Encoder = Base64.getUrlEncoder();
    private static final Base64.Decoder urlSafeBase64Decoder = Base64.getUrlDecoder();
    private static final Charset CHARSET = StandardCharsets.UTF_8;
    private static final String RSA_ALGORITHM = "RSA";
    private static final String RSA_ALGORITHM_SIGN = "SHA256WithRSA";

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    public XRsa(String publicKey, String privateKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(urlSafeBase64Decoder.decode(publicKey.getBytes(CHARSET)));
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(urlSafeBase64Decoder.decode(privateKey.getBytes(CHARSET)));

            this.publicKey = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
            this.privateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
        } catch (Exception e) {
            throw new RuntimeException("unsupported key", e);
        }
    }

    public static Map<String, String> createKeys(int keySize) {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm: " + RSA_ALGORITHM);
        }

        kpg.initialize(keySize);
        KeyPair keyPair = kpg.generateKeyPair();

        Key publicKey = keyPair.getPublic();
        String publicKeyStr = urlSafeBase64Encoder.encodeToString(publicKey.getEncoded());
        Key privateKey = keyPair.getPrivate();
        String privateKeyStr = urlSafeBase64Encoder.encodeToString(privateKey.getEncoded());

        Map<String, String> keyPairMap = new HashMap<>();
        keyPairMap.put("publicKey", publicKeyStr);
        keyPairMap.put("privateKey", privateKeyStr);
        return keyPairMap;
    }

    public String publicEncrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return urlSafeBase64Encoder.encodeToString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(CHARSET), publicKey.getModulus().bitLength()));
        } catch (Exception e) {
            throw new RuntimeException("加密字符串[" + data + "]时遇到异常", e);
        }
    }

    public String privateDecrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, urlSafeBase64Decoder.decode(data), publicKey.getModulus().bitLength()), CHARSET);
        } catch (Exception e) {
            throw new RuntimeException("解密字符串[" + data + "]时遇到异常", e);
        }
    }

    public String privateEncrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return urlSafeBase64Encoder.encodeToString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(CHARSET), publicKey.getModulus().bitLength()));
        } catch (Exception e) {
            throw new RuntimeException("加密字符串[" + data + "]时遇到异常", e);
        }
    }

    public String publicDecrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, urlSafeBase64Decoder.decode(data), publicKey.getModulus().bitLength()), CHARSET);
        } catch (Exception e) {
            throw new RuntimeException("解密字符串[" + data + "]时遇到异常", e);
        }
    }

    public String sign(String data) {
        try {
            //sign
            Signature signature = Signature.getInstance(RSA_ALGORITHM_SIGN);
            signature.initSign(privateKey);
            signature.update(data.getBytes(CHARSET));
            return urlSafeBase64Encoder.encodeToString(signature.sign());
        } catch (Exception e) {
            throw new RuntimeException("签名字符串[" + data + "]时遇到异常", e);
        }
    }

    public boolean verify(String data, String sign) {
        try {
            Signature signature = Signature.getInstance(RSA_ALGORITHM_SIGN);
            signature.initVerify(publicKey);
            signature.update(data.getBytes(CHARSET));
            return signature.verify(urlSafeBase64Decoder.decode(sign));
        } catch (Exception e) {
            throw new RuntimeException("验签字符串[" + data + "]时遇到异常", e);
        }
    }

    private static byte[] rsaSplitCodec(Cipher cipher, int opmode, byte[] datas, int keySize) throws IOException {
        int maxBlock = 0;
        if (opmode == Cipher.DECRYPT_MODE) {
            maxBlock = keySize / 8;
        } else {
            // The message must be no longer than the
            // length of the public modulus minus 11 bytes (taken by padding).
            maxBlock = keySize / 8 - 11;
        }

        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            int offSet = 0;
            byte[] buff;
            int i = 0;
            try {
                while (datas.length > offSet) {
                    if (datas.length - offSet > maxBlock) {
                        buff = cipher.doFinal(datas, offSet, maxBlock);
                    } else {
                        buff = cipher.doFinal(datas, offSet, datas.length - offSet);
                    }
                    out.write(buff, 0, buff.length);
                    i++;
                    offSet = i * maxBlock;
                }
            } catch (Exception e) {
                throw new RuntimeException("加解密阀值为[" + maxBlock + "]的数据时发生异常", e);
            }
            return out.toByteArray();
        }
    }
}
