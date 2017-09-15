package com.inspii;

import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.util.Map;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.mortbay.util.ajax.JSON;

public class XRsaTest extends TestCase {
    public XRsaTest(String testName) {
        super(testName);
    }

    public static Test suite() {
        return new TestSuite(XRsaTest.class);
    }

    public void testPublicEncryptPrivateDecrypt() {
        Map<String, String> keys = XRsa.createKeys(2048);
        XRsa rsa = new XRsa(keys.get("publicKey"), keys.get("privateKey"));
        String data = "hello world";

        String encrypted = rsa.publicEncrypt(data);
        String decrypted = rsa.privateDecrypt(encrypted);
        assertEquals(data, decrypted);
    }

    public void testPrivateEncryptPublicDecrypt() {
        Map<String, String> keys = XRsa.createKeys(2048);
        XRsa rsa = new XRsa(keys.get("publicKey"), keys.get("privateKey"));
        String data = "hello world";

        String encrypted = rsa.privateEncrypt(data);
        String decrypted = rsa.publicDecrypt(encrypted);
        assertEquals(data, decrypted);
    }

    public void testSign() {
        Map<String, String> keys = XRsa.createKeys(2048);
        XRsa rsa = new XRsa(keys.get("publicKey"), keys.get("privateKey"));
        String data = "hello world";

        String sign = rsa.sign(data);
        Boolean isValid = rsa.verify(data, sign);
        assertTrue(isValid);
    }

    public void testCrossPlatform() {
        File pubFile = new File("pub.base64cert");
        File priFile = new File("pri.base64cert");
        File testFile = new File("java.json");
        String pubKey = readFile(pubFile);
        String priKey = readFile(priFile);
        String dataStr = readFile(testFile);
        Map<String, String> data = (Map) JSON.parse(dataStr);

        XRsa rsa = new XRsa(pubKey, priKey);
        String decrypted = rsa.privateDecrypt(data.get("encrypted"));
        assertEquals(data.get("data"), decrypted);

        String sign = rsa.sign(data.get("data"));
        Boolean isValid = rsa.verify(data.get("data"), sign);
        assertTrue(isValid);
    }

    private static String readFile(File file) {
        StringBuilder result = new StringBuilder();
        try {
            BufferedReader br = new BufferedReader(new FileReader(file));
            String s;
            while ((s = br.readLine()) != null) {
                result.append(System.lineSeparator() + s);
            }
            br.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result.toString();
    }
}

