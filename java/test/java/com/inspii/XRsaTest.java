package com.inspii;

import java.util.Map;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class XRsaTest extends TestCase
{
    public XRsaTest( String testName )
    {
        super( testName );
    }

    public static Test suite()
    {
        return new TestSuite( XRsaTest.class );
    }

    public void testEncryptDecrypt()
    {
        Map<String, String> keys = XRsa.createKeys(2048);
        XRsa rsa = new XRsa(keys.get("publicKey"), keys.get("privateKey"));
        String data = "hello world";

        String encrypted = rsa.publicEncrypt(data);
        String decrypted = rsa.privateDecrypt(encrypted);

        assertEquals(data, decrypted);
    }

    public void testSign()
    {
        Map<String, String> keys = XRsa.createKeys(2048);
        XRsa rsa = new XRsa(keys.get("publicKey"), keys.get("privateKey"));
        String data = "hello world";

        String sign = rsa.privateSign(data);
        Boolean isValid = rsa.verifySign(data, sign);

        assertTrue(isValid);
    }
}
