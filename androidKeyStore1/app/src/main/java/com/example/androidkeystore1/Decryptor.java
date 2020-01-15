package com.example.androidkeystore1;

/**
 * Created by erfli on 2/24/17.
 */

import android.util.Base64;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Decryptor {

    private static final String TRANSFORMATION_AES_CBC = "AES/CBC/PKCS5Padding";
    private static final String TRANSFORMATION_RSA_ECB = "RSA/ECB/PKCS1Padding";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    private KeyStore keyStore;

    Decryptor() throws CertificateException, NoSuchAlgorithmException, KeyStoreException,
            IOException {
        initKeyStore();
    }

    private void initKeyStore() throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
    }
    byte[] aesDecrypt(byte[] aesKey,byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] decData = Base64.decode(data,2);
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION_AES_CBC);
        IvParameterSpec iv = new IvParameterSpec("1234567812345678".getBytes());
        SecretKeySpec secretKey = new SecretKeySpec(aesKey, "AES");
//        SecretKey secretKey = getSecretKey(alias);
//        IvParameterSpec iv = new IvParameterSpec("1234567812345678".getBytes());
        cipher.init(Cipher.DECRYPT_MODE,secretKey,iv);

        return (cipher.doFinal(decData));
    }
    byte[] decryptAesKey(String encKey,String alias)
            throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
            NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        byte[] encData = Base64.decode(encKey,2);
        PrivateKey privateKey= (PrivateKey) keyStore.getKey(alias,null);
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION_RSA_ECB);
//        final GCMParameterSpec spec = new GCMParameterSpec(128, "1234567812345678".getBytes());
//        SecretKey secretKey = getSecretKey(alias);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(encData);
    }

    private SecretKey getSecretKey(final String alias) throws NoSuchAlgorithmException,
            UnrecoverableEntryException, KeyStoreException {
        return ((KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null)).getSecretKey();
    }
}
