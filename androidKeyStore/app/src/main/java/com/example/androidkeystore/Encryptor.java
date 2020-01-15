package com.example.androidkeystore;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;


import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static android.content.Context.MODE_PRIVATE;


/**
 * Created by erfli on 2/24/17.
 */

class Encryptor {

    private static final String TRANSFORMATION_AES_CBC = "AES/CBC/PKCS5Padding";
    private static final String TRANSFORMATION_RSA_ECB = "RSA/ECB/PKCS1Padding";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    private byte[] encryption;
    private byte[] aesKey;

//    private byte[] iv = "1234567812345678".getBytes();

    Encryptor() {
    }

    private byte[] genAESKey() {
        // Generate AES-Key
        byte[] aesKey = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(aesKey);
        return aesKey;
    }

    String rsaEncAes(byte[] aesKey, String alias) throws Exception {
        KeyPair keyPair = generateRSAKey(alias);
        PublicKey rsaPub = keyPair.getPublic();
        Cipher instance = Cipher.getInstance(TRANSFORMATION_RSA_ECB);
        instance.init(Cipher.ENCRYPT_MODE,rsaPub);

        byte[] doFinal = instance.doFinal(aesKey);
        String result = new String(Base64.encode(doFinal,1));
        return result;
    }
//非对称加密
    private KeyPair generateRSAKey(final String alias) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);


        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec
                .Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .build();

        keyPairGenerator.initialize(keyGenParameterSpec);
        return keyPairGenerator.generateKeyPair();

    }
    byte[] encryptText(final String textToEncrypt,byte[] aesKey)
            throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
            NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException,
            InvalidAlgorithmParameterException, SignatureException, BadPaddingException,
            IllegalBlockSizeException {
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION_AES_CBC);
        IvParameterSpec iv = new IvParameterSpec("1234567812345678".getBytes());
        SecretKeySpec secretKey = new SecretKeySpec(aesKey, "AES");
//        SecretKey secretKey = getSecretKey(alias);
//        IvParameterSpec iv = new IvParameterSpec("1234567812345678".getBytes());
        cipher.init(Cipher.ENCRYPT_MODE,secretKey,iv);


        return (encryption = cipher.doFinal(textToEncrypt.getBytes("UTF-8")));
    }

////对称加密
//    private SecretKey getSecretKey(final String alias) throws NoSuchAlgorithmException,
//            NoSuchProviderException, InvalidAlgorithmParameterException {
//
//        final KeyGenerator keyGenerator = KeyGenerator
//                .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
//
//        keyGenerator.init(new KeyGenParameterSpec.Builder(alias,
//                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
//                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
//                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
//                .build());
//
//        return keyGenerator.generateKey();
//    }

    byte[] getEncryption() {
        return encryption;
    }

    byte[] getAesKey() {
        return aesKey = genAESKey();
    }
}
