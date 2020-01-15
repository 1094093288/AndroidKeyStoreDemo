package com.example.androidkeystore;

import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {
    String TAG = "MainActivity";
    private TextView textShow;
    private Button encrypt;
    private Button decrypt;
    private EditText dataText;


    private Encryptor encryptor;
    private Decryptor decryptor;


    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        dataText = findViewById(R.id.data);
        encrypt = findViewById(R.id.encrypt);
        decrypt = findViewById(R.id.decrypt);
        textShow = findViewById(R.id.text);

        encryptor = new Encryptor();

        try {
            decryptor = new Decryptor();
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException |
                IOException e) {
            e.printStackTrace();
        }

        encrypt.setOnClickListener(new View.OnClickListener() {
            @RequiresApi(api = Build.VERSION_CODES.M)
            @Override
            public void onClick(View v) {
                encryptText();
            }
        });

        decrypt.setOnClickListener(new View.OnClickListener() {
            @RequiresApi(api = Build.VERSION_CODES.KITKAT)
            @Override
            public void onClick(View v) {
                decryptText();
            }
        });
    }

    private void decryptText() {
        SharedPreferences sharedPreferences = getSharedPreferences("key_data", MODE_PRIVATE);

        String data = sharedPreferences.getString("AESkey", "");

        try {
            byte[] aesKey = decryptor.decryptAesKey(data,TAG);
            textShow.setText(new String(decryptor.aesDecrypt(aesKey, encryptor.getEncryption())));
        } catch (UnrecoverableEntryException | NoSuchAlgorithmException |
                KeyStoreException | NoSuchPaddingException | NoSuchProviderException |
                IOException | InvalidKeyException e) {
            Log.e(TAG, "decryptData() called with: " + e.getMessage(), e);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private void encryptText() {
//        String AESKey = "1234567812345678";
        byte[] AESKey = encryptor.getAesKey();
        try {
            final byte[] encryptedText = encryptor
                    .encryptText(dataText.getText().toString(),AESKey);
            String encText = Base64.encodeToString(encryptedText, Base64.DEFAULT);
            System.out.println(encText);
            textShow.setText(encText);
            SharedPreferences sp = getSharedPreferences("key_data", MODE_PRIVATE);
            SharedPreferences.Editor editor = sp.edit();
            try {
                editor.putString("AESkey", encryptor.rsaEncAes(AESKey,TAG));
            } catch (Exception e) {
                e.printStackTrace();
            }
            editor.commit();
        } catch (UnrecoverableEntryException | NoSuchAlgorithmException | NoSuchProviderException |
                KeyStoreException | IOException | NoSuchPaddingException | InvalidKeyException e) {
            Log.e(TAG, "onClick() called with: " + e.getMessage(), e);
        } catch (InvalidAlgorithmParameterException | SignatureException |
                IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }
}
