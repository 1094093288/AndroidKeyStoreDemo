package com.example.androidkeystore1;

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


    private Decryptor decryptor;


    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        dataText = findViewById(R.id.data);
        decrypt = findViewById(R.id.decrypt);
        textShow = findViewById(R.id.text);

        try {
            SharedPreferences sp = getSharedPreferences("test", MODE_PRIVATE);
            SharedPreferences.Editor editor = sp.edit();
            editor.putString("AESkey", "");
            editor.commit();
            decryptor = new Decryptor();
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException |
                IOException e) {
            e.printStackTrace();
        }
        decrypt.setOnClickListener(new View.OnClickListener() {
            @RequiresApi(api = Build.VERSION_CODES.KITKAT)
            @Override
            public void onClick(View v) {
                decryptText();
            }
        });
    }
//SWGfK2b0T0KjJPaGKu/Ieg==
    private void decryptText() {
        try {
            SharedPreferences sharedPreferences = getSharedPreferences("key_data", MODE_PRIVATE);

            String data = sharedPreferences.getString("AESkey", "");
            byte[] aesKey = decryptor.decryptAesKey(data,TAG);
            textShow.setText(new String(decryptor
                    .aesDecrypt( aesKey,dataText.getText().toString().getBytes())));
        } catch (UnrecoverableEntryException | NoSuchAlgorithmException |
                KeyStoreException | NoSuchPaddingException | NoSuchProviderException |
                IOException | InvalidKeyException e) {
            Log.e(TAG, "decryptData() called with: " + e.getMessage(), e);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }
}
