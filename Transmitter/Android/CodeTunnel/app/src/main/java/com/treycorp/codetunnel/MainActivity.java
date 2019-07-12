package com.treycorp.codetunnel;

import android.app.ProgressDialog;
import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.openpgp.PGPKeyRingGenerator;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPSecretKeyRing;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.Security;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import static com.treycorp.codetunnel.PGP.RSAGen.generateKeyRingGenerator;


public class MainActivity extends AppCompatActivity {

    TextView nodeView, pairedView, xpdrView;
    Button testMessageButton, pairButton, resetButton, chuckButton, restartButton, registerButton;

    LocalPlugin localPlugin;
    CryptoPlugin cryptoPlugin;
    OkHttpClient client;

    public ProgressDialog progressDialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);

        nodeView = findViewById(R.id.nodeView);
        pairedView = findViewById(R.id.pairedView);
        xpdrView = findViewById(R.id.xpdrView);
        testMessageButton = findViewById(R.id.testMessageButton);
        pairButton = findViewById(R.id.pairButton);
        resetButton = findViewById(R.id.resetButton);
        chuckButton = findViewById(R.id.chuckButton);
        restartButton = findViewById(R.id.restartButton);
        registerButton = findViewById(R.id.registerButton);

        localPlugin = new LocalPlugin();
        localPlugin.init(MainActivity.this);
        client = localPlugin.getClient();
        cryptoPlugin = new CryptoPlugin();

        progressDialog = new ProgressDialog(this);

        if (localPlugin.getBoolean("ChuckEnabled")) {
            chuckButton.setText("Chuck: Enabled");
        } else {
            chuckButton.setText("Chuck: Disabled");
        }

        setOnClickListeners();

    }

    void registerServer() {
        String url = "https://juniper.treycorp.com/CodeTunnel/register.py";
        Request request = new Request.Builder().url(url).build();
        progressDialog.setMessage("Requesting UUID");
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                e.printStackTrace();
            }

            @Override
            public void onResponse(Call call, final Response response) throws IOException {
                if (!response.isSuccessful()) {
                    throw new IOException("Unexpected code " + response);
                } else {
                    Log.d("registerServer", response.body().string());



                }
            }


        });}

    void setOnClickListeners() {
        testMessageButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //webPlugin.pingServer();
                //pingServer();

            }
        });

        pairButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                localPlugin.toast("pairButton");
            }
        });

        resetButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                localPlugin.toast("resetButton");
            }
        });

        chuckButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                localPlugin.toast("Restart app for new setting to take effect");
                if (localPlugin.getBoolean("ChuckEnabled")) {
                    localPlugin.setBoolean("ChuckEnabled", false);
                    chuckButton.setText("Chuck: Pending off");
                } else {
                    localPlugin.setBoolean("ChuckEnabled", true);
                    chuckButton.setText("Chuck: Pending on");
                }
            }
        });

        restartButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent i = getBaseContext().getPackageManager().getLaunchIntentForPackage(getBaseContext().getPackageName());
                i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
                startActivity(i);
                finish();
            }
        });

        registerButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                progressDialog.setTitle("Registering");
                progressDialog.show();
                //progressDialog.setMessage("Generating Keys");
                //cryptoPlugin.test();
                Thread mThread = new Thread() {
                    @Override
                    public void run() {
                        generateKeypair();
                        progressDialog.dismiss();
                    }
                };
                mThread.start();
                //registerServer();
            }
        });
    }

    public void generateKeypair() {
        char pass[] = {'C', 'o', 'd', 'e', 'T', 'u', 'n', 'n', 'e', 'l'};
        progressDialog.setMessage("Generating Keypair");
        try {
            PGPKeyRingGenerator krgen = generateKeyRingGenerator("alice@example.com", pass);
            progressDialog.setMessage("Generating Public Key");
            PGPPublicKeyRing pkr = krgen.generatePublicKeyRing();
            progressDialog.setMessage("Exporting Public Key");
            ByteArrayOutputStream encOut = new ByteArrayOutputStream();
            ArmoredOutputStream armorOut = new ArmoredOutputStream(encOut);
            armorOut.write(pkr.getEncoded());
            armorOut.flush();
            armorOut.close();
            String publickey = new String(encOut.toByteArray());
            progressDialog.setMessage("Generating Private Key");
            PGPSecretKeyRing skr = krgen.generateSecretKeyRing();
            progressDialog.setMessage("Exporting Private Key");
            encOut = new ByteArrayOutputStream();
            armorOut = new ArmoredOutputStream(encOut);
            armorOut.write(skr.getEncoded());
            armorOut.flush();
            armorOut.close();
            String privatekey = new String(encOut.toByteArray());
            progressDialog.setMessage("");
            Log.d("PubKey", publickey);
            Log.d("PrivKey", privatekey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
