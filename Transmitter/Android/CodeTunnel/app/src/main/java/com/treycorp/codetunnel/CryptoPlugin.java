package com.treycorp.codetunnel;

import android.content.Context;
import android.util.Log;


import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.openpgp.PGPKeyRingGenerator;
import org.spongycastle.openpgp.PGPPublicKeyRing;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.security.Security;

import static com.treycorp.codetunnel.PGP.RSAGen.generateKeyRingGenerator;


public class CryptoPlugin {

    LocalPlugin localPlugin;
    Context context;


    public void init(LocalPlugin localPlugin) {
        this.localPlugin = localPlugin;
        this.context = localPlugin.getContext();

        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public void test() {
        char pass[] = {'h', 'e', 'l', 'l', 'o'};

        try {
            PGPKeyRingGenerator krgen = generateKeyRingGenerator("alice@example.com", pass);


            PGPPublicKeyRing pkr = krgen.generatePublicKeyRing();


            ByteArrayOutputStream encOut = new ByteArrayOutputStream();
            ArmoredOutputStream armorOut = new ArmoredOutputStream(encOut);
            armorOut.write(pkr.getEncoded());
            armorOut.flush();
            armorOut.close();
            String encoded = new String(encOut.toByteArray());

            //Log.d("PubKey", encoded);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
