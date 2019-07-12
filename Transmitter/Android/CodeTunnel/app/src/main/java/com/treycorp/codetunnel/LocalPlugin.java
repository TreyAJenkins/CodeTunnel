package com.treycorp.codetunnel;

import android.content.Context;
import android.content.SharedPreferences;
import android.widget.Toast;

import com.chuckerteam.chucker.api.ChuckerInterceptor;

import java.security.Security;

import okhttp3.OkHttpClient;

import static android.content.Context.MODE_PRIVATE;

public class LocalPlugin {
    Context context;
    SharedPreferences prefs;
    OkHttpClient client;

    public void init(Context context) {
        this.context = context;
        this.prefs = context.getSharedPreferences("CodeTunnel", MODE_PRIVATE);
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);

    }

    public OkHttpClient buildClient() {
        OkHttpClient.Builder clientBuilder = new OkHttpClient().newBuilder();
        if (getBoolean("ChuckEnabled")) {
            clientBuilder = clientBuilder.addInterceptor(new ChuckerInterceptor(context));
        }
        client = clientBuilder.build();
        return client;
    }

    public OkHttpClient getClient() {
        if (client == null) {
            client = buildClient();
        }
        return client;
    }

    public Context getContext() {
        return context;
    }

    public Boolean getBoolean(String key) {
        return prefs.getBoolean(key, false);
    }

    public void setBoolean(String key, Boolean value) {
        SharedPreferences.Editor editor = prefs.edit();
        editor.putBoolean(key, value);
        editor.commit();
    }

    public String getString(String key) {
        return prefs.getString(key, "");
    }

    public void setString(String key, String value) {
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(key, value);
        editor.commit();
    }

    public void toast(String bread) {
        Toast.makeText(context, bread, Toast.LENGTH_SHORT).show();
    }
}
