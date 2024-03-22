package org.example;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import org.example.handler.MyHttpHandler;
import org.json.JSONException;

public class Main implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("HTTP Handler Example");

        try {
            api.proxy().registerResponseHandler(new MyHttpHandler(api));
        } catch (JSONException e) {
            api.logging().logToError(String.valueOf(e));
            throw new RuntimeException(e);
        }
    }
}
