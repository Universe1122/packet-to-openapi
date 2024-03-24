package org.example;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import org.example.handler.MyHttpHandler;
import org.json.JSONException;

import java.io.IOException;
import java.nio.file.*;

public class Main implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {

        api.extension().setName("HTTP Handler Example");

        try {
            api.proxy().registerResponseHandler(new MyHttpHandler(api));
        } catch (Exception e) {
            api.logging().logToError(String.valueOf(e));
            throw new RuntimeException(e);
        }
    }
}