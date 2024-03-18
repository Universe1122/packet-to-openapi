package org.example;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.logging.Logging;
import org.example.handler.MyHttpHandler;
import org.json.JSONException;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        Logging logging = api.logging();
        logging.logToOutput("asdf");
        api.extension().setName("HTTP Handler Example");


        try {
            api.http().registerHttpHandler(new MyHttpHandler(api));
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
    }
}
