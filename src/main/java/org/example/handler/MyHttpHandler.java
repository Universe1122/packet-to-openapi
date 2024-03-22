package org.example.handler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import org.example.parser.PacketParser;
import org.json.JSONException;

import java.util.ArrayList;
import java.util.List;

public class MyHttpHandler implements ProxyResponseHandler {
    private final Logging logging;
    private final PacketParser packet_parser;

    public MyHttpHandler(MontoyaApi api) throws JSONException {
        this.logging = api.logging();
        packet_parser = new PacketParser(this.logging);
    }

    private boolean checkContentType(InterceptedResponse response) {
        List<String> allow_content_types = new ArrayList<String>() {
            {
                add("application/json");
            }
        };

        String response_content_type = null;

        if (response.hasHeader("Content-Type")){
            HttpHeader content_type_header = response.header("Content-Type");

            if(content_type_header != null){
                response_content_type = content_type_header.value();
            }
        }

        if(response_content_type == null){
            return false;
        }

        for (String allow_content_type: allow_content_types){
            if (response_content_type.contains(allow_content_type)) {
                return true;
            }
        }
        HttpRequest request = response.request();
        logging.logToError("checkContentType() -> false, url: " + request.url() + ", Content-Type: " + response_content_type);
        return false;
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        if(checkContentType(interceptedResponse)){
            HttpRequest request = interceptedResponse.initiatingRequest();
            try {
                packet_parser.parse(request, interceptedResponse);
            } catch (JSONException e) {
                this.logging.logToError("packet parsing error: " + request.url());
            }
        }

//        logging.logToOutput(packet_parser.server.toString());

        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return null;
    }
}