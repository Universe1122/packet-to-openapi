package org.example.handler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import org.example.parser.PacketParser;
import org.json.JSONException;

import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

public class MyHttpHandler implements HttpHandler {
    private final Logging logging;
    private final PacketParser packet_parser;

    public MyHttpHandler(MontoyaApi api) throws JSONException {
        this.logging = api.logging();
        packet_parser = new PacketParser(this.logging);
    }


    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        return null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        Annotations annotations = responseReceived.annotations();
        //Highlight all responses where the request had a Content-Length header.
        if (responseHasContentLengthHeader(responseReceived)) {
            annotations = annotations.withHighlightColor(HighlightColor.BLUE);
        }

        if(checkContentType(responseReceived)){
            HttpRequest request = responseReceived.initiatingRequest();
            try {
                packet_parser.parse(request, responseReceived);
            } catch (JSONException e) {
                this.logging.logToError("packet parsing error");
            }
        }

        logging.logToOutput(packet_parser.server.toString());

        return continueWith(responseReceived, annotations);
    }

    private static boolean isPost(HttpRequestToBeSent httpRequestToBeSent) {
        return httpRequestToBeSent.method().equalsIgnoreCase("POST");
    }

    private static boolean responseHasContentLengthHeader(HttpResponseReceived httpResponseReceived) {
        return httpResponseReceived.initiatingRequest().headers().stream().anyMatch(header -> header.name().equalsIgnoreCase("Content-Length"));
    }

    private boolean checkContentType(HttpResponseReceived response) {
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

        logging.logToOutput("checkContentType() -> false: " + response_content_type);
        return false;
    }
}