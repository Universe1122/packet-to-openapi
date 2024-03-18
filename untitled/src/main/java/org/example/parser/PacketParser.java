package org.example.parser;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PacketParser {
    public JSONObject openapi;

    public PacketParser() throws JSONException {
        this.openapi = this.init();
    }

    public JSONObject init() throws JSONException {
        JSONObject license = new JSONObject();
        license.put("name", "MIT");

        JSONObject info = new JSONObject();
        info.put("version", "1.0.0");
        info.put("title", "Translate Burpsuite Packet to openapi");
        info.put("license", license);

        JSONArray servers = new JSONArray();
        servers.put(new JSONObject());

        JSONObject data = new JSONObject();
        data.put("openapi", "3.0.0");
        data.put("info", info);
        data.put("servers", servers);
        data.put("paths", new JSONArray());

        return data;
    }

    public void parse(HttpRequest request, HttpResponseReceived response) throws JSONException {
        RequestParser request_parser = new RequestParser(request);
        ResponseParser response_parser = new ResponseParser(response);

        JSONObject path_info = request_parser.parse();
        // TODO
//        response_parser.parse();
        
        // TODO
        // 새로운 path 추가 될때, 기존에 존재하는 path가 사라지는 이슈 해결하기
        this.openapi.put("paths", path_info);
    }

    public static class RequestParser {
        public HttpRequest request;

        // Remove Authorization
        public ArrayList<String> standard_header = new ArrayList<String>(Arrays.asList("A-IM", "Accept", "Accept-Charset", "Accept-Datetime", "Accept-Encoding", "Accept-Language", "Access-Control-Request-Method", "Access-Control-Request-Headers", "Cache-Control", "Connection", "Content-Encoding", "Content-Length", "Content-MD5", "Content-Type", "Cookie", "Date", "Expect", "Forwarded", "From", "Host", "HTTP2-Settings", "If-Match", "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since", "Max-Forwards", "Origin", "Pragma", "Prefer", "Proxy-Authorization", "Range", "Referer", "TE", "Trailer", "Transfer-Encoding", "User-Agent", "Upgrade", "Via", "Warning"));
        public ArrayList<String> non_standard_header = new ArrayList<String>(Arrays.asList("Upgrade-Insecure-Requests", "X-Requested-With", "DNT", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Front-End-Https", "X-Http-Method-Override", "X-ATT-DeviceId", "X-Wap-Profile", "Proxy-Connection", "X-UIDH", "X-Csrf-Token", "X-Request-ID","X-Correlation-ID", "Correlation-ID", "Save-Data", "Sec-GPC"));

        public RequestParser(HttpRequest request) {
            this.request = request;
        }

        public JSONObject parse() throws JSONException {
            String _server = this.getServerInfo();
            String _path = this.getPath();
            String _method = this.getHttpMethod();
            String _parameters = this.getQuery();
            List<String> _custom_header = this.getCustomHeader();

            JSONArray parameters = new JSONArray();
            // TODO
            // openapi spec 대로 변경하기
            parameters.put(_parameters);

            JSONObject ep_info = new JSONObject();
            ep_info.put("parameters", parameters);
            ep_info.put("summary", "this is summary");

            JSONObject method = new JSONObject();
            method.put(_method.toLowerCase(), ep_info);

            JSONObject path = new JSONObject();
            path.put(_path, method);

            return path;
        }

        public String getServerInfo(){
            HttpService http_service = this.request.httpService();
            return http_service.toString();
//            URI uri = new URI(this.request.url());
//
//            String domain = uri.getHost();
//            String protocol = uri.getScheme();
//            int port = uri.getPort();
//            String portString = (port != -1) ? (":" + port) : "";
//
//            return protocol + "://" + domain + portString;
        }

        public String getPath() {
            return this.request.pathWithoutQuery();
        }

        public String getHttpMethod() {
            return this.request.method();
        }

        public String getQuery() {
            // TODO
            // 어떻게 리턴하는지 보고, & 기준으로 문자열을 쪼개서 리턴할건지 생각하기
            return this.request.query();
        }

        public List<String> getCustomHeader(){
            List<HttpHeader> headers = this.request.headers();
            List<String> return_headers = new ArrayList<String>();

            for (HttpHeader header: headers){

                if (Arrays.asList(standard_header).contains(header.name()) == false) {
                    return_headers.add(header.name());
                }
            }

            return return_headers;
        }

        public String getBody(){
            // TODO
            // body를 파싱해서 리턴하기
            return this.request.bodyToString();
        }
    }

    public static class ResponseParser {
        public HttpResponseReceived response;
        public ResponseParser(HttpResponseReceived response) {
            this.response = response;
        }

        public void parse(){

        }

        public short getStatusCode(){
            return this.response.statusCode();
        }

        public String getBody() {
            return this.response.bodyToString();
        }
    }
}
