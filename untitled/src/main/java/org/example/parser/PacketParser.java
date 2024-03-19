package org.example.parser;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

public class PacketParser {
    public JSONObject openapi;
    public Logging logging;

    public PacketParser(Logging logging) throws JSONException {
        this.openapi = this.init();
        this.logging = logging;
        this.logging.logToOutput(this.openapi.toString());
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
        data.put("paths", new JSONObject());

        return data;
    }

    public void parse(HttpRequest request, HttpResponseReceived response) throws JSONException {
        RequestParser request_parser = new RequestParser(request, this.logging);
        ResponseParser response_parser = new ResponseParser(response);

        JSONObject path_info = request_parser.parse();
        JSONObject response_info = response_parser.parse();
        this.logging.logToOutput("response: " + response_info.toString());
        this.insert(path_info, response_info);
        // TODO
//        response_parser.parse();

    }

    public void insert(JSONObject new_path_info, JSONObject new_response_info) throws JSONException {
        JSONObject paths_info = this.openapi.getJSONObject("paths");
        Iterator paths_info_key = paths_info.keys();

        Iterator new_path_info_key = new_path_info.keys();
        String new_path_key = new_path_info_key.next().toString();

        boolean check_new_path = true;
        boolean check_new_method = true;
        boolean check_new_status_code = true;

        // path 가 이미 등록되었는지 확인
        while(paths_info_key.hasNext()){
            String path_key = paths_info_key.next().toString();

            // path 가 이미 등록되어 있는 경우,
            if(path_key.equals(new_path_key)) {
                JSONObject path_detail_info = paths_info.getJSONObject(path_key);
                JSONObject new_path_detail_info = new_path_info.getJSONObject(new_path_key);

                Iterator path_detail_methods_key = path_detail_info.keys();
                Iterator new_path_method_key = new_path_detail_info.keys();
                String new_method_key = new_path_method_key.next().toString();
                
                // method 가 이미 등록되었는지 확인
                while(path_detail_methods_key.hasNext()){
                    String path_method_key = path_detail_methods_key.next().toString();
                    
                    // method 가 이미 등록되어 있는 경우
                    if (path_method_key.equals(new_method_key)){
                        JSONObject method_info = path_detail_info.getJSONObject(path_method_key);
                        JSONArray parameters_info = method_info.getJSONArray("parameters");

                        JSONObject new_method_info = new_path_detail_info.getJSONObject(new_method_key);
                        JSONArray new_parameters_info = new_method_info.getJSONArray("parameters");;

                        // 새로 등록할 parameter 가 있는지 확인하기
                        for(int new_index=0; new_index < new_parameters_info.length(); new_index++){
                            boolean check_new_parameter = true;

                            JSONObject new_parameter_info = new_parameters_info.getJSONObject(new_index);
                            String new_parameter_name = new_parameter_info.getString("name");

                            for(int index=0; index < parameters_info.length(); index++){
                                JSONObject parameter_info = parameters_info.getJSONObject(index);
                                String parameter_name = parameter_info.getString("name");

                                // 기존에 등록된 parameter 일 경우, 등록하지 않음
                                if (new_parameter_name.equals(parameter_name)){
                                    check_new_parameter = false;
                                    break;
                                }
                            }
                            
                            // 없는 parameter 일 경우, 추가
                            if (check_new_parameter) {
                                parameters_info.put(new_parameter_info);
                            }
                        }
                        // TODO
                        // 특정 조건때만 response 값이 등록 되는 것 같음. 원인 파악 및 수정하기
                        // 새로 등록할 response 가 있는지 확인하기
                        JSONObject responses = method_info.getJSONObject("responses");

                        Iterator responses_key = responses.keys();
                        Iterator new_responses_key = new_response_info.keys();
                        String new_response_status_code_key = new_responses_key.next().toString();

                        while(responses_key.hasNext()) {
                            String response_status_code = responses_key.next().toString();

                            // 이미 등록된 상태코드 인 경우, break
                            if (response_status_code.equals(new_response_status_code_key)){
                                check_new_status_code = false;
                                break;
                            }
                        }
                        
                        // 새로운 상태코드 인 경우, 추가
                        if(check_new_status_code) {
                            responses.put(new_response_status_code_key, new_response_info.getJSONObject(new_response_status_code_key));
                        }

                        check_new_method = false;
                        break;
                    }
                }
                
                // 새로운 method 인 경우, 추가
                if(check_new_method){
                    JSONObject value = new_path_detail_info.getJSONObject(new_method_key);
                    path_detail_info.put(new_method_key, value);
                }

                check_new_path = false;
                break;
            }
        }

        // 새로운 path 인 경우, 추가
        if(check_new_path) {
            JSONObject value = new_path_info.getJSONObject(new_path_key);
            paths_info.put(new_path_key, value);
        }
    }

    public static class RequestParser {
        public HttpRequest request;
        public Logging logging;

        // Remove Authorization
        public ArrayList<String> standard_header = new ArrayList<String>(Arrays.asList("A-IM", "Accept", "Accept-Charset", "Accept-Datetime", "Accept-Encoding", "Accept-Language", "Access-Control-Request-Method", "Access-Control-Request-Headers", "Cache-Control", "Connection", "Content-Encoding", "Content-Length", "Content-MD5", "Content-Type", "Cookie", "Date", "Expect", "Forwarded", "From", "Host", "HTTP2-Settings", "If-Match", "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since", "Max-Forwards", "Origin", "Pragma", "Prefer", "Proxy-Authorization", "Range", "Referer", "TE", "Trailer", "Transfer-Encoding", "User-Agent", "Upgrade", "Via", "Warning"));
        public ArrayList<String> non_standard_header = new ArrayList<String>(Arrays.asList("Upgrade-Insecure-Requests", "X-Requested-With", "DNT", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Front-End-Https", "X-Http-Method-Override", "X-ATT-DeviceId", "X-Wap-Profile", "Proxy-Connection", "X-UIDH", "X-Csrf-Token", "X-Request-ID","X-Correlation-ID", "Correlation-ID", "Save-Data", "Sec-GPC"));

        public RequestParser(HttpRequest request, Logging logging) {
            this.logging = logging;
            this.request = request;
        }

        public JSONObject parse() throws JSONException {
            String _server = this.getServerInfo();
            String _path = this.getPath();
            String _method = this.getHttpMethod();
            JSONArray _parameters = this.getQuery();
            List<String> _custom_header = this.getCustomHeader();

            JSONObject ep_info = new JSONObject();
            if(_parameters.length() > 0){
                ep_info.put("parameters", _parameters);
            }
            else{
                ep_info.put("parameters", new JSONArray());
            }
            ep_info.put("summary", "this is summary");
            ep_info.put("responses", new JSONObject());

            JSONObject method = new JSONObject();
            method.put(_method.toLowerCase(), ep_info);

            JSONObject path = new JSONObject();
            path.put(_path, method);

            return path;
        }

        public String getServerInfo(){
            HttpService http_service = this.request.httpService();
            return http_service.toString();
        }

        public String getPath() {
            return this.request.pathWithoutQuery();
        }

        public String getHttpMethod() {
            return this.request.method();
        }

        public JSONArray getQuery() throws JSONException {
            if (this.request.query().isEmpty()){
                return new JSONArray();
            }

            JSONArray parameters = new JSONArray();
            String[] queries = this.request.query().split("&");


            for (String query: queries){
                JSONObject parameter_info = new JSONObject();

                String[] data = query.split("=", 2);

                parameter_info.put("name", data[0]);
                parameter_info.put("in", "query");
                parameter_info.put("description", "");
                parameter_info.put("example", data[1]);
                parameter_info.put("schema", new JSONObject());

                parameters.put(parameter_info);
            }

            return parameters;
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

        public JSONObject parse() throws JSONException {
            short status_code = this.getStatusCode();

            JSONObject info = new JSONObject();
            info.put("description", "");
            info.put("headers", new JSONObject());
            info.put("content", new JSONObject());

            JSONObject data = new JSONObject();
            data.put(String.valueOf(status_code), info);

            return data;
        }

        public short getStatusCode(){
            return this.response.statusCode();
        }

        public String getBody() {
            return this.response.bodyToString();
        }
    }
}
