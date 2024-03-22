package org.example.parser;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedResponse;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.*;

public class PacketParser {
    public JSONArray server;
    public Logging logging;

    public PacketParser(Logging logging) throws JSONException {
        this.server = new JSONArray();
        this.logging = logging;
    }

    public JSONObject initOpenApiSpec(String new_host) throws JSONException {
        JSONObject license = new JSONObject();
        license.put("name", "MIT");

        JSONObject info = new JSONObject();
        info.put("version", "1.0.0");
        info.put("title", "Translate Burpsuite Packet to openapi");
        info.put("license", license);

        JSONObject url = new JSONObject();
        url.put("url", new_host);
        JSONArray servers = new JSONArray();
        servers.put(url);

        JSONObject data = new JSONObject();
        data.put("openapi", "3.0.0");
        data.put("info", info);
        data.put("servers", servers);
        data.put("paths", new JSONObject());

        return data;
    }

    public void parse(HttpRequest request, InterceptedResponse response) throws JSONException {
        RequestParser request_parser = new RequestParser(request, this.logging);
        JSONObject path_info = request_parser.parse(response);
        String new_host = request_parser.getServerInfo();

        // 새로운 서버인지 확인
        boolean check_new_host = true;
        for(int index=0; index<this.server.length(); index++) {
            JSONObject server_info = this.server.getJSONObject(index);
            String host = server_info.getString("host");

            // 존재하는 서버 정보인 경우 break
            if (host.equals(new_host)) {
                check_new_host = false;
                break;
            }
        }

        // 새로운 서버 정보인 경우, 추가
        if (check_new_host) {
            JSONObject new_server_info = new JSONObject();
            new_server_info.put("openapi", this.initOpenApiSpec(new_host));
            new_server_info.put("host", new_host);
            this.server.put(new_server_info);
        }
        this.insert(path_info, new_host);
    }

    public void insert(JSONObject new_path_info, String new_host){
        try {
            JSONObject openapi = null;
            for (int index = 0; index < this.server.length(); index++) {
                JSONObject server_info = this.server.getJSONObject(index);
                String host = server_info.getString("host");

                if (host.equals(new_host)) {
                    openapi = server_info.getJSONObject("openapi");
                    break;
                }
            }
            assert openapi != null;

            JSONObject paths_info = openapi.getJSONObject("paths");
            Iterator paths_info_key = paths_info.keys();
            Iterator new_path_info_key = new_path_info.keys();
            String new_path_key = new_path_info_key.next().toString();

            boolean check_new_path = true;
            boolean check_new_method = true;
            boolean check_new_status_code = true;

            // path 가 이미 등록되었는지 확인
            while (paths_info_key.hasNext()) {
                String path_key = paths_info_key.next().toString();

                // path 가 이미 등록되어 있는 경우,
                if (path_key.equals(new_path_key)) {
                    JSONObject path_detail_info = paths_info.getJSONObject(path_key);
                    JSONObject new_path_detail_info = new_path_info.getJSONObject(new_path_key);

                    Iterator path_detail_methods_key = path_detail_info.keys();
                    Iterator new_path_method_key = new_path_detail_info.keys();
                    String new_method_key = new_path_method_key.next().toString();

                    // method 가 이미 등록되었는지 확인
                    while (path_detail_methods_key.hasNext()) {
                        String path_method_key = path_detail_methods_key.next().toString();

                        // method 가 이미 등록되어 있는 경우
                        if (path_method_key.equals(new_method_key)) {
                            JSONObject method_info = path_detail_info.getJSONObject(path_method_key);
                            JSONArray parameters_info = method_info.getJSONArray("parameters");

                            JSONObject new_method_info = new_path_detail_info.getJSONObject(new_method_key);
                            JSONArray new_parameters_info = new_method_info.getJSONArray("parameters");
                            ;

                            // 새로 등록할 parameter 가 있는지 확인하기
                            for (int new_index = 0; new_index < new_parameters_info.length(); new_index++) {
                                boolean check_new_parameter = true;

                                JSONObject new_parameter_info = new_parameters_info.getJSONObject(new_index);
                                String new_parameter_name = new_parameter_info.getString("name");

                                for (int index = 0; index < parameters_info.length(); index++) {
                                    JSONObject parameter_info = parameters_info.getJSONObject(index);
                                    String parameter_name = parameter_info.getString("name");

                                    // 기존에 등록된 parameter 일 경우, 등록하지 않음
                                    if (new_parameter_name.equals(parameter_name)) {
                                        check_new_parameter = false;
                                        break;
                                    }
                                }

                                // 없는 parameter 일 경우, 추가
                                if (check_new_parameter) {
                                    parameters_info.put(new_parameter_info);
                                }
                            }

                            // 새로 등록할 response 가 있는지 확인하기
                            JSONObject responses = method_info.getJSONObject("responses");
                            JSONObject new_responses = new_method_info.getJSONObject("responses");
                            Iterator responses_key = responses.keys();
                            Iterator new_responses_key = new_responses.keys();
                            String new_response_status_code_key = new_responses_key.next().toString();

                            while (responses_key.hasNext()) {
                                String response_status_code = responses_key.next().toString();

                                // 이미 등록된 상태코드 인 경우, break
                                if (response_status_code.equals(new_response_status_code_key)) {
                                    check_new_status_code = false;
                                    break;
                                }
                            }

                            // 새로운 상태코드 인 경우, 추가
                            if (check_new_status_code) {
                                responses.put(new_response_status_code_key, new_responses.getJSONObject(new_response_status_code_key));
                            }

                            // 새로 등록할 request body 가 있는지 확인
                            if(method_info.has("requestBody")){
                                JSONObject request_body = method_info.getJSONObject("requestBody");
                                JSONObject new_request_body = new_method_info.getJSONObject("requestBody");

                                if(new_request_body.length() != 0){
                                    JSONObject request_content = request_body.getJSONObject("content");
                                    JSONObject new_request_content = new_request_body.getJSONObject("content");

                                    Iterator request_content_type_iter = request_content.keys();
                                    Iterator new_request_content_type_iter = new_request_content.keys();
                                    String new_request_content_type_key = new_request_content_type_iter.next().toString();

                                    boolean check_content_type_key = true;

                                    while(request_content_type_iter.hasNext()) {
                                        String request_content_type_key = request_content_type_iter.next().toString();

                                        // 기존에 이미 있는 content_type 인 경우,
                                        if(request_content_type_key.equals(new_request_content_type_key)) {
                                            JSONObject request_content_type = request_content.getJSONObject(request_content_type_key);
                                            JSONObject new_request_content_type = new_request_content.getJSONObject(request_content_type_key);

                                            JSONObject request_schema = request_content_type.getJSONObject("schema");
                                            JSONObject new_request_schema = new_request_content_type.getJSONObject("schema");

                                            JSONObject request_properties = request_schema.getJSONObject("properties");
                                            JSONObject new_request_properties = new_request_schema.getJSONObject("properties");
                                            JSONObject request_example = request_content_type.getJSONObject("examples");
                                            JSONObject new_request_example = new_request_content_type.getJSONObject("examples");


                                            // 새로운 request body parameter 가 있는지 확인
                                            Iterator new_request_properties_iter = new_request_properties.keys();
                                            while(new_request_properties_iter.hasNext()){
                                                boolean check_new_parameter = true;

                                                String new_parameter_key = new_request_properties_iter.next().toString();
                                                Iterator request_properties_iter = request_properties.keys();

                                                while(request_properties_iter.hasNext()){
                                                    String parameter_key = request_properties_iter.next().toString();

                                                    if(parameter_key.equals(new_parameter_key)){
                                                        check_new_parameter = false;
                                                        break;
                                                    }
                                                }

                                                // 새로운 request body parameter 가 있는 경우, 추가
                                                if(check_new_parameter) {
                                                    request_properties.put(new_parameter_key, new_request_properties.getJSONObject(new_parameter_key));
                                                    request_example.put(new_parameter_key, new_request_example.get(new_parameter_key));
                                                }
                                            }

                                            check_content_type_key = false;
                                            break;
                                        }
                                    }

                                    if(check_content_type_key) {
                                        request_content.put(new_request_content_type_key, new_request_content.getJSONObject(new_request_content_type_key));
                                    }
                                }
                            }

                            check_new_method = false;
                            break;
                        }
                    }

                    // 새로운 method 인 경우, 추가
                    if (check_new_method) {
                        JSONObject value = new_path_detail_info.getJSONObject(new_method_key);
                        path_detail_info.put(new_method_key, value);
                    }

                    check_new_path = false;
                    break;
                }
            }

            // 새로운 path 인 경우, 추가
            if (check_new_path) {
                JSONObject value = new_path_info.getJSONObject(new_path_key);
                paths_info.put(new_path_key, value);
            }
        }
        catch (Exception e) {
            this.logging.logToError(e);
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

        public JSONObject parse(InterceptedResponse response) throws JSONException {
            String _path = this.getPath();
            String _method = this.getHttpMethod();
            JSONArray _parameters = this.getQuery();
            List<String> _custom_header = this.getCustomHeader();
            ResponseParser response_parser = new ResponseParser(response);
            JSONObject _body = this.getBody();

            JSONObject ep_info = new JSONObject();
            if(_parameters.length() == 0){
                ep_info.put("parameters", new JSONArray());
            }
            else{
                ep_info.put("parameters", _parameters);
            }

            if(_body.length() != 0){
                ep_info.put("requestBody", _body);
            }

            ep_info.put("summary", "this is summary");
            ep_info.put("responses", response_parser.parse());

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

        public JSONObject getBody() throws JSONException {
            String body = this.request.bodyToString();

            if (body.isEmpty()){
                return new JSONObject();
            }

            JSONObject requestBody = new JSONObject();
            JSONObject content = new JSONObject();
            JSONObject applicationJson = new JSONObject();
            JSONObject schema = new JSONObject();
            JSONObject properties = new JSONObject();
            JSONObject example = new JSONObject();

            String content_type = this.request.contentType().name();
            this.logging.logToOutput(this.getPath());
            this.logging.logToOutput("content-type: "+ content_type);
            String[] keyValuePairs = body.split("&");
            for (String pair : keyValuePairs) {
                String[] keyValue = pair.split("=", 2);
                properties.put(keyValue[0], new JSONObject().put("type", "string")); // TODO, type 작성하기

                JSONObject value = new JSONObject();
                value.put("summary", "");
                if(keyValue.length == 2){
                    value.put("value", keyValue[1]);
                }
                else{
                    value.put("value", "");
                }
                example.put(keyValue[0], value);
            }

            schema.put("type", "object"); // TODO, object 그대로 둬도 되나?
            schema.put("properties", properties);

            applicationJson.put("schema", schema);
            applicationJson.put("examples", example);
            content.put(this.changeContentType(this.request.contentType().toString()), applicationJson);

            requestBody.put("content", content);

            return requestBody;
        }

        public String changeContentType(String content_type) {
            // https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/message/ContentType.html
            Map<String, String> change_content_type = new HashMap<String, String>();
            change_content_type.put("JSON", "application/json");
            change_content_type.put("MULTIPART", "multipart/form-data");
            change_content_type.put("URL_ENCODED", "application/x-www-form-urlencoded");
            change_content_type.put("XML", "application/xml");

            for(String key: change_content_type.keySet()){
                if(key.equals(content_type)) {
                    return change_content_type.get(key);
                }
            }

            this.logging.logToError("changeContentType()");
            this.logging.logToError("    -> not found content-type: " + content_type);
            return "application/json";
        }
    }

    public static class ResponseParser {
        public InterceptedResponse response;
        public ResponseParser(InterceptedResponse response) {
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
