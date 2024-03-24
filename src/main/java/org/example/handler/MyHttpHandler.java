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
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.ParseException;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

public class MyHttpHandler implements ProxyResponseHandler {
    private final Logging logging;
    private final PacketParser packet_parser;
    public String dir = "C:\\Users\\whdal\\Downloads\\result\\";
    public String filename = "output.json";


    public MyHttpHandler(MontoyaApi api){
        this.logging = api.logging();
        this.packet_parser = new PacketParser(this.logging);
        try{
            this.logging.logToOutput("Init: get data");
            this.packet_parser.load(this.dir + this.filename);
            this.logging.logToOutput("Init: Done");
        }
        catch (Exception e){
            this.logging.logToOutput(String.valueOf(e));
        }

        Thread thread = new Thread(new FileChangeWatcher(api.logging(), this.packet_parser, this.dir, this.filename));
        thread.start();
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
        this.logging.logToError("checkContentType() -> false, url: " + request.url() + ", Content-Type: " + response_content_type);
        return false;
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        if(checkContentType(interceptedResponse)){
            HttpRequest request = interceptedResponse.initiatingRequest();
            try {
                this.packet_parser.parse(request, interceptedResponse);
//                this.logging.logToOutput(packet_parser.server.toString());
            } catch (Exception e) {
                this.logging.logToError("packet parsing error: " + request.url());
            }
        }
//        logging.logToOutput(packet_parser.server.toString());
        try {
            this.save(this.packet_parser.server);
        } catch (InterruptedException e) {
            this.logging.logToOutput(String.valueOf(e));
        }

        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    public void save(JSONArray data) throws InterruptedException {
        this.logging.logToOutput("Saving packet info...");
        this.packet_parser.isCodeSave = 1;

        try {
            this.packet_parser.waitLock();
            FileWriter file = new FileWriter(this.dir + this.filename);
            JSONValue.writeJSONString(data, file);
            file.flush();
            file.close();
            this.logging.logToOutput("Done");
        } catch (IOException e) {
            this.logging.logToError("파일에 내용을 쓰는 중 오류가 발생했습니다: " + e.getMessage());
        }
        finally {
            this.packet_parser.lock.set(0);
        }
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return null;
    }
}

class FileChangeWatcher implements Runnable {
    public Logging logging;
    public PacketParser packet_parser;
    public String dir;
    public String filename;

    public FileChangeWatcher(Logging logging, PacketParser packet_parser, String dir, String filename) {
        this.logging = logging;
        this.packet_parser = packet_parser;
        this.dir = dir;
        this.filename = filename;

    }
    @Override
    public void run() {
        try {
            // 변경 감지 루프 시작
            while (true) {
                Thread.sleep(1000);
                // WatchService 생성
                WatchService watchService = FileSystems.getDefault().newWatchService();

                // 감지할 디렉토리 경로 설정
                Path directory = Path.of(this.dir);

                // 디렉토리를 WatchService에 등록
                directory.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);
                WatchKey key;
                try {
                    // 변경 이벤트 대기
                    key = watchService.take();
                } catch (InterruptedException ex) {
                    return;
                }

                // 이벤트 처리
                if (this.packet_parser.isCodeSave == 1) {
                    this.packet_parser.isCodeSave = 0;
                    continue;
                }
                for (WatchEvent<?> event : key.pollEvents()) {
                    WatchEvent.Kind<?> kind = event.kind();
                    // 변경된 파일명 출력
                    if (kind == StandardWatchEventKinds.ENTRY_MODIFY) {
//                        this.test();
                        this.packet_parser.load(this.dir + this.filename);
                        break;
//                        this.logging.logToOutput("test1");
//                            this.logging.logToOutput("File modified: " + event.context());
                    }
                }

                // WatchKey 재사용하기 전에 리셋해야 함
                boolean valid = key.reset();
                watchService.close();
                if (!valid) {
                    break; // 만약 key가 유효하지 않다면 루프를 종료
                }
            }
        } catch (Exception ex) {
            this.logging.logToOutput(ex.toString());
        }
    }

//    public synchronized void test() throws InterruptedException {
//        this.packet_parser.lock = 1;
//        this.logging.logToOutput("Lock");
//        Thread.sleep(4000);
//        this.packet_parser.lock = 0;
//        this.logging.logToOutput("Unlock");
//
//    }
}