package burp.core;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.core.scanners.*;
import burp.utils.Utilities;
import java.nio.file.Files;
import java.nio.file.Path;

import java.time.Instant;
import java.util.Iterator;
import java.util.Set;
import java.util.UUID;

import static burp.BurpExtender.mStdOut;
import static burp.utils.Constants.*;


/**
 * Class to build and run specific scans. It also feeds data to TaskRepository.
 */
public class ScannerBuilder2 {
    private static final String[] EXTENSION_JS = {"js"};
    private static final String[] EXTENSION_JS_JSON = {"js", "json"};
    private static final String[] EXTENSION_CSS = {"css"};
    private static final String[] EXTENSION_JS_JSON_CSS_MAP = {"js", "json", "css", "map"};
    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = callbacks.getHelpers();

    private final String[] baseRequestResponseArray;
    private final int taskId;
    private final long timeStamp;
    private final boolean scanSecrets;
    private final boolean scanDependencyConfusion;
    private final boolean scanCloudURLs;
    private final boolean scanSubDomains;
    private final boolean scanInlineSourceMapFiles;
    private final boolean activeSourceMapperScan;
    private final boolean dumpStaticFiles;
    private final boolean endpointsFinder;


    public static class Builder {
        // Required parameters
        private final String[] baseRequestResponseArray;

        // Optional parameters - initialized to default values
        private long timeStamp = Instant.now().toEpochMilli();
        private int taskId = -1;
        private boolean scanSecrets = false;
        private boolean scanDependencyConfusion = false;
        private boolean scanCloudURLs = false;
        private boolean scanSubDomains = false;
        private boolean scanInlineSourceMapFiles = false;
        private boolean activeSourceMapperScan = false;
        private boolean dumpStaticFiles = false;
        private boolean endpointsFinder = false;

        public Builder(String[] baseRequestResponseArray) {
            this.baseRequestResponseArray = baseRequestResponseArray;
        }

        public Builder taskId(int id) {
            taskId = id;
            return this;
        }

        public Builder scanSecrets() {
            scanSecrets = true;
            return this;
        }

        public Builder scanDependencyConfusion() {
            scanDependencyConfusion = true;
            return this;
        }

        public Builder scanCloudURLs() {
            scanCloudURLs = true;
            return this;
        }

        public Builder scanSubDomains() {
            scanSubDomains = true;
            return this;
        }

        public Builder scanInlineSourceMapFiles() {
            //scanInlineSourceMapFiles = true;
            scanInlineSourceMapFiles = false;
            return this;
        }

        public Builder activeSourceMapperScan() {
            //activeSourceMapperScan = true;
            activeSourceMapperScan = false;
            return this;
        }

        public Builder timeStamp(long ts) {
            timeStamp = ts;
            return this;
        }

        public Builder dumpStaticFiles() {
            //dumpStaticFiles = true;
            dumpStaticFiles = false;
            return this;
        }

        public Builder endpointsFinder() {
            //endpointsFinder = true;
            endpointsFinder = false;
            return this;
        }

        public Builder runAllPassiveScans() {
            scanDependencyConfusion = true;
            scanSubDomains = true;
            scanSecrets = true;
            scanCloudURLs = true;
            //scanInlineSourceMapFiles = true;
            scanInlineSourceMapFiles = false;
            //endpointsFinder = true;
            endpointsFinder = false;
            return this;
        }

        public Builder runAllScans() {
            runAllPassiveScans();
            activeSourceMapperScan();
            return this;
        }

        public ScannerBuilder2 build() {
            return new ScannerBuilder2(this);
        }
    }

    private ScannerBuilder2(Builder builder) {
        baseRequestResponseArray = builder.baseRequestResponseArray;
        taskId = builder.taskId;
        timeStamp = builder.timeStamp;
        scanSecrets = builder.scanSecrets;
        scanDependencyConfusion = builder.scanDependencyConfusion;
        scanCloudURLs = builder.scanCloudURLs;
        scanSubDomains = builder.scanSubDomains;
        scanInlineSourceMapFiles = builder.scanInlineSourceMapFiles;
        activeSourceMapperScan = builder.activeSourceMapperScan;
        dumpStaticFiles = builder.dumpStaticFiles;
        endpointsFinder = builder.endpointsFinder;
    }

    public void runScans() {
        if (scanSecrets) {
            runSecretsScan(baseRequestResponseArray, taskId, timeStamp);
        }

        if (scanDependencyConfusion) {
            runDependencyConfusionScan(baseRequestResponseArray, taskId, timeStamp);
        }

        if (scanCloudURLs) {
            runCloudURLsScan(baseRequestResponseArray, taskId, timeStamp);
        }

        if (scanSubDomains) {
            runSubDomainsScan(baseRequestResponseArray, taskId, timeStamp);
        }
        /*
        if (scanInlineSourceMapFiles) {
            runInlineSourceMapper(baseRequestResponseArray, taskId, timeStamp);
        }
        
        if (activeSourceMapperScan) {
            runActiveSourceMapper(baseRequestResponseArray, taskId, timeStamp);
        }

        if (dumpStaticFiles) {
            runStaticFilesDumper(baseRequestResponseArray, taskId, timeStamp);
        }

        if (endpointsFinder) {
            runEndpointsFinder(baseRequestResponseArray, taskId, timeStamp);
        }
        */
    }

    private static String getFileContents(String path){
    try{
        Path fileName= Path.of(path);
        return Files.readString(fileName);
    }
    catch(Exception e){
        return "";
        }
    }
    private static void scanVerifierExecutor(String path, int taskId, TaskName taskName, long timeStamp, boolean isLastIterator) {
        String url = path;
        System.out.println("the path is: "+path);
        String requestResponse = getFileContents(path);
        System.out.println("we read the contents");
        if(requestResponse=="")return;
        System.out.println(requestResponse);
        byte[] responseBodyHash = Utilities.getHTTPResponseBodyHash2(requestResponse);
        // Checks if Request URL & Response Body Hash were not scanned before
        if (BurpExtender.getTaskRepository().notDuplicate(taskName, url, responseBodyHash)) {
            UUID uuid = UUID.randomUUID();
            // New queued task
            BurpExtender.getTaskRepository().addTask(
                    new Task(taskId, uuid, taskName, url, responseBodyHash)
            );
            switch (taskName){
                case SECRETS_SCAN:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new Secrets2(url, requestResponse, uuid));
                    break;
                case DEPENDENCY_CONFUSION_SCAN:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new DependencyConfusion2(url, requestResponse, uuid, true));
                    break;
                case DEPENDENCY_CONFUSION_SCAN_2:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new DependencyConfusion2(url, requestResponse, uuid, false));
                    break;
                case SUBDOMAINS_SCAN:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new SubDomains2(url, requestResponse, uuid));
                    break;
                case CLOUD_URLS_SCAN:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new CloudURLs2(url, requestResponse, uuid));
                    break;
                /*
                case INLINE_JS_SOURCE_MAPPER:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new InlineSourceMapFiles(url, requestResponse, uuid, timeStamp));
                    break;
                case SOURCE_MAPPER_ACTIVE_SCAN:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new ActiveSourceMapper(url, requestResponse, timeStamp, uuid));
                    break;
                case STATIC_FILES_DUMPER:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new StaticFilesDumper(url, requestResponse, timeStamp, uuid, isLastIterator));
                    break;
                
                case ENDPOINTS_FINDER:
                    BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                            new Endpoints(requestResponse, uuid));
                    break;
                */
                default:
                    break;
            }
        } else {
            // Log skipped task to console
            logSkippedScanInfo(taskId, taskName, url);
        }
    }

    private static void runSecretsScan(String[] baseRequestResponseArray, int taskId, long timeStamp) {
        //Set<IHttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS_JSON);
        for (int i=0;i<baseRequestResponseArray.length;i++) {
            scanVerifierExecutor(baseRequestResponseArray[i], taskId, TaskName.SECRETS_SCAN, timeStamp, false);
        }
    }

    private static void runDependencyConfusionScan(String[] baseRequestResponseArray, int taskId, long timeStamp) {
        // run Dependency Confusion Regex for all JS/JSON files
        //Set<IHttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS_JSON);
        for (int i=0;i<baseRequestResponseArray.length;i++) {
            scanVerifierExecutor(baseRequestResponseArray[i], taskId, TaskName.DEPENDENCY_CONFUSION_SCAN, timeStamp, false);
        }

        // For CSS files, don't run the regex (only check for disclosures like in '/node_modules/<pkg>')
        //Set<IHttpRequestResponse> uniqueRequestsCSS = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_CSS);
        for (int i=0;i<baseRequestResponseArray.length;i++) {
            scanVerifierExecutor(baseRequestResponseArray[i], taskId, TaskName.DEPENDENCY_CONFUSION_SCAN_2, timeStamp, false);
        }
    }

    private static void runCloudURLsScan(String[] baseRequestResponseArray, int taskId, long timeStamp) {
        //Set<IHttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS_JSON);
        for (int i=0;i<baseRequestResponseArray.length;i++) {
            scanVerifierExecutor(baseRequestResponseArray[i], taskId, TaskName.CLOUD_URLS_SCAN, timeStamp, false);
        }
    }

    private static void runSubDomainsScan(String[] baseRequestResponseArray, int taskId, long timeStamp) {
        //Set<IHttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS_JSON);
        for (int i=0;i<baseRequestResponseArray.length;i++) {
            scanVerifierExecutor(baseRequestResponseArray[i], taskId, TaskName.SUBDOMAINS_SCAN, timeStamp, false);
        }
    }
/*
    private static void runInlineSourceMapper(String[] baseRequestResponseArray, int taskId, long timeStamp) {
        //Set<IHttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS);
        for (int i=0;i<baseRequestResponseArray.length;i++) {
            scanVerifierExecutor(baseRequestResponseArray[i], taskId, TaskName.INLINE_JS_SOURCE_MAPPER, timeStamp, false);
        }
    }

    private static void runActiveSourceMapper(String[] baseRequestResponseArray, int taskId, long timeStamp) {
        //Set<IHttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS);
        for (int i=0;i<baseRequestResponseArray.length;i++) {
            scanVerifierExecutor(baseRequestResponseArray[i], taskId, TaskName.SOURCE_MAPPER_ACTIVE_SCAN, timeStamp, false);
        }
    }

    private static void runStaticFilesDumper(String[] baseRequestResponseArray, int taskId, long timeStamp) {
        Set<IHttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS_JSON_CSS_MAP);
        Iterator<IHttpRequestResponse> iterator = uniqueRequests.iterator();
        while (iterator.hasNext()) {
            boolean isLastIterator = false;
            IHttpRequestResponse httpRequestResponse = iterator.next();
            if (!iterator.hasNext()) {
                isLastIterator = true;
            }
            scanVerifierExecutor(httpRequestResponse, taskId, TaskName.STATIC_FILES_DUMPER, timeStamp, isLastIterator);
        }
    }
*/
    private static void runEndpointsFinder(String[] baseRequestResponseArray, int taskId, long timeStamp) {
        //Set<IHttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS);
        for (int i=0;i<baseRequestResponseArray.length;i++) {
            scanVerifierExecutor(baseRequestResponseArray[i], taskId, TaskName.ENDPOINTS_FINDER, timeStamp, false);
        }
    }


    @Override
    public String toString() {
        return "Scan Information{" +
                "RequestURL=" + baseRequestResponseArray[0] +
                ", taskId=" + taskId +
                ", timeStamp=" + timeStamp +
                ", scanSecrets=" + scanSecrets +
                ", scanDependencyConfusion=" + scanDependencyConfusion +
                ", scanCloudURLs=" + scanCloudURLs +
                ", scanSubDomains=" + scanSubDomains +
                ", scanInlineSourceMapFiles=" + scanInlineSourceMapFiles +
                ", activeSourceMapperScan=" + activeSourceMapperScan +
                '}';
    }

    private static void logSkippedScanInfo(int taskId, TaskName scannerName, String url) {
        if (taskId != -1 && BurpExtender.getExtensionConfig().isVerboseLogging()) {
            mStdOut.printf(LOG_FORMAT, "[" + TaskStatus.SKIPPED + "]", LOG_TASK_ID_PREFIX + taskId, scannerName, url);
        }
    }

}
