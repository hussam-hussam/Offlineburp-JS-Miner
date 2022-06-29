package burp.core.scanners;

import burp.*;
import burp.utils.Utilities;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

import static burp.utils.Constants.*;
import static burp.utils.Utilities.appendFoundMatches;
import static burp.utils.Utilities.sendNewIssue2;

public class SubDomains2 implements Runnable {
    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = callbacks.getHelpers();
    private final String baseRequestResponse;
    private final String url;
    private final UUID taskUUID;

    public SubDomains2(String url, String baseRequestResponse, UUID taskUUID) {
        this.baseRequestResponse = baseRequestResponse;
        this.taskUUID = taskUUID;
        this.url = url;
    }

    @Override
    public void run() {
        BurpExtender.getTaskRepository().startTask(taskUUID);

        String responseBodyString = baseRequestResponse;
        if (1) {
            // For reporting unique matches with markers
            List<byte[]> uniqueMatches = new ArrayList<>();
            StringBuilder uniqueMatchesSB = new StringBuilder();

            // ip matching
            Pattern subDomainsRegex = Pattern.compile("[\"'/](([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])[\"'/]", Pattern.CASE_INSENSITIVE);
            Matcher matcherSubDomains = subDomainsRegex.matcher(responseBodyString);
            while (matcherSubDomains.find() && BurpExtender.isLoaded()) {
                    uniqueMatches.add(helpers.urlDecode(matcherSubDomains.group()).getBytes(StandardCharsets.UTF_8));
                    appendFoundMatches(helpers.urlDecode(matcherSubDomains.group()), uniqueMatchesSB);
            }
            //hostname matching
            Pattern subDomainsRegex = Pattern.compile("[\"'/](([a-zA-Z0-9]|[a-zA-Z0-9][-a-zA-Z0-9]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][-A-Za-z0-9]*[A-Za-z0-9])[\"'/]", Pattern.CASE_INSENSITIVE);
            Matcher matcherSubDomains = subDomainsRegex.matcher(responseBodyString);
            while (matcherSubDomains.find() && BurpExtender.isLoaded()) {
                    uniqueMatches.add(helpers.urlDecode(matcherSubDomains.group()).getBytes(StandardCharsets.UTF_8));
                    appendFoundMatches(helpers.urlDecode(matcherSubDomains.group()), uniqueMatchesSB);
            }
            reportFinding(url,baseRequestResponse, uniqueMatchesSB, uniqueMatches);
        }
        BurpExtender.getTaskRepository().completeTask(taskUUID);
    }

    private static void reportFinding(String url, String baseRequestResponse, StringBuilder allMatchesSB, List<byte[]> uniqueMatches) {
        if (allMatchesSB.length() > 0) {
            // Get markers of found Cloud URL Matches
            List<int[]> allMatchesMarkers = Utilities.getMatches(baseRequestResponse.getResponse(), uniqueMatches);

            // report the issue
            sendNewIssue2(url,
                    "[JS Miner] Subdomains",
                    "The following subdomains were found in a static file.",
                    allMatchesSB.toString(),
                    allMatchesMarkers,
                    SEVERITY_INFORMATION,
                    CONFIDENCE_CERTAIN
            );
        }
    }
}
