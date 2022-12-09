package burp;
// vim: et:ts=4:sts=4:sw=4:fileencoding=utf-8

import java.io.PrintWriter;
import java.util.List;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.text.DateFormat;

public class BurpExtender implements burp.IBurpExtender, burp.IHttpListener
{
    private burp.IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private String nextToken = "";
    private int nextTokenLen = 0;

    // implement IBurpExtender
    @Override
    public void registerExtenderCallbacks(burp.IBurpExtenderCallbacks callbacks)
    {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(),true);

        // set our extension name
        callbacks.setExtensionName("Update Access Token");

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);

        stdout.println("-----Plugin Loaded-------");
    }


    // implement IHttpListener
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo)
    {
        boolean updated = false;
        String[] checks = new String[]{ "{\"accessToken\":\"", "{\"accesstoken\":\"","{\"AccessToken\":\"","{\"access_Token\":\"","{\"access_token\":\"" ,"{\"Access_Token\":\""};

        // only process requests
        if (messageIsRequest) {
            // get the HTTP service for the request
            burp.IHttpService httpService = messageInfo.getHttpService();
            burp.IRequestInfo iRequest = helpers.analyzeRequest(messageInfo);

            String request = new String(messageInfo.getRequest());

            List<String> headers = iRequest.getHeaders();
            // get the request body
            String reqBody = request.substring(iRequest.getBodyOffset());

            //Get all the data needed
            String[] pieces = headers.get(0).split(" ", 3);
            String httpmethod = pieces[0];
            String uri = pieces[1];

            //Update Token Logic
            if (!nextToken.equals("")) {
                //Code for updating a token in a Header
                //log old header & update new header
                for (int i = 0; i < headers.size(); i++)
                {
                    String H = headers.get(i);
                    if (H.toLowerCase().startsWith("authorization:")) {
                        pieces = H.split(" ", 3);
                        if (pieces[1].toLowerCase().equals("bearer")) {
                            String hash = pieces[2];
                            int hashLen = hash.length();
                            stdout.println("Replacing " + (hashLen < 8 ? hash : hash.substring(0, 4) + "..." + hash.substring(hashLen - 4, hashLen)) 
                                    + " with " + (nextTokenLen < 8 ? nextToken : nextToken.substring(0, 4) + "..." + nextToken.substring(nextTokenLen - 4, nextTokenLen)));
                            H = pieces[0] + " " + pieces[1] + " " + nextToken;
                            headers.set(i, H);
                            updated = true;
                            break;
                        }
                    }
                }
            }

            if (updated) {
                byte[] message = helpers.buildHttpMessage(headers, reqBody.getBytes());
                messageInfo.setRequest(message);
            }
        }
        else//it's a response - grab a new token
        {
            burp.IRequestInfo iResponse = helpers.analyzeRequest(messageInfo);
            String response = new String(messageInfo.getResponse());

            //start at {"access_token":"
            //end at "
            for (String check: checks) {
                if (response.contains(check)) {
                    String startMatch = check;
                    String endMatch = "\"";
                    int tokenStartIndex = response.indexOf(startMatch) + startMatch.length();
                    int tokenEndIndex = response.indexOf(endMatch, tokenStartIndex+1);

                    nextToken = response.substring(tokenStartIndex, tokenEndIndex);
                    nextTokenLen = nextToken.length();

                    DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
                    Date date = new Date();

                    stdout.println(dateFormat.format(date));
                    stdout.println("grabbed token starts with" + nextToken.substring(0,16));

                    break;
                }
            }
        }
    }
}
