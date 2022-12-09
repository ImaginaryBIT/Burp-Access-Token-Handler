package burp;

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
    private Boolean DEBUG = Boolean.TRUE;

    // implement IBurpExtender
    @Override
    public void registerExtenderCallbacks(burp.IBurpExtenderCallbacks callbacks)
    {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(),true);

        // set our extension name
        callbacks.setExtensionName("RSA Decryption and AES decrpyion");

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);

        stdout.println("-----     Plugin Loaded   -------");
        stdout.println("-----Author: Xiaogeng Chen-------");
    }


    // implement IHttpListener
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo)
    {

        boolean updated = false;
        // Set the prefix of target in response, allow to set multiple
        String[] checks = new String[]{ "\"body\":{\"data\":\"",};

        // only process requests
        if (!messageIsRequest) {
            burp.IRequestInfo iResponse = helpers.analyzeRequest(messageInfo);
            String response = new String(messageInfo.getResponse());

            for (String check: checks) {
                while (response.contains(check)) {

                    if(DEBUG)
                    {stdout.println("DEBUG: response= " + response);}

                    // capture the secret key in the response
                    String secretStartMatch = "\",\"secret\":\"";
                    String secretEndMatch = "\"}},\"signature\":\"";

                    int secretStartIndex = response.indexOf(secretStartMatch) + secretStartMatch.length();
                    int secretEndIndex = response.indexOf(secretEndMatch, secretStartIndex+1);

                    encryptedSecretKey = response.substring(secretStartIndex, secretEndIndex);

                    // capture the data in the response

                    String dataStartMatch = "\"body\":{\"data\":\"";
                    String dataEndMatch = "\",\"secret\":\"";

                    int dataStartIndex = response.indexOf(dataStartMatch) + dataEndMatch.length();
                    int dataEndIndex = response.indexOf(dataEndMatch, dataStartIndex+1);

                    encryptedData = response.substring(dataStartIndex, dataEndIndex);

                    // decrypt the secret key using private key

                    String privateKey = FileIOUtil


                    // decrypt the data using decrypted secret key

                    //get the data

                }
            }
        }
    }
}
