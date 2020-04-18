# Update Access Token
This Burp extension is used to updated bearer tokens, similar to how Burp's cooke jar works. Specifically, it pulls a authorization token out of a JSON response and includes it in future request headers.

## Example
It will extract the following token from an HTTP response:
```
"access_token":"5dbf5b54-4644-4015-a08e-333deea4c78c",
```

And then include it in future request headers in the following format:
```
Authorization: Bearer 5dbf5b54-4644-4015-a08e-333deea4c78c
```
