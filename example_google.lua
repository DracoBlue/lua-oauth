    oauth = require("oauth");

    -- create a new consumer, you may generate x accesstokens from it
    consumer = oauth.newConsumer({
        consumer_key = "example.org",
        consumer_secret = "secretGivenByGoogleCom",
        request_token_url = 'https://www.google.com/accounts/OAuthGetRequestToken',
        scope = 'https://spreadsheets.google.com/feeds/',
        authorize_url= 'https://www.google.com/accounts/OAuthAuthorizeToken',
        access_token_url= 'https://www.google.com/accounts/OAuthGetAccessToken',
        token_ready_url='http://example.org/oauth/token_ready'
    })

	local requestToken = consumer.getRequestToken("oob");
    print("Please open: ",requestToken.getAuthUrl())
    print("and enter the pin code: ")

    local pin = io.read()

    local accessToken, err = consumer.getAccessTokenByPin(tostring(pin), requestToken.getToken(), requestToken.getTokenSecret())	
    print(err)
    print(accessToken.getToken())
    print(accessToken.getTokenSecret())

    access, msg = accessToken.getAccess();

    response, err = access.call("https://spreadsheets.google.com/feeds/spreadsheets/private/full", "GET", {})

    -- use that one to check whether your authentification works:
    --response, err = access.call("https://www.google.com/accounts/AuthSubTokenInfo", "GET", {})

    print(response, err)
