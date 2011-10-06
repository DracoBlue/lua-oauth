    oauth = require("oauth");

    -- create a new consumer, you may generate x accesstokens from it
    consumer = oauth.newConsumer({
        consumer_key = "AAAAAAAAAAAAAAAA", -- take that from your twitter app page
        consumer_secret = "BBBBBBBBBBBBBBBB", -- take that from your twitter app page
        request_token_url = 'https://api.twitter.com/oauth/request_token',
        authorize_url= 'https://api.twitter.com/oauth/authorize',
        access_token_url= 'https://api.twitter.com/oauth/access_token',
        token_ready_url='http://example.org/oauth/token_ready'
    })

	local requestToken = consumer.getRequestToken("oob");
    print("Please open: ",requestToken.getAuthUrl())
    print("and enter the pin code: ")

    local pin = io.read()

    local accessToken, err = consumer.getAccessTokenByPin(tostring(pin), requestToken.getToken(), requestToken.getTokenSecret())

    print(accessToken.getToken())
    print(accessToken.getTokenSecret())
    print(accessToken.getUserId())
    print(accessToken.getScreenName())

    access = accessToken.getAccess();

    -- get latest tweets (even if it's private!)
    return_value = access.call("http://api.twitter.com/1/statuses/user_timeline.xml", "GET", {
        count = '2'
    });

    print(access, return_value);
