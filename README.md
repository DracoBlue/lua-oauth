# A Library for Oauth in lua

This library was created a while back and works well with twitter's oauth
implementation.

## Copyright

Copyright 2009-2010 by DracoBlue (JanS@DracoBlue.de) from <http://dracoblue.net>

## License

This library is released under the terms of MIT License.

## Example of a call, from a sucessful redirect
    
    oauth = require("oauth")
    
    -- create a new consumer, you may generate x accesstokens from it
    consumer = oauth.newConsumer({
        consumer_key = "SUDZIASZDASIUUDSUIDA",
        consumer_secret = "SLDJASLKDJASLKDJASLDKASJDLSKJDASKLDJASLKDJAS",
        request_token_url = 'http://twitter.com/oauth/request_token',
        authorize_url= 'http://twitter.com/oauth/authorize',
        access_token_url= 'http://twitter.com/oauth/access_token',
        token_ready_url='http://example.org/oauth/token_ready'
    })

    -- generate a accesstoken, by a given oauth token + verifier + secret
    -- (those are the result of a successful oauth!)
    -- from the redirect (by the app) there should come a oauth_token + oauth_verifier
    -- for the sake of simplicity of this example those are stored in the params table
    access, msg = consumer.getAccessToken(
        params["oauth_token"],
        params["oauth_verifier"],
        params["secret"]
    )

    -- now call a method!
    return_value = access.call("method", {
        param = 'value',
        param2 = 'value2'
    });

## Dependencies

* crypto
* base64
* curl

## Resources and further reading:

* OAuth RFC
 <http://oauth.net/core/1.0>
* Jeffrey's lightroom plugin
 <http://regex.info/blog/lua/twitter>



