# A Library for Oauth in lua

This library was created a while back and works well with twitter's oauth
implementation.

* Version: 1.1
* Date: 2011/10/06

## Copyright

Copyright 2009-2011 by DracoBlue (JanS@DracoBlue.de) from <http://dracoblue.net>

## License

This library is released under the terms of MIT License.

## Examples with oauth redirect or for oob

See example_google.lua and example_twitter.lua for working `oob` examples. You may
use a proper token_ready-url if you want to use a website instead of an standalone
application.

## Example with single_token (without oauth redirect or long-lived token)
    
    -- generate a accesstoken, by the single_token at
    -- http://dev.twitter.com/pages/oauth_single_token
    access, msg = consumer.getAccess(
        "fdgsdf908g7df98g7dfs9g7df98g7df9g8fdg98", -- oauth_token
        "89fdg80df78gdasd9as0dsa0ds21kjh321kj3h12" -- oauth_token_secret 
    )

    -- now call a method!
    return_value = access.call("method", {
        param = 'value',
        param2 = 'value2'
    });

## Dependencies

* crypto
* base64
* luacurl (luarocks install luacurl)

## Changelog

* 1.1.0 (2011/10/06)
  * Use Authorization-Header instead of GET-Parameters
  * dropped curl dependency and replaced with luacurl
  * nonce is not base64 encoded anymore
  * decode parameters returned by requests
  * added examples for twitter and google
* 1.0.0 (2010/09/16)
  * Initial release

## Resources and further reading:

* OAuth RFC
 <http://oauth.net/core/1.0>
* Jeffrey's lightroom plugin
 <http://regex.info/blog/lua/twitter>



