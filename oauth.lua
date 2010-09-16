module(...,package.seeall)
---
-- Using oauth in lua.
--
--     Copyright 2009-2010 by DracoBlue (JanS@DracoBlue.de)
--                 http://dracoblue.net
--
-- Depends:
--   crypto
--   base64
--   curl
--
--
-- Resources and further reading:
--   OAuth RFC
--      http://oauth.net/core/1.0
--   Jeffrey's lightroom plugin
--      http://regex.info/blog/lua/twitter
--

local crypto = require("crypto")
local hmac = require("crypto.hmac")
local base64 = require("base64")
local cURL = require("curl")

---
-- Encode a parameter in that way, so it fits RFC2986
-- @link http://oauth.net/core/1.0a#encoding_parameters
local function encode_parameter(str)
    return str:gsub('[^-%._~a-zA-Z0-9]', function(c)
        return string.format("%%%02x", c:byte()):upper()
    end)
end

---
-- Wrapper for get requests.
local function rawGetRequest(url)
    local c = cURL.easy_init()
    c:setopt(cURL.OPT_URL,url)

    local response = {}
    c:setopt(cURL.OPT_WRITEFUNCTION, function(str)
        table.insert(response, str)
        return #str
    end)
    c:perform()
    return table.concat(response,"")
end

---
-- Wrapper for post requests.
local function rawPostRequest(url, rawdata)
    local c = cURL.easy_init()
    c:setopt(cURL.OPT_URL,url)
    c:setopt(cURL.OPT_POST, 1);
    c:setopt(cURL.OPT_POSTFIELDS, rawdata); 

    local response = {}
    c:setopt(cURL.OPT_WRITEFUNCTION, function(str)
        table.insert(response, str)
        return #str
    end)
    c:perform()
    return table.concat(response,"")
end

---
-- Calculate the sha1 hash for a given string.
local function sha1(str, key, binary)
    binary = binary or false
    return hmac.digest("sha1",str,key,binary)
end

---
-- Generate nonce none for oauth
local function oauth_nonce()
   return base64.encode(hmac.digest("sha1",tostring(math.random()) .. "random" .. tostring(os.time()),"keyyyy"))
end

---
-- Returns the current time as a Unix timestamp.
--
local function unix_timestamp()
   return tostring(os.time() + 1) -- we want the next second
end

---
-- Given a url endpoint, a GET/POST method, and a table of key/value args, build
-- the query string and sign it, returning the query string (in the case of a
-- POST) or, for a GET, the final url.
--
-- The args should also contain an 'oauth_token_secret' item, except for the
-- initial token request.
--
local function oauth_sign(url, method, args, consumer_secret)
    assert(method == "GET" or method == "POST","method must be either POST or GET")
    assert(consumer_secret,"consumer_secret required")
    assert(url,"url required")
   
    args = args or {}

    local token_secret    = args.oauth_token_secret or ""

    --
    -- Remove the token_secret from the args, 'cause we neither send nor sign it.
    -- (we use it for signing which is why we need it in the first place)
    --
    args.oauth_token_secret = nil

    args.oauth_signature_method = 'HMAC-SHA1'

    --
    -- oauth-encode each key and value, and get them set up for a Lua table sort.
    --
    local keys_and_values = { }

    for key, val in pairs(args) do
        table.insert(keys_and_values, {
          key = encode_parameter(key),
          val = encode_parameter(val)
        })
    end

    --
    -- Sort by key first, then value
    --
    table.sort(keys_and_values, function(a,b)
        if a.key < b.key then
            return true
        elseif a.key > b.key then
            return false
        else
            return a.val < b.val
        end
    end)

    --
    -- Now combine key and value into key=value
    --
    local key_value_pairs = { }
    for _, rec in pairs(keys_and_values) do
        table.insert(key_value_pairs, rec.key .. "=" .. rec.val)
    end

   --
   -- Now we have the query string we use for signing, and, after we add the
   -- signature, for the final as well.
   --
   local query_string_except_signature = table.concat(key_value_pairs, "&")

   -- Hint from Jeffrey Fried at http://regex.info/blog/lua/twitter :
   --    Don't need it for Twitter, but if this routine is ever adapted for
   --    general OAuth signing, we may need to massage a version of the url to
   --    remove query elements, as described in http://oauth.net/core/1.0#rfc.section.9.1.2
   local SignatureBaseString = method .. '&' .. encode_parameter(url) .. '&' .. encode_parameter(query_string_except_signature)
   local key = encode_parameter(consumer_secret) .. '&' .. encode_parameter(token_secret)

   --
   -- Now have our text and key for HMAC-SHA1 signing
   --
   local hmac_binary = sha1(SignatureBaseString, key, true)

   --
   -- Base64 encode it
   --
   local hmac_b64 = base64.encode(hmac_binary)

   --
   -- Now append the signature to end up with the final query string
   --
   local query_string = query_string_except_signature .. '&oauth_signature=' .. encode_parameter(hmac_b64)

   if method == "GET" then
      -- return the full url
      return url .. "?" .. query_string
   else
      -- for a post, just return the query string, so it can be included in the POST payload
      return query_string
   end
end

---
-- @return oauth_RequestToken
local function getRequestToken(options)
    assert(options.authorize_url,"authorize_url option must be set") 
    assert(options.request_token_url,"request_token_url option must be set") 
    assert(options.consumer_key,"consumer_key option must be set")
    assert(options.consumer_secret,"consumer_secret option must be set")
    assert(options.token_ready_url,"token_ready_url option must be set")
    
    local authorize_url = options.authorize_url
    
    local post_data = {
         oauth_consumer_key = options.consumer_key,
         oauth_timestamp    = unix_timestamp(),
         oauth_version      = '1.0',
         oauth_callback     = options.token_ready_url,
         oauth_nonce        = oauth_nonce(),
    }
    local post_data = oauth_sign(options.request_token_url,
                          "POST",
                          post_data,
                          options.consumer_secret)
    local result, headers = rawPostRequest(options.request_token_url, post_data)
   
    local token        = result:match('oauth_token=([^&]+)')
    local token_secret = result:match('oauth_token_secret=([^&]+)')

    if not token then
       return nil, "couldn't get request token"
    end

    return {
        getToken = function ()
            return token
        end,
        getTokenSecret = function ()
            return token_secret
        end,
        getAuthUrl = function ()
            return authorize_url .. '?oauth_token=' .. encode_parameter(token)
        end
    }
end

---
--
-- @return oauth_Access
local function getAccessByTokenAndSecret(token, token_secret, options)
    assert(options.consumer_key,"consumer_key option must be set")
    local consumer_key = options.consumer_key
    
    local function local_call(url, method, params)
        local post_data = {
           oauth_consumer_key = options.consumer_key,
           oauth_timestamp    = unix_timestamp(),
           oauth_version      = '1.0',
           oauth_nonce        = oauth_nonce(),
           oauth_token           = token
        }
        for k,v in pairs(params) do
            post_data[k] = v
        end
        if (method == "POST") then
            post_data = oauth_sign(
                url,
                "POST",
                post_data,
                token_secret
            )
            return rawPostRequest(url, post_data)
        elseif (method == "GET") then
            url = oauth_sign(
                url,
                "GET",
                post_data,
                token_secret
            )
            return rawGetRequest(url)
        end
        return nil, "Wrong method. Can be only POST or GET"
    end
    
    return {
        call = local_call
    }
end

local function parse_access_token_response(consumer_key, response)
    local oauth_token        = response:match(       'oauth_token=([^&]+)')
    local oauth_token_secret = response:match('oauth_token_secret=([^&]+)')
    local user_id            = response:match(           'user_id=([^&]+)')
    local screen_name        = response:match(       'screen_name=([^&]+)')

    if oauth_token and oauth_token_secret and user_id and screen_name then
        return {
            getAccess = function()
                return getAccessByTokenAndSecret(
                    oauth_token,
                    oauth_token_secret,
                    {
                        consumer_key = consumer_key
                    }
                )
            end,
            getToken = function()
               return oauth_token
            end,
            getTokenSecret = function()
                return oauth_token_secret
            end,
            getUserId = function()
                return user_id
            end,
            getScreenName = function()
                return screen_name
            end
        } 
    end

    return nil, "unexpected reply from oauth server:" .. response
end

local function getAccessToken(token, verifier, token_secret, options)
    assert(options.consumer_key,"consumer_key option must be set")
    assert(options.consumer_secret,"consumer_secret option must be set")
    assert(options.access_token_url,"access_token_url option must be set")
    
    local consumer_key = options.consumer_key
    
    local post_data = {
       oauth_consumer_key = consumer_key,
       oauth_timestamp    = unix_timestamp(),
       oauth_version      = '1.0',
       oauth_nonce        = oauth_nonce(),
       oauth_token           = token,
       oauth_token_secret = token_secret,
       oauth_verifier     = verifier
    }
    local post_data = oauth_sign(options.access_token_url,
                          "POST",
                          post_data,
                          options.consumer_secret)
    local result, headers = rawPostRequest(options.access_token_url, post_data)

    return parse_access_token_response(consumer_key, result)
end

local function getAccessTokenByPin(pin, options)
    assert(options.consumer_key,"consumer_key option must be set")
    assert(options.consumer_secret,"consumer_secret option must be set")
    assert(options.access_token_url,"access_token_url option must be set")
    assert(pin,"pin must be given")
    
    local consumer_key = options.consumer_key
    
    local post_data = {
       oauth_consumer_key = consumer_key,
       oauth_timestamp    = unix_timestamp(),
       oauth_version      = '1.0',
       oauth_nonce        = oauth_nonce(),
       oauth_token        = nil,
       oauth_token_secret = nil,
       oauth_verifier     = tostring(pin)
    }
    local post_data = oauth_sign(options.access_token_url,
                          "POST",
                          post_data,
                          options.consumer_secret)
    local result, headers = rawPostRequest(options.access_token_url, post_data)
    print(options.access_token_url, post_data)
    return parse_access_token_response(consumer_key, result)
end

consumer = {}
---
-- @return oauth_Consumer
--
function newConsumer(options)
    assert(options.request_token_url,"request_token_url option must be set") 
    assert(options.authorize_url,"authorize_url option must be set") 
    assert(options.access_token_url,"access_token_url option must be set")
    assert(options.consumer_key,"consumer_key option must be set")
    assert(options.consumer_secret,"consumer_secret option must be set")
    assert(options.token_ready_url,"token_ready_url option must be set")
    
    local consumer_key = options.consumer_key
    local consumer_secret = options.consumer_secret
    local authorize_url = options.authorize_url
    local request_token_url = options.request_token_url
    local access_token_url = options.access_token_url
    local token_ready_url = options.token_ready_url
    
    function local_getRequestToken(callback)
        local auth_opts = {
            consumer_key = consumer_key,
            consumer_secret = consumer_secret,
            request_token_url = request_token_url,
            authorize_url = authorize_url,
            token_ready_url = callback or token_ready_url,
        }
        return getRequestToken(auth_opts)
    end
    function local_getAccessToken(token, verifier, token_secret)
        local access_opts = {
            consumer_key = consumer_key,
            consumer_secret = consumer_secret,
            access_token_url = access_token_url
        }
        return getAccessToken(token, verifier, token_secret, access_opts)
    end
    function local_getAccessTokenByPin(pin)
        local access_opts = {
            consumer_key = consumer_key,
            consumer_secret = consumer_secret,
            access_token_url = access_token_url
        }
        return getAccessTokenByPin(pin, access_opts)
    end
    function local_getAccess(token, token_secret)
        return getAccessByTokenAndSecret(token, token_secret, { consumer_key = consumer_key })
    end
    
    return {
        getRequestToken = local_getRequestToken,
        getAccessToken = local_getAccessToken,
        getAccessTokenByPin = local_getAccessTokenByPin,
        getAccess = local_getAccess
    }
end

