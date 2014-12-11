{-
Created       : 2014 Nov 14 (Fri) 14:32:32 by Harold Carr.
Last Modified : 2014 Dec 10 (Wed) 17:32:33 by Harold Carr.
-}

{-# LANGUAGE OverloadedStrings #-}

module NFSNClient where

import           Control.Lens
import           Control.Monad         (when)
import           Crypto.Hash.SHA1      (hash)
import qualified Data.ByteString       as S
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy  as L
import           Data.UnixTime         as UT
import           Network.HTTP.Client   (RequestBody (RequestBodyBS))
import           Network.Wreq
import           System.IO
import           System.Random
import           Text.Printf           (printf)

------------------------------------------------------------------------------

debug :: Bool
debug  = False

newtype ApiKey      = ApiKey      String
newtype Body        = Body        String
newtype ContentType = ContentType String
newtype Id0         = Id0         String
newtype Login       = Login       String
newtype Member      = Member      String
data    Method      = GET | POST deriving Show
newtype Type0       = Type0       String
newtype Uri         = Uri         String

------------------------------------------------------------------------------
-- MEMBER

getMemberAccounts      :: Id0 -> IO L.ByteString
getMemberAccounts       = rqGetMember "accounts"

getMemberSites         :: Id0 -> IO L.ByteString
getMemberSites          = rqGetMember "sites"

rqGetMember            :: String -> Id0 -> IO L.ByteString
rqGetMember             = rqGet (Type0 "member") . Member

------------------------------------------------------------------------------
-- ACCOUNT

getAccountBalance      :: Id0 -> IO L.ByteString
getAccountBalance       = rqGetAccount "balance"

getAccountFriendlyName :: Id0 -> IO L.ByteString
getAccountFriendlyName  = rqGetAccount "friendlyName"

getAccountSites        :: Id0 -> IO L.ByteString
getAccountSites         = rqGetAccount "sites"

getAccountStatus       :: Id0 -> IO L.ByteString
getAccountStatus        = rqGetAccount "status"

rqGetAccount           :: String -> Id0 -> IO L.ByteString
rqGetAccount            = rqGet (Type0 "account") . Member

------------------------------------------------------------------------------
-- DNS

getDnsMinTtl           :: Id0 -> IO L.ByteString
getDnsMinTtl            = rqGetDns "minTTL"

rqGetDns               :: String -> Id0 -> IO L.ByteString
rqGetDns                = rqGet (Type0 "dns") . Member

------------------------------------------------------------------------------
-- EMAIL

getEmailForwards       :: Id0 -> IO L.ByteString
getEmailForwards        = rqPostEmail  "listForwards"

rqPostEmail            :: String -> Id0 -> IO L.ByteString
rqPostEmail             = rqPost (Type0 "email") . Member

------------------------------------------------------------------------------
-- SITE

-- not support by NFSN
getSiteInfo            :: Id0 -> IO L.ByteString
getSiteInfo             = rqPostSite  "listBandwidthActivity"

rqPostSite             :: String -> Id0 -> IO L.ByteString
rqPostSite              = rqPost (Type0 "site") . Member

------------------------------------------------------------------------------

rqGet  :: Type0 -> Member -> Id0 -> IO L.ByteString
rqGet   = rq GET  (ContentType "")

rqPost :: Type0 -> Member -> Id0 -> IO L.ByteString
rqPost  = rq POST (ContentType "application/x-www-form-urlencoded")

rq  :: Method -> ContentType -> Type0 -> Member -> Id0 -> IO L.ByteString
rq method contentType type0 member id0 = do
    r <- req (Body "") method contentType type0 member id0
    return $ r ^. responseBody

req :: Body -> Method -> ContentType -> Type0 -> Member -> Id0 -> IO (Response L.ByteString)
req (Body body) method (ContentType contentType0) (Type0 type0) (Member member) (Id0 id0) =
  do
    let uri         = "/" ++ type0 ++ "/" ++ id0 ++ "/" ++ member
    (login, apiKey) <- getApiKey
    strHash         <- authHash (Uri uri) login apiKey (Body body)
    let apiHost     = "api.nearlyfreespeech.net"
    let contentType = if null contentType0 then "application/x-nfsn-api" else contentType0
    let opts        = defaults & header "Host"                  .~ [C8.pack apiHost]
                               & header "Content-Type"          .~ [C8.pack contentType]
                               & header "X-NFSN-Authentication" .~ [C8.pack strHash]
    let url         = "https://" ++ apiHost ++ ":443" ++ uri
    -- let url         = "http://" ++ apiHost ++ ":443" ++ uri
    -- let url         = "http://localhost:8080" ++ uri
    when debug $ do
        print url
        print $ show method ++ " " ++ uri ++ " HTTP/1.0"
        print opts
        print body
    case method of
        GET  -> do resp <- getWith  opts url
                   response resp
        -- 'Raw' to set the correct content type
        POST -> do resp <- postWith opts url (Raw (C8.pack contentType) (RequestBodyBS (C8.pack body)))
                   response resp
  where
    response r = do
        when debug $
            print r
        return r

authHash :: Uri -> Login -> ApiKey -> Body -> IO String
authHash (Uri uri) (Login login) (ApiKey apiKey) (Body body) = do
    let bodyHash = sha1 body
    tmStamp      <- time
    strSalt      <- salt
    let strCheck = ic ";" [login, tmStamp, strSalt, apiKey, uri, bodyHash]
    let strHash  = sha1 strCheck
    return $ ic ";" [login, tmStamp, strSalt, strHash]

salt :: IO String
salt = do
    let strChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    t            <- UT.getUnixTime
    let g        = mkStdGen (read (show $ utSeconds t) :: Int)
    let rs       = randomRs (0, length strChars - 1) g
    let saltLoop xs (i:is)
            | length xs < 16 = saltLoop (strChars !! i : xs) is
            | otherwise      = xs
    return $ saltLoop [] rs

sha1 :: String -> String
sha1 = toHex . hash . C8.pack

toHex :: S.ByteString -> String
toHex bytes = S.unpack bytes >>= printf "%02x"

time :: IO String
time = do
    ut <- UT.getUnixTime
    return $ show (utSeconds ut)

apiKeyFile :: String
apiKeyFile  = ".access_tokens" -- single line, space separated, no newline

getApiKey :: IO (Login, ApiKey)
getApiKey = do
    tokens <- withFile apiKeyFile ReadMode hGetLine
    let [login, apiKey] = words tokens
    return (Login login, ApiKey apiKey)

ic :: String -> [String] -> String
ic a as = C8.unpack $ C8.intercalate (C8.pack a) (map C8.pack as)

-- End of file.
