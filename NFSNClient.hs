{-
Created       : 2014 Nov 14 (Fri) 14:32:32 by Harold Carr.
Last Modified : 2014 Nov 19 (Wed) 13:40:58 by Harold Carr.
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
debug = True

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

getMemberAccounts :: Id0 -> IO L.ByteString
getMemberAccounts  = rqGetMember (Member "accounts")

getMemberSites    :: Id0 -> IO L.ByteString
getMemberSites     = rqGetMember (Member "sites")

rqGetMember :: Member -> Id0 -> IO L.ByteString
rqGetMember  = rqGet (Type0 "member")

------------------------------------------------------------------------------
-- ACCOUNT

getAccountBalance :: Id0 -> IO L.ByteString
getAccountBalance  = rqGetAccount (Member "balance")

getAccountSites   :: Id0 -> IO L.ByteString
getAccountSites    = rqGetAccount (Member "sites")

getAccountStatus  :: Id0 -> IO L.ByteString
getAccountStatus   = rqGetAccount (Member "status")

rqGetAccount :: Member -> Id0 -> IO L.ByteString
rqGetAccount  = rqGet (Type0 "account")

------------------------------------------------------------------------------
-- DNS

getDnsMinTtl      :: Id0 -> IO L.ByteString
getDnsMinTtl       = rqGetDns     (Member "minTTL")

rqGetDns :: Member -> Id0 -> IO L.ByteString
rqGetDns  = rqGet (Type0 "dns")

------------------------------------------------------------------------------
-- EMAIL

getEmailForwards  :: Id0 -> IO L.ByteString
getEmailForwards   = rqPostEmail  (Member "listForwards")

rqPostEmail :: Member -> Id0 -> IO L.ByteString
rqPostEmail  = rqPost (Type0 "email")

------------------------------------------------------------------------------

rqGet :: Type0 -> Member -> Id0 -> IO L.ByteString
rqGet  type0 member id0 = rq GET  type0 id0 member (ContentType "")

rqPost :: Type0 -> Member -> Id0 -> IO L.ByteString
rqPost type0 member id0 = rq POST type0 id0 member (ContentType "application/x-www-form-urlencoded")

rq :: Method -> Type0 -> Id0 -> Member -> ContentType -> IO L.ByteString
rq method type0 id0 member contentType = do
    r <- rq' method type0 id0 member contentType
    return $ r ^. responseBody

rq' :: Method -> Type0 -> Id0 -> Member -> ContentType -> IO (Response L.ByteString)
rq' method type0 id0 member contentType =
    req method
        type0 id0 member
        contentType
        (Body "")

req :: Method
       -> Type0  -> Id0    -> Member
       -> ContentType -> Body
       -> IO (Response L.ByteString)
req method
    (Type0 type0)     (Id0 id0)         (Member member)
    (ContentType contentType0)  (Body body) =
  do
    let uri         = "/" ++ type0 ++ "/" ++ id0 ++ "/" ++ member
    (login, apiKey) <- getApiKey
    strHash         <- authHash (Uri uri) login apiKey (Body body)
    let apiHost     = "api.nearlyfreespeech.net"
    let contentType = if null contentType0 then "application/x-nfsn-api" else contentType0
    let opts        = defaults & header "Host"                  .~ [C8.pack apiHost]
                               & header "Content-Length"        .~ [C8.pack (show (length body))]
                               & header "Content-Type"          .~ [C8.pack contentType]
                               & header "X-NFSN-Authentication" .~ [C8.pack strHash]
    let url         = "https://" ++ apiHost ++ ":443" ++ uri
    -- let url         = "http://localhost:8080" ++ uri
    when debug $ do
        print url
        print $ show method ++ " " ++ uri ++ " HTTP/1.0"
        print opts
        print body
    case method of
        GET  -> do resp <- getWith  opts url
                   response resp
        -- 'Raw' uses the right content type, but still gets NFSN error - probably from writing empty string?
        POST -> do resp <- postWith opts url (Raw (C8.pack contentType) (RequestBodyBS (C8.pack body)))
                   response resp

        -- Posting this way causes: Content-Type: Content-Type: application/octet-stream
        -- POST -> do resp <- postWith opts url (C8.pack body); response resp

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
