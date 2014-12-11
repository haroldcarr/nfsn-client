{-
Created       : 2014 Nov 14 (Fri) 14:32:32 by Harold Carr.
Last Modified : 2014 Dec 10 (Wed) 21:34:05 by Harold Carr.
-}

{-# LANGUAGE OverloadedStrings #-}

module NFSNClient where

import           Control.Exception     as E
import           Control.Lens
import           Crypto.Hash.SHA1      (hash)
import           Data.Aeson
import qualified Data.ByteString       as S
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy  as L
import           Data.HashMap.Strict   (toList)
import           Data.Text             as T (Text, unpack)
import           Data.UnixTime         as UT
import           Network.HTTP.Client   (RequestBody (RequestBodyBS))
import           Network.HTTP.Conduit  (HttpException)
import           Network.Wreq
import           System.IO
import           System.Random
import           Text.Printf           (printf)

------------------------------------------------------------------------------

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
-- aggregate
-- getAllInfo (Id0 "haroldcarr")
-- getAllInfo :: Id0 -> IO [L.ByteString]
getAllInfo id0 = do
    a   <- (getMemberAccounts id0)
    afn <- s getAccountFriendlyName a
    ast <- s getAccountStatus       a
    ab  <- s getAccountBalance      a
    as  <- s getAccountSites        a
    return (afn, a, ast, ab, as)
 where
    s f = sequence . map (\x -> f (Id0 $ T.unpack x))

------------------------------------------------------------------------------
-- MEMBER

getMemberAccounts      :: Id0 -> IO [T.Text]
getMemberAccounts id0   = do
    r0 <- rqGetMember "accounts" id0
    return $ case r0 of
        Right r' -> let r = r' ^. responseBody
                        in case decode r :: Maybe [T.Text] of
                               (Just dr) -> dr
                               _         -> []
        Left _   -> []

-- getMemberSites         :: Id0 -> IO L.ByteString
-- getMemberSites          = rqGetMember "sites"

rqGetMember            :: String -> Id0 -> IO (Either HttpException (Response L.ByteString))
rqGetMember             = rqGet' (Type0 "member") . Member

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

-- NFSN return value is list of pairs: email name -> email forward address,
-- i.e., a JSON object whose labels are not known in advance.
getEmailForwards       :: Id0 -> IO [(T.Text, T.Text)]
getEmailForwards id0    = do
    r0 <- rqPostEmail "listForwards" id0
    return $ case r0 of
        Right r' -> let r = r' ^. responseBody
                    in case decode r of
                           (Just dr) -> map (\(x,String y) -> (x,y)) (toList dr)
                           _         -> []
        Left _   -> []

rqPostEmail            :: String -> Id0 -> IO (Either HttpException (Response L.ByteString))
rqPostEmail             = rqPost' (Type0 "email") . Member

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

rqGet'  :: Type0 -> Member -> Id0 -> IO (Either HttpException (Response L.ByteString))
rqGet'   = rq' GET  (ContentType "")

rqPost :: Type0 -> Member -> Id0 -> IO L.ByteString
rqPost  = rq POST (ContentType "application/x-www-form-urlencoded")

rqPost' :: Type0 -> Member -> Id0 -> IO (Either HttpException (Response L.ByteString))
rqPost'  = rq' POST (ContentType "application/x-www-form-urlencoded")

rq  :: Method -> ContentType -> Type0 -> Member -> Id0 -> IO L.ByteString
rq method contentType type0 member id0 = do
    r <- req (Body "") method contentType type0 member id0
    return $ r ^. responseBody

rq'  :: Method -> ContentType -> Type0 -> Member -> Id0 -> IO (Either HttpException (Response L.ByteString))
rq' method contentType type0 member id0 =
    reqC (Body "") method contentType type0 member id0

reqC :: Body -> Method -> ContentType -> Type0 -> Member -> Id0 -> IO (Either HttpException (Response L.ByteString))
reqC body method contentType0 type0 member id0 =
    E.try $ req body method contentType0 type0 member id0

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
    case method of
        GET  -> getWith  opts url
        -- 'Raw' to set the correct content type
        POST -> postWith opts url (Raw (C8.pack contentType) (RequestBodyBS (C8.pack body)))

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
