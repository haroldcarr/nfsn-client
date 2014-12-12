{-
Created       : 2014 Nov 14 (Fri) 14:32:32 by Harold Carr.
Last Modified : 2014 Dec 11 (Thu) 17:28:58 by Harold Carr.
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
import           Data.HashMap.Strict   as H (lookup, toList)
import           Data.Text             as T (Text, unpack)
import           Data.UnixTime         as UT
import           Network.HTTP.Client   (RequestBody (RequestBodyBS))
import           Network.HTTP.Conduit  (HttpException)
import           Network.Wreq
import           System.IO
import           System.Random
import           Text.Printf           (printf)

-- ============================================================================
-- API

-- The index used for a request.
newtype Ix        = Ix         String

type NfsnResponse = Either HttpException (Response L.ByteString)

------------------------------------------------------------------------------
-- aggregate
-- getAllInfo (Ix "haroldcarr")
-- getAllInfo :: Ix -> IO [L.ByteString]
getAllInfo ix0 = do
    a   <- (getMemberAccounts ix0)
    afn <- s getAccountFriendlyName a
    ast <- s getAccountStatus       a
    ab  <- s getAccountBalance      a
    as  <- s getAccountSites        a
    return (afn, a, ast, ab, as)
 where
    s f = sequence . map (\x -> f (Ix $ T.unpack x))

------------------------------------------------------------------------------
-- MEMBER

getMemberAccounts      :: Ix -> IO [T.Text]
getMemberAccounts ix0   = do
    r0 <- rqGetMember "accounts" ix0
    return $ extractListOfText r0

getMemberSites         :: Ix -> IO [T.Text]
getMemberSites    ix0   = do
    r0 <- rqGetMember "sites" ix0
    return $ extractListOfText r0

--  RCat   Ix            RSubCat
-- /member/<member name>/[accounts|sites]
rqGetMember            :: String -> Ix -> IO NfsnResponse
rqGetMember             = rqGet (RCat "member") . RSubCat

------------------------------------------------------------------------------
-- ACCOUNT

getAccountBalance      :: Ix -> IO Double
getAccountBalance ix0   = do
    r0 <- rqGetAccount "balance" ix0
    return $ extract r0 Just (read . tail . init . show) 0.0

getAccountFriendlyName :: Ix -> IO String
getAccountFriendlyName ix0 = do
    r0 <- rqGetAccount "friendlyName" ix0
    return $ extractString r0

getAccountSites        :: Ix -> IO [T.Text]
getAccountSites   ix0   = do
    r0 <- rqGetAccount "sites" ix0
    return $ extractListOfText r0

getAccountStatus       :: Ix -> IO T.Text
getAccountStatus  ix0   = do
    r0 <- rqGetAccount "status" ix0
    return $ extract r0 (\r -> decode r :: Maybe Object)
                        (\dr -> let (Just (String x)) = H.lookup "short" dr in x)
                        ""
--  RCat    Ix          RSubCat
-- /account/<account #>/[balance|friendlyName|sites|status]
rqGetAccount           :: String -> Ix -> IO NfsnResponse
rqGetAccount            = rqGet (RCat "account") . RSubCat

------------------------------------------------------------------------------
-- DNS

getDnsAll              :: Ix -> IO [Int]
getDnsAll        ix0    = mapM (\f -> f ix0) [getDnsExpire, getDnsMinTtl, getDnsRefresh, getDnsRetry, getDnsSerial]

getDnsExpire           :: Ix -> IO Int
getDnsExpire            = rqGetDnsInt "expire"

getDnsMinTtl           :: Ix -> IO Int
getDnsMinTtl            = rqGetDnsInt "minTTL"

getDnsRefresh          :: Ix -> IO Int
getDnsRefresh           = rqGetDnsInt "refresh"

getDnsRetry            :: Ix -> IO Int
getDnsRetry             = rqGetDnsInt "refresh"

getDnsSerial           :: Ix -> IO Int
getDnsSerial            = rqGetDnsInt "serial"

rqGetDnsInt            :: String -> Ix -> IO Int
rqGetDnsInt subcat ix0 = do
    r0 <- rqGetDns subcat ix0
    return $ extract r0 Just (read . tail . init . show) 0

--  RCat Ix           RSubCat
-- /dns/<domain name>/minTTL
rqGetDns               :: String -> Ix -> IO NfsnResponse
rqGetDns                = rqGet (RCat "dns") . RSubCat

------------------------------------------------------------------------------
-- EMAIL

-- NFSN return value is list of pairs: email name -> email forward address,
-- i.e., a JSON object whose labels are not known in advance.

getEmailForwards       :: Ix -> IO [(T.Text, T.Text)]
getEmailForwards  ix0   = do
    r0 <- rqPostEmail "listForwards" ix0
    return $ extract r0 (\r  -> decode r)
                        (\dr -> map (\(x, String y) -> (x,y)) (H.toList dr))
                        []

--  RCat  Ix            RSubCat
-- /email/<domain name>/listForwards
rqPostEmail            :: String -> Ix -> IO NfsnResponse
rqPostEmail             = rqPost (RCat "email") . RSubCat

------------------------------------------------------------------------------
-- SITE

-- not support by NFSN
getSiteInfo            :: Ix -> IO NfsnResponse
getSiteInfo             = rqPostSite  "getInfo"

--  RCat  Ix            RSubCat
-- /site/<short name>/...
rqPostSite             :: String -> Ix -> IO NfsnResponse
rqPostSite              = rqPost (RCat "site") . RSubCat

-- ============================================================================
-- parsing utilities

extract :: Either e (Response a) -> (a -> Maybe d) -> (d -> r) -> r -> r
extract r0 fd fr z =
    case r0 of
        Right r' -> let r = r' ^. responseBody
                    in case fd r of
                           (Just dr) -> fr dr
                           _         -> z
        Left _   -> z

extractListOfText :: NfsnResponse -> [T.Text]
extractListOfText r0 = extract r0 (\r -> decode r :: Maybe [T.Text]) id []

extractString     :: NfsnResponse -> String
extractString     r0 = extract r0 Just (read . show) ""

-- ============================================================================
-- request utilities

newtype RCat        = RCat        String
newtype RSubCat     = RSubCat     String
newtype ApiKey      = ApiKey      String
newtype Body        = Body        String
newtype ContentType = ContentType String
newtype Login       = Login       String
data    Method      = GET | POST deriving Show
newtype Uri         = Uri         String

rqGet  :: RCat -> RSubCat -> Ix -> IO NfsnResponse
rqGet   = rq GET  (ContentType "")

rqPost :: RCat -> RSubCat -> Ix -> IO NfsnResponse
rqPost  = rq POST (ContentType "application/x-www-form-urlencoded")

rq     :: Method -> ContentType -> RCat -> RSubCat -> Ix -> IO NfsnResponse
rq      = reqC (Body "")

reqC   :: Body -> Method -> ContentType -> RCat -> RSubCat -> Ix -> IO NfsnResponse
reqC body method contentRCat rCat rSubCat ix0 =
    E.try $ req body method contentRCat rCat rSubCat ix0

req    :: Body -> Method -> ContentType             -> RCat     -> RSubCat        -> Ix      -> IO (Response L.ByteString)
req (Body body)   method   (ContentType contentType0) (RCat rCat) (RSubCat rSubCat) (Ix ix0) = do
    let uri         = "/" ++ rCat ++ "/" ++ ix0 ++ "/" ++ rSubCat
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

authHash :: Uri  -> Login      -> ApiKey       -> Body       -> IO String
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
