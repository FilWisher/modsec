{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}

module ModSecurity.ToConf where

import Data.Text as T hiding (map, intersperse, filter)
import Data.Monoid
import Data.List

import ModSecurity.Rule

class ToConf a where
  toConf :: a -> Text

instance ToConf (Maybe Msg) where
  toConf Nothing = ""
  toConf (Just m) = "msg:'" <> getMsg m <> "'"

instance ToConf Variable where
  toConf RequestUri         = "REQUEST_URI"
  toConf RequestFilename    = "REQUEST_FILENAME"
  toConf RequestBody        = "REQUEST_BODY"
  toConf (RequestHeaders t) = "REQUEST_HEADERS:" <>  t
  toConf RequestMethod      = "REQUEST_METHOD"

instance ToConf [Variable] where
  toConf = mconcat . intersperse "|" . map toConf

instance ToConf Transform where
  toConf t = "t:" <> case t of
    CompressWhitespace -> "compressWhitespace"
    Lowercase          -> "lowercase"
    UrlDecode          -> "urlDecode"
    Base64Decode       -> "base64Decode"

instance ToConf [Transform] where
  toConf = mconcat . intersperse "," . map toConf

instance ToConf (Maybe Action) where
  toConf Nothing = ""
  toConf (Just a) = case a of
    Disabled -> "disabled"
    Drop     -> "drop"
    Simulate -> "simulate"
    Allow    -> "allow"

instance ToConf (Maybe Id) where
  toConf Nothing = ""
  toConf (Just id) = getId id

instance ToConf Operator where
  toConf o = "@" <> case o of
    Rx            -> "rx"
    Contains      -> "contains"
    Streq         -> "streq"
    StreqFromFile -> "streqFromFile"
    BeginsWith    -> "beginsWith"
    Gt            -> "gt"
    NonEmpty      -> "nonEmpty"
    Pm            -> "pm"
    PmFromFile    -> "pmFromFile"
    (Not op)      -> "!" <> toConf op

condString p str =
  if p then str else ""

instance ToConf Rule where
  toConf rule = "SecRule " 
    <> toConf (vars rule) <> " \""
    <> toConf (operator rule) <> " "
    <> argument rule <> "\" \""
    <> options
      [ toConf (action rule)
      , toConf (transforms rule)
      , "id:" <> toConf (rid rule)
      , toConf (msg rule)
      , "phase:" <> pack (show $ phase rule)
      , condString isChained "chain"
      ]
    <> "\""
    <> (condString isChained $ "\n" <> showSubsequent "    " (nextRule rule))
        where isChained = chain rule
              options :: [Text] -> Text
              options = mconcat . intersperse "," . filter (/= "")

showSubsequent :: Text -> Maybe Rule -> Text
showSubsequent _ Nothing = ""
showSubsequent prefix (Just rule) = 
  prefix <> "SecRule "
    <> toConf (vars rule) <> " \""
    <> toConf (operator rule) <> " "
    <> argument rule <> "\" \""
    <> options
      [ toConf (action rule)
      , toConf (transforms rule)
      , "id:" <> toConf (rid rule)
      , toConf (msg rule)
      , "phase:" <> pack (show $ phase rule)
      , condString isChained "chain"
      ]
    <> "\""
    <> (condString isChained $ "\n" <> showSubsequent (prefix <> "    ") (nextRule rule))
        where isChained = chain rule
              options :: [Text] -> Text
              options = mconcat . intersperse "," . filter (/= "")
