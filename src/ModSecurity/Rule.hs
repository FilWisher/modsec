{-# LANGUAGE OverloadedStrings #-}

module ModSecurity.Rule where

import Data.Text

-- TODO: enumerate all possible requests
data Variable
 = RequestUri
 | RequestFilename
 | RequestBody
 | RequestHeaders Text
 | RequestMethod

-- TODO: enumerate all possible transforms
data Transform
  = CompressWhitespace
  | Lowercase
  | UrlDecode
  | Base64Decode

data Action
  = Disabled
  | Drop
  | Simulate
  | Allow

-- TODO: enumarte all possible operators
data Operator
  = Rx
  | Contains
  | Streq
  | StreqFromFile
  | BeginsWith
  | Gt
  | NonEmpty
  | Pm
  | PmFromFile
  | Not Operator

newtype Msg = Msg { getMsg :: Text } 
newtype Id = Id { getId :: Text } 

data Rule = Rule
  { rid :: Maybe Id
  , vars :: [Variable]
  , transforms :: [Transform]
  , msg :: Maybe Msg
  , action :: Maybe Action
  , operator :: Operator
  , argument :: Text
  , phase :: Integer
  , chain :: Bool
  , nextRule :: Maybe Rule
  }

emptyRule :: Rule
emptyRule = Rule
  { rid = Nothing
  , vars = []
  , transforms = []
  , msg = Nothing
  , action = Nothing
  , operator = Gt
  , argument = ""
  , phase = 0
  , chain = False
  , nextRule = Nothing
  }
