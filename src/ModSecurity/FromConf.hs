{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}

module ModSecurity.FromConf where

import Data.Text hiding (map, foldr)
import Data.Char
import Text.Parsec hiding (Parser(..))
import Text.Parsec.Text
import Text.ParserCombinators.Parsec hiding (Parser(..), try)

import ModSecurity.Rule
import ModSecurity.ToConf

class FromConf a where
  fromConf :: Text -> Maybe a

instance FromConf Variable where
  fromConf t = case parse parseVariable "" t of
    Left _ -> Nothing
    Right var -> Just var

instance FromConf [Variable] where
  fromConf ts = case parse parseVariables "" ts of
    Left _ -> Nothing
    Right vars -> Just vars

parseVariable :: Parser Variable
parseVariable = do
  var <- many (try (char '_') <|> try letter)
  case var of
    "REQUEST_URI"      -> return RequestUri
    "REQUEST_FILENAME" -> return RequestFilename
    "REQUEST_BODY"     -> return RequestBody
    "REQUEST_METHOD"   -> return RequestMethod
    unrecognized       -> fail $ "Unrecognized variable: " ++ unrecognized

parseVariables :: Parser [Variable]
parseVariables = parseVariable `sepBy` char '|'

opString :: Parser (Operator, Text)
opString = do
  op <- parseOperator
  arg <- parseArgument
  return (op, arg)

parseOperator :: Parser Operator
parseOperator = do
  c <- anyChar
  case c of
    '!' -> do
      op <- parseOperator
      return $ Not op
    '@' -> do
      op <- many letter
      case op of
        "rx"            -> return Rx
        "contains"      -> return Contains
        "streq"         -> return Streq
        "streqFromFile" -> return StreqFromFile
        "beginsWith"    -> return BeginsWith
        "gt"            -> return Gt
        "nonEmpty"      -> return NonEmpty
        "pm"            -> return Pm
        "pmFromFile"    -> return PmFromFile
        _ -> fail "Not a recognized operator"
    c -> fail $ "Expecting either '!' or '@' to start operator string: " ++ [c]

data Part 
  = RuleId (Maybe Id)
  | RuleAction (Maybe Action)
  | RuleMsg (Maybe Msg)
  | RuleChain Bool
  | RulePhase (Maybe Integer)
  | RuleTransform Transform

updateRule :: Part -> Rule -> Rule
updateRule (RuleId mid) rule       = rule { rid    = mid }
updateRule (RuleAction mact) rule  = rule { action = mact }
updateRule (RuleMsg mmsg) rule     = rule { msg    = mmsg }
updateRule (RuleChain ch) rule     = rule { chain  = ch }
updateRule (RulePhase mph) rule    = 
  case mph of
    Nothing -> rule
    Just ph -> rule { phase = ph }
updateRule (RuleTransform t) rule  = rule { transforms = t : transforms rule }

parseId :: Parser Part
parseId = do 
  try (string "id:")
  idString <- many alphaNum
  return $ RuleId (Just $ Id $ pack idString)

stringToAction str
  | str == "drop"     = Just Drop
  | str == "simulate" = Just Simulate
  | str == "disabled" = Just Disabled
  | str == "allow"    = Just Allow
  | otherwise         = Nothing

parseAction :: Parser Part
parseAction = do
  action <- choice $ map (try . string) ["drop", "simulate", "disabled", "allow"]
  return $ RuleAction (stringToAction action)

parseMsg :: Parser Part
parseMsg = do
  try (string "msg:'")
  msg <- manyTill anyChar (char '\'')
  return $ RuleMsg $ Just $ Msg $ pack msg

parseTransform :: Parser Part
parseTransform = do
  try (string "t:")
  transform <- many letter
  case transform of
    "compressWhitespace" -> return $ RuleTransform CompressWhitespace
    "lowercase"          -> return $ RuleTransform Lowercase
    "urlDecode"          -> return $ RuleTransform UrlDecode
    "base64Decode"       -> return $ RuleTransform Base64Decode
    _                    -> fail "Transform not recognized"

   
parseChain :: Parser Part
parseChain = do
  try (string "chain")
  return $ RuleChain True

parsePhase :: Parser Part
parsePhase = do
  try (string "phase:")
  i <- digit
  case i of
    '0' -> return $ RulePhase $ Just 0
    '1' -> return $ RulePhase $ Just 1
    '2' -> return $ RulePhase $ Just 2
    _ -> fail "Invalid phase: must be 0, 1, or 2"

msgPart :: Parser Part
msgPart = choice 
  [ parseId
  , parseAction
  , parseMsg
  , parseTransform
  , parseChain
  , parsePhase
  ]

msgParts = msgPart `sepBy` char ','

parseRule :: Parser Rule
parseRule = do
  string "SecRule"
  space
  vars' <- parseVariables
  space
  char '"'
  (op, arg) <- opString
  space
  r <- return emptyRule 
    { operator = op
    , argument = arg
    , vars = vars'
    }
  char '"'
  parts <- msgParts
  char '"'
  return $ foldr updateRule r parts

parseArgument :: Parser Text
parseArgument = pack <$> manyTill anyChar (try $ string "\"")

testRule =
  "SecRule REQUEST_URI \"@rx /*\" \"id:100057,msg:'hello!',chain\""

runTest :: IO ()
runTest = case parse parseRule "" testRule of
  Left err -> print err >> fail "parse error"
  Right rule -> putStrLn $ unpack $ toConf rule

