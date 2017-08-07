main :: IO ()
main = putStrLn "Test suite not yet implemented"

testRule :: Rule
testRule = Rule
  { rid = "100057"
  , vars = [ RequestUri ]
  , transforms = [ UrlDecode ]
  , msg = Msg (Just "Drop this one")
  , action = Drop
  , operator = Rx
  , argument = "/.*lulwat"
  , phase = 0
  , chain = True
  , nextRule = next
  }

next :: Rule
next = Rule
  { rid = ""
  , vars = [ RequestMethod ]
  , transforms = []
  , msg = Msg Nothing
  , action = Drop
  , operator = Streq
  , argument = "GET"
  , phase = 0
  , chain = False
  , nextRule = undefined
  }
  
three = Rule
  { rid = ""
  , vars = [ RequestMethod ]
  , transforms = []
  , msg = Msg Nothing
  , action = Drop
  , operator = Streq
  , argument = "POST"
  , phase = 0
  , chain = False
  , nextRule = undefined
  }
