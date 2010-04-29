-module(bcrypt_tests).
-include_lib("eunit/include/eunit.hrl").

simple_test_() ->
  {timeout, 1000, %% since bcrypt can take long, this is to avoid eunit timeout
   fun() -> 
     Hash = bcrypt:hashpw("foo", bcrypt:gen_salt()),
     ?assert(Hash =:= bcrypt:hashpw("foo", Hash)),
     ?assertNot(Hash =:= bcrypt:hashpw("bar", Hash))
   end}.