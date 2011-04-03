-module(bcrypt_tests).
-include_lib("eunit/include/eunit.hrl").

simple_test_() ->
  {timeout, 1000, %% since bcrypt can take long, this is to avoid eunit timeout
   fun() ->
           application:start(crypto),
           application:start(bcrypt),
           {ok, Salt} = bcrypt:gen_salt(),
           {ok, Hash} = bcrypt:hashpw("foo", Salt),
           ?assert({ok, Hash} =:= bcrypt:hashpw("foo", Hash)),
           ?assertNot({ok, Hash} =:= bcrypt:hashpw("bar", Hash))
   end}.
