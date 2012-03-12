%% Copyright (c) 2011 Hunter Morris
%% Distributed under the MIT license; see LICENSE for details.
-module(bcrypt_nif_worker).
-author('Hunter Morris <huntermorris@gmail.com>').

-behaviour(gen_server).

-export([start_link/0]).
-export([gen_salt/0, gen_salt/1]).
-export([hashpw/2]).
-export([create_ctx/0]).

%% gen_server
-export([init/1, code_change/3, terminate/2,
         handle_call/3, handle_cast/2, handle_info/2]).

-record(state, {default_log_rounds}).

start_link() -> gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

gen_salt() -> gen_server:call(?MODULE, gen_salt, infinity).
gen_salt(Rounds) ->
    gen_server:call(?MODULE, {gen_salt, Rounds}, infinity).
hashpw(Password, Salt) ->
    gen_server:call(?MODULE, {hashpw, Password, Salt}, infinity).
create_ctx() ->
    gen_server:call(?MODULE, create_ctx, infinity).

init([]) ->
    {ok, Default} = application:get_env(bcrypt, default_log_rounds),
    {ok, #state{default_log_rounds = Default}}.

terminate(shutdown, _) -> ok.

handle_call(gen_salt, _From, #state{default_log_rounds = R} = State) ->
    {reply, {ok, bcrypt_nif:gen_salt(R)}, State};
handle_call({gen_salt, R}, _From, State) ->
    {reply, {ok, bcrypt_nif:gen_salt(R)}, State};
handle_call({hashpw, Password, Salt}, _From, State) ->
    {reply, {ok, bcrypt_nif:hashpw(Password, Salt)}, State};
handle_call(create_ctx, _From, State) ->
    {reply, {ok, bcrypt_nif:create_ctx()}, State};
handle_call(Msg, _, _) -> exit({unknown_call, Msg}).
handle_cast(Msg, _) -> exit({unknown_cast, Msg}).
handle_info(Msg, _) -> exit({unknown_info, Msg}).
code_change(_OldVsn, State, _Extra) -> {ok, State}.
