%% @author Hunter Morris <huntermorris@gmail.com>
%% @copyright 2009 Hunter Morris
%%
%% @doc Wrapper around the OpenBSD Blowfish password hashing algorithm, as
%% described in "A Future-Adaptable Password Scheme" by Niels Provos and
%% David Mazieres: http://www.openbsd.org/papers/bcrypt-paper.ps
%%
%% Types:
%%  @type fname() = string() | atom() | deeplist()
%%  @type deeplist() = [char() | atom() | deeplist()]
%%  @type password() = string() | binary()
%%
%% @end
%%
%% Permission to use, copy, modify, and distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.

%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
-module(bcrypt).
-author('Hunter Morris <huntermorris@gmail.com>').

-behaviour(gen_server).

%% API
-export([start_link/0, start_link/1, stop/0]).
-export([gen_salt/0, gen_salt/1]).
-export([hashpw/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-define(CMD_SALT, 0).
-define(CMD_HASHPW, 1).
-record(state, {port}).

-define(BCRYPT_ERROR(F, D), error_logger:error_msg(F, D)).
-define(BCRYPT_WARNING(F, D), error_logger:warning_msg(F, D)).
-define(DEFAULT_LOG_ROUNDS, 12).
-define(MAX_LOG_ROUNDS(L), L < 32).
-define(MIN_LOG_ROUNDS(L), L > 3).

%%--------------------------------------------------------------------
%% @doc Start a bcrypt port using the default filename
%% @spec start_link() -> {ok, pid()}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    case application:get_env(bcrypt, bcrypt_filename) of
        {ok, Filename} ->
            start_link(Filename);
        undefined ->
            case code:priv_dir(bcrypt) of
                {error, bad_name} ->
                    {stop, bcrypt_not_found};
                Dir ->
                    start_link(Dir ++ "/bcrypt")
            end
    end.

%%--------------------------------------------------------------------
%% @doc Start a bcrypt port server
%% @spec start_link(Filename::fname()) -> {ok, pid()}
%% @end
%%--------------------------------------------------------------------
start_link(Filename) when is_list(Filename)
                          ; is_atom(Filename) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE,
                          [{filename, Filename}], []).

%%--------------------------------------------------------------------
%% @doc Stop a bcrypt port server
%% @spec stop() -> ok
%% @end
%%--------------------------------------------------------------------
stop() ->
    gen_server:call(?MODULE, stop).

%%--------------------------------------------------------------------
%% @doc Generate a salt with the default number of rounds, 12.
%% @see gen_salt/1
%% @spec gen_salt() -> string()
%% @end
%%--------------------------------------------------------------------
gen_salt() ->
    gen_salt(?DEFAULT_LOG_ROUNDS).

%%--------------------------------------------------------------------
%% @doc Generate a random text salt for use with hashpw/3. LogRounds
%% defines the complexity of the hashing, increasing the cost as
%% 2^log_rounds.
%% @spec gen_salt(integer()) -> string()
%% @end
%%--------------------------------------------------------------------
gen_salt(LogRounds) when is_integer(LogRounds),
                         ?MAX_LOG_ROUNDS(LogRounds),
                         ?MIN_LOG_ROUNDS(LogRounds) ->
    R = crypto:rand_bytes(16),
    gen_server:call(?MODULE, {encode_salt, R, LogRounds}).

%%--------------------------------------------------------------------
%% @doc Hash the specified password and the salt using the OpenBSD
%% Blowfish password hashing algorithm. Returns the hashed password.
%% @spec hashpw(Password::password(), Salt::string()) -> string()
%% @end
%%--------------------------------------------------------------------
hashpw(Password, Salt)
  when is_list(Password); is_binary(Password),
       is_list(Salt) ->
    gen_server:call(?MODULE, {hashpw, Password, Salt}, infinity).

%%====================================================================
%% gen_server callbacks
%%====================================================================
init(L) ->
    Filename = proplists:get_value(filename, L),
    case file:read_file_info(Filename) of
	{ok, _Info} ->
	    Port = open_port({spawn, Filename}, [{packet, 2}, binary, exit_status]),
	    {ok, #state{port=Port}};
	{error, Reason} ->
	    ?BCRYPT_ERROR("Can't open file ~p: ~p", [Filename, Reason]),
	    error
    end.

terminate(_Reason, #state{port=Port}) ->
    catch port_close(Port),
    ok.

handle_call({encode_salt, R, LogRounds}, From, State) ->
    Port = State#state.port,
    Data = term_to_binary({?CMD_SALT, From, {R, LogRounds}}),
    port_command(Port, Data),
    {noreply, State};
handle_call({hashpw, Password, Salt}, From, State) ->
    Port = State#state.port,
    Data = term_to_binary({?CMD_HASHPW, From, {Password, Salt}}),
    port_command(Port, Data),
    {noreply, State};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    {reply, bad_request, State}.

handle_info({Port, {data, Data}}, #state{port=Port}=State) ->
    case binary_to_term(Data) of
	{Cmd, To, Reply} when Cmd == ?CMD_SALT; Cmd == ?CMD_HASHPW ->
	    gen_server:reply(To, Reply);
	Err ->
	    ?BCRYPT_ERROR("Got invalid reply from ~p: ~p", [Port, Err])
    end,
    {noreply, State};
handle_info({Port, {exit_status, Status}}, #state{port=Port}=State) ->
    %% Rely on whomever is supervising this process to restart.
    ?BCRYPT_WARNING("Port died: ~p", [Status]),
    {stop, port_died, State};
handle_info(Msg, State) ->
    ?BCRYPT_WARNING("Got unexpected message: ~p", [Msg]),
    {noreply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
