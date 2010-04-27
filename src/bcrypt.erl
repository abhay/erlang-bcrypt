%% @author Hunter Morris <huntermorris@gmail.com>
%% @copyright 2009 Hunter Morris
%%
%% @doc Wrapper around the OpenBSD Blowfish password hashing algorithm, as
%% described in "A Future-Adaptable Password Scheme" by Niels Provos and
%% David Mazieres: http://www.openbsd.org/papers/bcrypt-paper.ps
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

%% API
-export([init/0]).
-export([gen_salt/0, gen_salt/1]).
-export([hash/2, hashpw/2]).

-define(DEFAULT_LOG_ROUNDS, 12).
-define(MAX_LOG_ROUNDS(L), L < 32).
-define(MIN_LOG_ROUNDS(L), L > 3).

-on_load(init/0).

%%--------------------------------------------------------------------
%% @doc Load the bcrypt NIFs
%% @spec start() -> ok
%% @end
%%--------------------------------------------------------------------
init() ->
    erlang:load_nif("priv/bcrypt_drv", 0).

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
    encode_salt(R, LogRounds).

encode_salt(_R, _LogRounds) ->
    nif_error(?LINE).

%%--------------------------------------------------------------------
%% @doc Hash the specified password and the salt using the OpenBSD
%% Blowfish password hashing algorithm. Returns the hashed password.
%% @spec hashpw(Password::binary(), Salt::binary()) -> string()
%% @end
%%--------------------------------------------------------------------
hash(Password, Salt) when is_binary(Password), is_binary(Salt) ->
    hashpw(Password, Salt).

hashpw(_Password, _Salt) ->
    nif_error(?LINE).

nif_error(Line) ->
    exit({nif_not_loaded, module, ?MODULE, line, Line}).
