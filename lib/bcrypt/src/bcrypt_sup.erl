%% @author Hunter Morris <huntermorris@gmail.com>
%% @copyright 2009 Hunter Morris
%%
%% @doc Bcrypt supervisor
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
-module(bcrypt_sup).
-author('Hunter Morris <huntermorris@gmail.com>').

-behaviour(supervisor).

%% External
-export([start_link/1]).

%% supervisor cb
-export([init/1]).

start_link(Args) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, Args).

init(_Args) ->
    Bcrypt =
        {bcrypt, {bcrypt, start_link, []},
         permanent, 2000, worker, [bcrypt]},

    {ok,{{one_for_one, 15, 60}, [Bcrypt]}}.
