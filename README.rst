erlang-bcrypt
=============

erlang-bcrypt is a wrapper around the OpenBSD Blowfish password hashing
algorithm, as described in `"A Future-Adaptable Password Scheme"`_ by Niels
Provos and David Mazieres.

.. _"A Future-Adaptable Password Scheme":
   http://www.openbsd.org/papers/bcrypt-paper.ps

Basic build instructions
------------------------

1. Build it::

        make

2. Run it::

        erl -pa ebin

Basic usage instructions
------------------------

1. Start the `sasl` and `crypto` applications::

        1> ok = application:start(sasl).
        ok
        2> ok = application:start(crypto).
        ok

2. Hash a password using a salt with the default number of rounds::

        4> Hash = bcrypt:hashpw("foo", bcrypt:gen_salt()).
        "$2...000"

3. Verify the password::

        5> Hash =:= bcrypt:hashpw("foo", Hash).
        true
        6> Hash =:= bcrypt:hashpw("bar", Hash).
        false
   
Authors: Hunter Morris (http://skarab.com/)
