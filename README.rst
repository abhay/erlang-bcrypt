erlang-bcrypt
=============

erlang-bcrypt is a wrapper around the OpenBSD Blowfish password hashing
algorithm, as described in `"A Future-Adaptable Password Scheme"`_ by Niels
Provos and David Mazieres.

.. _"A Future-Adaptable Password Scheme":
   http://www.openbsd.org/papers/bcrypt-paper.ps

Basic build instructions
------------------------

1. Bootstrap ``erlang-bcrypt``::

        ./bootstrap

2. Configure the project, specifying ``--with-erlang`` and
   ``--with-erl-interface``::

        ./configure \
            --with-erlang=R12B-4/lib/erlang/usr/include \
            --with-erl-interface=R12B-4/lib/erlang/lib/erl_interface-3.5.8

3. Build it

        make

4. Run it

        erl -pa lib/bcrypt/ebin

Basic usage instructions
------------------------

1. Start the `gen_server` which manages the port::

        1> ok = crypto:start(),
        1> {ok, Pid} = bcrypt:start_link("lib/bcrypt/bcrypt").
        {ok, <0.39.0>}

2. Hash a password using a salt with the default number of rounds::

        2> bcrypt:hashpw(Pid, "foo", bcrypt:gen_salt(Pid)).
        "$2...000"

Authors: Hunter Morris (http://skarab.com/)
