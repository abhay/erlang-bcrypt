%%% This is the application resource file (.app file) for the bcrypt
%%% application.
{application, bcrypt,
  [{description, "An Erlang wrapper for the OpenBSD password scheme, bcrypt."},
   {vsn, "0.1.0"},
   {modules, [bcrypt]},
   {registered, []},
   {env, [
          {lib_dir, "/tmp"}
         ]},
   {applications, [kernel, stdlib, sasl, crypto]}
  ]
}.
