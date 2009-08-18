%%% This is the application resource file (.app file) for the bcrypt
%%% application.
{application, bcrypt,
  [{description, "An Erlang wrapper for the OpenBSD password scheme, bcrypt."},
   {vsn, "0.2.0"},
   {modules, [bcrypt_app, bcrypt_sup, bcrypt]},
   {registered, [bcrypt]},
   {env, []},
   {applications, [kernel, stdlib, sasl, crypto]},
   {mod, {bcrypt_app, []}}
  ]
}.
