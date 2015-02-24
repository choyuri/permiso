-module(permiso_mem_SUITE).

-compile(export_all).

-include("permiso.hrl").

-define(U1, <<"user1">>).
-define(G1, <<"user1">>).
-define(B1, <<"bucket1">>).
-define(K1, <<"key1">>).
-define(PW1, <<"secret">>).
-define(R1, {?B1, ?K1}).
-define(PERMS1, ["perm1", "perm2"]).
-define(GRANT1, #grant{resource=?R1, permissions=?PERMS1}).

all() -> [empty_user_list, user_notfound,
         user_delete_notfound, user_grant_notfound, user_revoke_notfound,
         user_passwd_notfound, user_auth_notfound, user_join_notfound,
         user_leave_notfound, user_allowed_notfound,

         user_add_get_del_get, user_grant_get_revoke_get,

         empty_group_list,  group_notfound, group_delete_notfound,
         group_grant_notfound, group_revoke_notfound
         ].

init_per_suite(Config) -> 
    Config.

init_per_testcase(_Test, Config) ->
    Mem = permiso_mem:new([]),
    [{mem, Mem}|Config].

mem(Config) -> proplists:get_value(mem, Config).

end_per_testcase(_Test, Config) ->
    Mem = mem(Config),
    permiso_mem:clear(Mem), % XXX release resources
    ok.

%% Tests

empty_user_list(Config) ->
    Mem = mem(Config),
    {ok, []} = permiso_mem:user_list(Mem).

empty_group_list(Config) ->
    Mem = mem(Config),
    {ok, []} = permiso_mem:group_list(Mem).

user_notfound(Config) ->
    Mem = mem(Config),
    {error, notfound} = permiso_mem:user_get(Mem, ?U1).

user_delete_notfound(Config) ->
    Mem = mem(Config),
    {error, notfound} = permiso_mem:user_delete(Mem, ?U1).

user_grant_notfound(Config) ->
    Mem = mem(Config),
    {error, notfound} = permiso_mem:user_grant(Mem, ?U1, ?GRANT1).

user_revoke_notfound(Config) ->
    Mem = mem(Config),
    {error, notfound} = permiso_mem:user_revoke(Mem, ?U1, ?GRANT1).

user_passwd_notfound(Config) ->
    Mem = mem(Config),
    {error, notfound} = permiso_mem:user_passwd(Mem, ?U1, ?PW1).

user_auth_notfound(Config) ->
    Mem = mem(Config),
    {error, notfound} = permiso_mem:user_auth(Mem, ?U1, ?PW1).

user_join_notfound(Config) ->
    Mem = mem(Config),
    {error, user_notfound} = permiso_mem:user_join(Mem, ?U1, ?G1).

user_leave_notfound(Config) ->
    Mem = mem(Config),
    {error, user_notfound} = permiso_mem:user_leave(Mem, ?U1, ?G1).

user_allowed_notfound(Config) ->
    Mem = mem(Config),
    {error, notfound} = permiso_mem:user_allowed(Mem, ?U1, ?R1, ?PERMS1).

group_notfound(Config) ->
    Mem = mem(Config),
    {error, notfound} = permiso_mem:group_get(Mem, ?G1).

group_delete_notfound(Config) ->
    Mem = mem(Config),
    {error, notfound} = permiso_mem:group_delete(Mem, ?U1).

group_grant_notfound(Config) ->
    Mem = mem(Config),
    {error, notfound} = permiso_mem:group_grant(Mem, ?U1, ?GRANT1).

group_revoke_notfound(Config) ->
    Mem = mem(Config),
    {error, notfound} = permiso_mem:group_revoke(Mem, ?U1, ?GRANT1).

user_add_get_del_get(Config) ->
    Mem = mem(Config),
    User = #user{username=?U1, password=?PW1, grants=[], groups=[?G1]},
    {ok, Mem1} = permiso_mem:user_add(Mem, User),
    {ok, User} = permiso_mem:user_get(Mem1, ?U1),
    {ok, Mem2} = permiso_mem:user_delete(Mem1, ?U1),
    {error, notfound} = permiso_mem:user_get(Mem2, ?U1).

user_grant_get_revoke_get(Config) ->
    Mem = mem(Config),
    User = #user{username=?U1, password=?PW1, grants=[], groups=[?G1]},
    {ok, Mem1} = permiso_mem:user_add(Mem, User),
    {ok, User} = permiso_mem:user_get(Mem1, ?U1),
    {ok, Mem2} = permiso_mem:user_grant(Mem1, ?U1, ?GRANT1),
    User1 = User#user{grants=[{?R1, ?GRANT1}]},
    {ok, User1} = permiso_mem:user_get(Mem2, ?U1),
    {ok, Mem3} = permiso_mem:user_revoke(Mem2, ?U1, ?GRANT1),
    {ok, User2} = permiso_mem:user_get(Mem3, ?U1),
    ct:print("~p", [User]),
    ct:print("~p", [User2]),
    User = User2.
