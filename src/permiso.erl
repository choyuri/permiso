-module(permiso).

-export([match_permissions/3]).

-export([behaviour_info/1]).

-ignore_xref([behaviour_info/1]).

-include("permiso.hrl").

%% API

behaviour_info(callbacks) ->
    [{user_list, 1},
     {user_get, 2},
     {user_add, 2},
     {user_delete, 2},
     {user_grant, 3},
     {user_revoke, 3},
     {user_passwd, 3},
     {user_join, 3},
     {user_leave, 3},
     {user_auth, 3},

     {user_allowed, 4},

     %{user_set_resource, 4},
     %{user_get_resource, 3},
     %{user_claim_resource, 4},
     %{user_free_resource, 4},
     %{user_resource_stat, 2},

     {group_list, 1},
     {group_get, 2},
     {group_add, 2},
     {group_delete, 2},
     {group_grant, 3},
     {group_revoke, 3}];

behaviour_info(_Other) ->
    undefined.

match_permissions(_Grants, _Resource, []=Permissions) ->
    Permissions;
match_permissions([], _Resource, Permissions) ->
    Permissions;
match_permissions([#grant{resource=Resource, permissions=GPerms}|Grants],
                  Resource, Permissions) ->
    NewPermissions = lists:subtract(Permissions, GPerms),
    match_permissions(Grants, Resource, NewPermissions);
match_permissions([_Grant|Grants], Resource, Permissions) ->
    match_permissions(Grants, Resource, Permissions).

%% Internals

