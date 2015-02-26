-module(permiso_mem).
-behaviour(permiso).

-export([new/1]).

-ignore_xref([new/1]).

-export([user_list/1, user_get/2, user_add/2, user_delete/2, user_grant/3,
         user_revoke/3, user_passwd/3, user_join/3, user_leave/3, user_auth/3,
         user_allowed/4, user_context/2,

         group_list/1, group_get/2, group_add/2, group_delete/2, group_grant/3,
         group_revoke/3,
        
         clear/1]).

-ignore_xref([user_list/1, user_get/2, user_add/2, user_delete/2, user_grant/3,
              user_revoke/3, user_passwd/3, user_join/3, user_leave/3,
              user_auth/3, user_allowed/3,

              group_list/1, group_get/2, group_add/2, group_delete/2,
              group_grant/3, group_revoke/3,
             
              clear/1]).

-record(state, {users, groups}).

-include("permiso.hrl").

-type new_opts() :: [].
-type state() :: #state{}.
-type grant() :: #grant{}.
-type group() :: #group{}.
-type bucket() :: binary().
-type key() :: binary().
-type resource() :: bucket() | {bucket(), key()}.
-type perm() :: string().
-type perms() :: [perm()].
-type user() :: #user{}.
-type groupname() :: binary().
-type groupnames() :: [groupnames()].
-type username() :: binary().
-type usernames() :: [username()].
-type password() :: binary().

-type user_context() :: user().

-spec new(new_opts()) -> state().
new(Opts) -> 
    Users = ets:new(users, []),
    Groups = ets:new(groups, []),
    parse_opts(Opts, #state{users=Users, groups=Groups}).

%% User Functions

-spec user_list(state()) -> {ok, [usernames()]}.
user_list(#state{users=Table}) ->
    Usernames = ets:foldl(fun ({Username, _}, AccIn) -> [Username|AccIn] end,
                          [], Table),
    {ok, Usernames}.

-spec user_get(state(), username()) -> {ok, user()} | {error, notfound}.
user_get(#state{users=Users}, Username) ->
    case ets:lookup(Users, Username) of
        [{Username, UserData}] -> {ok, UserData};
        [] -> {error, notfound}
    end.

-spec user_add(state(), user()) -> {ok, state()} | {error, duplicate} | {error, term()}.
user_add(State=#state{users=Users}, User=#user{username=Username}) ->
    case user_get(State, Username) of
        {ok, _ExistingUser} -> {error, duplicate};
        {error, notfound} ->
            ets:insert(Users, {Username, User}),
            {ok, State}
    end.

-spec user_delete(state(), username()) -> {ok, state()}.
user_delete(State, Username) ->
    with_existing_user(State, Username,
                       fun (Users, _ExistingUser) ->
                               ets:delete(Users, Username),
                               {ok, State}
                       end).

-spec user_grant(state(), username(), grant()) -> {ok, state()}.
user_grant(State=#state{}, Username, Grant=#grant{}) ->
    with_existing_user(State, Username,
                       fun (Users, ExistingUser=#user{grants=CurrentGrants}) ->
                               NewGrants = put_grant(Grant, CurrentGrants),
                               NewUser = ExistingUser#user{grants=NewGrants},
                               upsert_user(Users, NewUser),
                               {ok, State}
                       end).

-spec user_revoke(state(), username(), grant()) -> {ok, state()}.
user_revoke(State=#state{}, Username, Grant=#grant{}) ->
    with_existing_user(State, Username,
                       fun (Users, ExistingUser=#user{grants=CurrentGrants}) ->
                               NewGrants = del_grant(Grant, CurrentGrants),
                               NewUser = ExistingUser#user{grants=NewGrants},
                               upsert_user(Users, NewUser),
                               {ok, State}
                       end).

-spec user_passwd(state(), username(), password()) -> {ok, state()}.
user_passwd(State, Username, Password) ->
    with_existing_user(State, Username,
                       fun (Users, ExistingUser) ->
                               NewUser = ExistingUser#user{password=Password},
                               upsert_user(Users, NewUser),
                               {ok, State}
                       end).

-spec user_join(state(), username(), groupname()) -> {ok, state()} | {error, notfound}.
user_join(State, Username, Groupname) ->
    Fun = fun (Users, ExistingUser=#user{groups=CurrentGroups},
              Groups, ExistingGroup=#group{users=GroupUsers}) ->

                  NewUserGroups = [Groupname|lists:delete(Groupname, CurrentGroups)],
                  NewUser = ExistingUser#user{groups=NewUserGroups},
                  upsert_user(Users, NewUser),

                  NewUsers = [Username|lists:delete(Username, GroupUsers)],
                  NewGroup = ExistingGroup#group{users=NewUsers},
                  upsert_group(Groups, NewGroup),
                  {ok, State}
          end,
    with_user_and_group(State, Username, Groupname, Fun).

-spec user_leave(state(), username(), groupname()) -> {ok, state()} | {error, notfound}.
user_leave(State, Username, Groupname) ->
    Fun = fun (Users, ExistingUser=#user{groups=CurrentGroups},
              Groups, ExistingGroup=#group{users=GroupUsers}) ->

                  NewUserGroups = lists:delete(Groupname, CurrentGroups),
                  NewUser = ExistingUser#user{groups=NewUserGroups},
                  upsert_user(Users, NewUser),

                  NewUsers = lists:delete(Username, GroupUsers),
                  NewGroup = ExistingGroup#group{users=NewUsers},
                  upsert_group(Groups, NewGroup),
                  {ok, State}
          end,
    with_user_and_group(State, Username, Groupname, Fun).

-spec user_auth(state(), username(), password()) -> ok | {error, term()}.
user_auth(State, Username, Password) ->
    with_existing_user(State, Username,
                       fun (_Users, #user{password=UPassword}) ->
                               if UPassword =:= Password -> ok;
                                  true -> {error, unauthorized}
                               end
                       end).

-spec user_allowed(state(), username() | user_context(), resource(), perms()) -> boolean().
user_allowed(State=#state{}, User=#user{}, Resource, Permissions) ->
    check_user_allowed(State, User, Resource, Permissions);
user_allowed(State=#state{}, Username, Resource, Permissions) ->
    WithUser = fun (_Users, User) ->
                       check_user_allowed(State, User, Resource, Permissions)
               end,
    with_existing_user(State, Username, WithUser).

-spec user_context(state(), username()) -> {ok, user_context()} | {error, notfound}.
user_context(State, Username) ->
    user_get(State, Username).

-spec clear(state()) -> {ok, state()}.
clear(State=#state{users=Users, groups=Groups}) ->
    ets:delete_all_objects(Users),
    ets:delete_all_objects(Groups),
    {ok, State}.

%% Group Functions

-spec group_list(state()) -> {ok, groupnames()}.
group_list(#state{groups=Table}) ->
    {ok, ets:tab2list(Table)}.

-spec group_get(state(), groupname()) -> {ok, group()} | {error, notfound}.
group_get(#state{groups=Groups}, Groupname) ->
    case ets:lookup(Groups, Groupname) of
        [{Groupname, GroupData}] -> {ok, GroupData};
        [] -> {error, notfound}
    end.

-spec group_add(state(), group()) -> {ok, state()} | {error, duplicate}.
group_add(State=#state{groups=Groups}, Group=#group{name=Groupname}) ->
    case ets:lookup(Groups, Groupname) of
        [{Groupname, _ExistingGroup}] -> {error, duplicate};
        [] ->
            upsert_group(Groups, Group),
            {ok, State}
    end.

-spec group_delete(state(), groupname()) -> {ok, state()}.
group_delete(State, Groupname) ->
    with_existing_group(State, Groupname, fun (Groups, _ExistingGroup) ->
                                                  ets:delete(Groups, Groupname),
                                                  {ok, State}
                                          end).

-spec group_grant(state(), groupname(), grant()) -> {ok, state()}.
group_grant(State, Groupname, Grant=#grant{}) ->
    WithGroup = fun (Groups, ExistingGroup=#group{grants=Grants}) ->
                        NewGrants = [Grant|Grants],
                        NewGroup = ExistingGroup#group{grants=NewGrants},
                        upsert_group(Groups, NewGroup),
                        {ok, State}
                end,
    with_existing_group(State, Groupname, WithGroup).

-spec group_revoke(state(), groupname(), grant()) -> {ok, state()}.
group_revoke(State, Groupname, Grant) ->
    WithGroup = fun (Groups, ExistingGroup=#group{grants=Grants}) ->
                        NewGrants = lists:delete(Grant, Grants),
                        NewGroup = ExistingGroup#group{grants=NewGrants},
                        upsert_group(Groups, NewGroup),
                        {ok, State}
                end,
    with_existing_group(State, Groupname, WithGroup).

%% Internal

parse_opts([], State) -> State.
%parse_opts([{key, Val}|Opts], State) -> State;
%    parse_opts(Opts, State#state{key=Val}).

with_existing_user(State=#state{users=Users}, Username, Fun) ->
    case user_get(State, Username) of
        {ok, ExistingUser} ->
            Fun(Users, ExistingUser);
        {error, notfound}=Reason -> Reason
    end.

with_existing_group(State=#state{groups=Groups}, Groupname, Fun) ->
    case group_get(State, Groupname) of
        {ok, ExistingGroup} ->
            Fun(Groups, ExistingGroup);
        {error, notfound}=Reason -> Reason
    end.

with_user_and_group(State, Username, Groupname, Fun) ->
    WithUser = fun (Users, ExistingUser) ->
                       WithGroup = fun (Groups, ExistingGroup) ->
                                    Fun(Users, ExistingUser, Groups,
                                        ExistingGroup)
                                   end,
                       R = with_existing_group(State, Groupname, WithGroup),
                       notfound_to(R, group_notfound)
               end,
    R = with_existing_user(State, Username, WithUser),
    notfound_to(R, user_notfound).

upsert_user(Users, User=#user{username=Username}) ->
    Obj = {Username, User},
    ets:insert(Users, Obj).

upsert_group(Groups, Group=#group{name=Groupname}) ->
    Obj = {Groupname, Group},
    ets:insert(Groups, Obj).

notfound_to({error, notfound}, NewReason) ->
    {error, NewReason};
notfound_to(Other, _NewReason) ->
    Other.

match_groups_permissions(_State,_GroupNames, _Resource, []) ->
    true;
match_groups_permissions(_State, [], _Resource, _Permissions) ->
    false;

match_groups_permissions(State, [GroupName|GroupNames], Resource, Permissions) ->
    case group_get(State, GroupName) of
        {ok, #group{grants=Grants}} ->
            NewPermissions = permiso:match_permissions(Grants, Resource, Permissions),
            match_groups_permissions(State, GroupNames, Resource, NewPermissions);
        {error, notfound} ->
            match_groups_permissions(State, GroupNames, Resource, Permissions)
    end.

unique_list(L1, L2) ->
    S1 = sets:from_list(L1),
    S2 = sets:from_list(L2),
    S3 = sets:union([S1, S2]),
    sets:to_list(S3).

substract(L1, from, L2) ->
    S1 = sets:from_list(L1),
    S2 = sets:from_list(L2),
    S3 = sets:subtract(S2, S1),
    sets:to_list(S3).

put_grant(Grant=#grant{resource=Resource, permissions=Perms}, Grants) ->
    {NewGrants, NewPerms} = case proplists:get_value(Resource, Grants) of
                                undefined -> {Grants, Perms};
                                #grant{permissions=CurrentPerms} ->
                                    Grants1 = proplists:delete(Resource, Grants),
                                    Perms1 = unique_list(CurrentPerms, Perms),
                                    {Grants1, Perms1}
                            end,

    NewGrant = Grant#grant{permissions=NewPerms},
    [{Resource, NewGrant}|NewGrants].

del_grant(Grant=#grant{resource=Resource, permissions=Perms}, Grants) ->
    {NewGrants, NewPerms} = case proplists:get_value(Resource, Grants) of
                                undefined -> {Grants, Perms};
                                #grant{permissions=CurrentPerms} ->
                                    Grants1 = proplists:delete(Resource, Grants),
                                    Perms1 = substract(CurrentPerms, from, Perms),
                                    {Grants1, Perms1}
                            end,

    if length(NewPerms) == 0 ->
           NewGrants;
       true ->
           NewGrant = Grant#grant{permissions=NewPerms},
           [{Resource, NewGrant}|NewGrants]
    end.

check_user_allowed(State, #user{grants=Grants, groups=Groups}, Resource, Permissions) ->
    case permiso:match_permissions(Grants, Resource, Permissions) of
        [] -> true;
        Remaining ->
            match_groups_permissions(State, Groups, Resource, Remaining)
    end.
