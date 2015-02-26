-module(permiso_rcore).
-behaviour(permiso).

-export([new/1]).

-ignore_xref([new/1]).

-export([user_list/1, user_get/2, user_add/2, user_delete/2, user_grant/3,
         user_revoke/3, user_passwd/3, user_join/3, user_leave/3, user_auth/3,
         user_allowed/4, user_context/2,

         group_list/1, group_get/2, group_add/2, group_delete/2, group_grant/3,
         group_revoke/3]).

-ignore_xref([user_list/1, user_get/2, user_add/2, user_delete/2, user_grant/3,
              user_revoke/3, user_passwd/3, user_join/3, user_leave/3,
              user_auth/3, user_allowed/3,

              group_list/1, group_get/2, group_add/2, group_delete/2,
              group_grant/3, group_revoke/3]).

-record(state, {}).

-include("permiso.hrl").

% NOTE '$deleted' is copied here since the other is a constant on
% riak_core_security ?TOMBSTONE
-define(TOMBSTONE, '$deleted').

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
% it's context from riak_core_security
-type user_context() :: {ctx, term()}.

-spec new(new_opts()) -> {ok, state()}.
new(_Opts) ->
    {ok, #state{}}.

%% User Functions

-spec user_list(state()) -> {ok, [usernames()]}.
user_list(#state{}) ->
    Usernames = fold_users(fun({_Username, [?TOMBSTONE]}, Acc) ->
                                   Acc;
                              ({Username, _Options}, Acc) ->
                                   [Username|Acc]
                           end),
    {ok, Usernames}.

-spec user_get(state(), username()) -> {ok, user()} | {error, notfound}.
user_get(#state{}, Username) ->
    case user_info(Username) of
        {found, {FGroups}} ->
            Grants = user_grants(Username),
            User = #user{username=Username, grants=Grants, groups=FGroups},
            {ok, User};
        {notfound, _Acc0} ->
            {error, notfound}
    end.

%% XXX ignores grants and extra
-spec user_add(state(), user()) -> {ok, state()} | {error, duplicate} | {error, term()}.
user_add(State=#state{}, #user{username=Username, password=Password,
                               groups=Groups}) ->
    case create_user(Username, Password, Groups) of
        ok -> {ok, State};
        {error, role_exists} -> {error, duplicate};
        Other -> Other
    end.

-spec user_delete(state(), string()) -> {ok, state()}.
user_delete(State=#state{}, Username) ->
    wrap_ok(State, riak_core_security:del_user(Username)).

-spec user_grant(state(), username(), grant()) -> {ok, state()}.
user_grant(State=#state{}, Username,
           #grant{resource={Bucket, Key}, permissions=Perms}) ->
    grant(Username, Bucket, Key, Perms),
    {ok, State}.

-spec user_revoke(state(), username(), grant()) -> {ok, state()}.
user_revoke(State=#state{}, Username,
           #grant{resource={Bucket, Key}, permissions=Perms}) ->
    revoke(Username, Bucket, Key, Perms),
    {ok, State}.

-spec user_passwd(state(), string(), password()) -> {ok, state()} | {error, term()}.
user_passwd(State=#state{}, Username, Password) ->
    wrap_ok(State,
            riak_core_security:alter_user(Username, [{"password", Password}])).


-spec user_join(state(), username(), groupname()) -> {ok, state()} | {error, notfound}.
user_join(State=#state{}, Username, Groupname) ->
    case user_info(Username) of
        {found, {Groups}} ->
            IsMember = lists:member(Groupname, Groups),
            if IsMember -> {ok, State};
               true ->
                   NewGroups = [Groupname|Groups],
                   wrap_ok(State, riak_core_security:alter_user(Username,
                                                                [{"groups", NewGroups}]))
            end;
        {notfound, _Acc0} ->
            {error, notfound}
    end.

-spec user_leave(state(), username(), groupname()) -> {ok, state()} | {error, notfound}.
user_leave(State=#state{}, Username, Groupname) ->
    case user_info(Username) of
        {found, {Groups}} ->
            IsMember = lists:member(Groupname, Groups),
            if IsMember ->
                   NewGroups = lists:delete(Groupname, Groups),
                   wrap_ok(State, riak_core_security:alter_user(Username,
                                                                [{"groups", NewGroups}]));
               true ->
                   {ok, State}
            end;
        {notfound, _Acc0} ->
            {error, notfound}
    end.

-spec user_auth(state(), username(), password()) -> {ok, user_context()} | {error, term()}.
user_auth(#state{}, Username, Password) ->
    Source = [{ip, {127, 0, 0, 1}}],
    case riak_core_security:authenticate(Username, Password, Source) of
        {ok, Ctx} -> {ok, {ctx, Ctx}};
        {error, _Reason}=Error -> Error
    end.

-spec user_allowed(state(), username() | user_context(), resource(), perms()) -> boolean().
user_allowed(#state{}, {ctx, Ctx}, Resource, Perms) ->
    check_ctx_authorized(Perms, Resource, Ctx);
user_allowed(#state{}, Username, Resource, Perms) ->
    case get_security_context(Username) of
        {ok, Ctx} ->
            check_ctx_authorized(Perms, Resource, Ctx);
        {error, notfound} -> false
    end.

-spec user_context(state(), username()) -> {ok, user_context()} | {error, notfound}.
user_context(_State, Username) ->
    case get_security_context(Username) of
        {ok, Ctx} -> {ok, {ctx, Ctx}};
        Other -> Other
    end.

%% _Group Functions

-spec group_list(state()) -> {ok, groupnames()}.
group_list(#state{}) ->
    Groups = fold_groups(fun ({Groupname, _Perms}, AccIn) ->
                                 [Groupname|AccIn]
                         end),
    {ok, Groups}.

-spec group_get(state(), groupname()) -> {ok, group()} | {error, notfound}.
group_get(#state{}, Groupname) ->
    Acc0 = #group{name=Groupname},
    case fold_group(fun (_, AccIn) -> AccIn end, Groupname, Acc0) of
        {found, AccOut} ->
            Users = group_users(Groupname),
            Grants = group_grants(Groupname),
            {ok, AccOut#group{grants=Grants, users=Users}};
        {notfound, _} ->
            {error, notfound}
    end.

-spec group_add(state(), group()) -> {ok, state()}.
group_add(State=#state{}, #group{name=Groupname}) ->
    wrap_ok(State, riak_core_security:add_group(Groupname, [])).

-spec group_delete(state(), string()) -> {ok, state()}.
group_delete(State=#state{}, Groupname) ->
    wrap_ok(State, riak_core_security:del_group(Groupname)).

-spec group_grant(state(), groupname(), grant()) -> {ok, state()}.
group_grant(State, Groupname,
            #grant{resource={Bucket, Key}, permissions=Perms}) ->
    grant(Groupname, Bucket, Key, Perms),
    {ok, State}.

-spec group_revoke(state(), groupname(), grant()) -> {ok, state()}.
group_revoke(State, Groupname,
            #grant{resource={Bucket, Key}, permissions=Perms}) ->
    revoke(Groupname, Bucket, Key, Perms),
    {ok, State}.

%% Internal

fold(Fun, Accum, Type) ->
    riak_core_metadata:fold(Fun, Accum, {<<"security">>, Type}).

fold_users(Fun) -> fold_users(Fun, []).
fold_users(Fun, Accum) -> fold(Fun, Accum, <<"users">>).

fold_groups(Fun) -> fold_groups(Fun, []).
fold_groups(Fun, Accum) -> fold(Fun, Accum, <<"groups">>).

fold_key(Fun, Key, Accum, Type) ->
    case riak_core_metadata:get({<<"security">>, Type}, Key) of
        undefined -> {notfound, Accum};
        Items -> {found, lists:foldl(Fun, Accum, Items)}
    end.

fold_user(Fun, Key, Accum) ->
    fold_key(Fun, Key, Accum, <<"users">>).

fold_group(Fun, Key, Accum) ->
    fold_key(Fun, Key, Accum, <<"groups">>).

merge_grant(Dict, Bucket, Key, Perms) ->
    SetPerms = sets:from_list(Perms),
    Fun = fun (SetExistingPerms) ->
                  sets:union(SetExistingPerms, SetPerms)
          end,
    dict:update({Bucket, Key}, Fun, SetPerms, Dict).

user_grants(Username) ->
    {context, Username, Grants, _Ts} = riak_core_security:get_context(Username),
    DPerm0 = dict:new(),
    DPerm1 = lists:foldl(fun
                    ({{Bucket, Key}, Perms}, DPermIn) ->
                        merge_grant(DPermIn, Bucket, Key, Perms);
                    ({Bucket, Perms}, DPermIn) ->
                        merge_grant(DPermIn, Bucket, any, Perms);
                    (_, Accum) ->
                        Accum
                end, DPerm0, Grants),
    dict:fold(fun (Key, Val, AccIn) ->
                      [#grant{resource=Key, permissions=sets:to_list(Val)}|AccIn]
              end, [], DPerm1).

group_grants(Groupname) ->
    Fun = fun
              ({GName, {Bucket, Key}, [Perms]}, DPermIn) when GName =:= Groupname ->
                  merge_grant(DPermIn, Bucket, Key, Perms);
              ({GName, Bucket, [Perms]}, DPermIn) when GName =:= Groupname ->
                  merge_grant(DPermIn, Bucket, any, Perms);
              (_, DPermIn) ->
                  DPermIn
          end,
    DPerm0 = dict:new(),
    DPerm1 = riak_core_metadata:fold(Fun, DPerm0,
                                     {<<"security">>, <<"groupgrants">>}),
    dict:fold(fun (Key, Val, AccIn) ->
                      [#grant{resource=Key, permissions=Val}|AccIn]
              end, [], DPerm1).

create_user(Username, Password, Groups) when is_binary(Username) ->
    create_user(binary_to_list(Username), Password, Groups);

create_user(Username, Password, Groups) when is_binary(Password) ->
    create_user(Username, binary_to_list(Password), Groups);

create_user(Username, Password, Groups) ->
    RcsGroups = lists:map(fun (Group) -> {"groups", [Group]} end, Groups),
    case riak_core_security:add_user(Username, [{"password", Password}]) of
        ok ->
            ok = riak_core_security:add_source([Username], {{127, 0, 0, 1}, 32}, password, []),
            ok = riak_core_security:alter_user(Username, RcsGroups),
            ok;
        Error ->
            Error
    end.

group_users(Groupname) ->
    fold_users(fun({Username, [Opts]}, Acc) ->
                       Groups = proplists:get_value("groups", Opts, []),
                       IsMember = lists:member(Groupname, Groups),
                       if IsMember -> [Username|Acc];
                          true -> Acc
                       end
               end).

grant(Role, Bucket, Key, Permission) when not is_list(Permission) ->
    grant(Role, Bucket, Key, [Permission]);

grant(<<"*">>, Bucket, any, Perms) ->
    riak_core_security:add_grant(all, Bucket, Perms);

grant(Role, Bucket, any, Perms) ->
    riak_core_security:add_grant([Role], Bucket, Perms);

grant(<<"*">>, Bucket, Key, Perms) ->
    riak_core_security:add_grant(all, {Bucket, Key}, Perms);

grant(Role, Bucket, Key, Perms) ->
    riak_core_security:add_grant([Role], {Bucket, Key}, Perms).

revoke(Role, Bucket, Key, Permission) when not is_list(Permission) ->
    revoke(Role, Bucket, Key, [Permission]);

revoke(<<"*">>, Bucket, any, Perms) ->
    riak_core_security:add_revoke(all, Bucket, Perms);

revoke(Role, Bucket, any, Perms) ->
    riak_core_security:add_revoke([Role], Bucket, Perms);

revoke(<<"*">>, Bucket, Key, Perms) ->
    riak_core_security:add_revoke(all, {Bucket, Key}, Perms);

revoke(Role, Bucket, Key, Perms) ->
    riak_core_security:add_revoke([Role], {Bucket, Key}, Perms).

-spec get_security_context(username()) -> {ok, user_context()} | {error, notfound}.
get_security_context(Username) ->
    % TODO: don't try catch
    % TODO: this is private
    try
        {ok, riak_core_security:get_context(Username)}
    catch error:badarg ->
        {error, notfound}
    end.

user_info(Username) ->
    IGs = sets:new(),
    Res = fold_user(fun ({"groups", Groups}, {GsIn}) ->
                            SGroups = sets:from_list(Groups),
                            GsOut = sets:union(GsIn, SGroups),
                            {GsOut};
                        (_, AccIn) -> AccIn
                    end, Username, {IGs}),
    case Res of
        {found, {OGs}} -> {found, {sets:to_list(OGs)}};
        Other -> Other
    end.

wrap_ok(State, ok) -> {ok, State};
wrap_ok(_State, Other) -> Other.

check_ctx_authorized(Perms, Resource, Ctx) ->
    RPerms = lists:map(fun (Perm) -> {Perm, Resource} end, Perms),
    case riak_core_security:check_permissions(RPerms, Ctx) of
        {true, _NewCtx} ->
            true;
        {false, _Reason, _NewCtx} ->
            false
    end.
