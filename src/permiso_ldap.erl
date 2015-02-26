-module(permiso_ldap).
-behaviour(permiso).

-export([new/1]).

-ignore_xref([new/1]).

-export([user_list/1, user_get/2, user_add/2, user_delete/2, user_grant/3,
         user_revoke/3, user_passwd/3, user_join/3, user_leave/3, user_auth/3,
         user_allowed/4, user_context/2,

         resource_get/2,

         group_list/1, group_get/2, group_add/2, group_delete/2, group_grant/3,
         group_revoke/3]).

-ignore_xref([user_list/1, user_get/2, user_add/2, user_delete/2, user_grant/3,
              user_revoke/3, user_passwd/3, user_join/3, user_leave/3,
              user_auth/3, user_allowed/3,

              group_list/1, group_get/2, group_add/2, group_delete/2,
              group_grant/3, group_revoke/3]).

-record(state, {host, port, child, handler, user_base, user_created_cb}).

-include("permiso.hrl").

-type new_opts() :: [].
-type state() :: #state{}.
-type grant() :: #grant{}.
-type group() :: #group{}.
-type bucket() :: binary().
-type key() :: binary().
-type resource() :: bucket() | {bucket(), key()}.
-type resource_data() :: #resource{}.
-type perm() :: string().
-type perms() :: [perm()].
-type user() :: #user{}.
-type groupname() :: binary().
-type groupnames() :: [groupnames()].
-type username() :: binary().
-type usernames() :: [username()].
-type password() :: binary().
-type user_context() :: term().

-spec new(new_opts()) -> {ok, state()}.
new(Opts) ->
    {host, Host} = proplists:lookup(host, Opts),
    {port, Port} = proplists:lookup(port, Opts),
    {handler, Mod} = proplists:lookup(handler, Opts),
    {user_base, UserBase} = proplists:lookup(user_base, Opts),
    {user_created_cb, OnUserCreated} = proplists:lookup(user_created_cb, Opts),
    {ok, Child} = Mod:new([]),
    State = #state{host=Host, port=Port, child=Child, handler=Mod,
                   user_base=UserBase, user_created_cb=OnUserCreated},
    {ok, State}.

%% User Functions

-spec user_list(state()) -> {ok, [usernames()]}.
user_list(#state{child=Child, handler=Mod}) ->
    Mod:user_list(Child).

-spec user_get(state(), username()) -> {ok, user()} | {error, notfound}.
user_get(#state{child=Child, handler=Mod}, Username) ->
    Mod:user_get(Child, Username).

-spec user_add(state(), user()) -> {ok, state()} | {error, duplicate} | {error, term()}.
user_add(State=#state{child=Child, handler=Mod}, User=#user{}) ->
    update_child(State, Mod:user_add(Child, User)).

-spec user_delete(state(), string()) -> {ok, state()}.
user_delete(State=#state{child=Child, handler=Mod}, Username) ->
    update_child(State, Mod:user_delete(Child, Username)).

-spec user_grant(state(), username(), grant()) -> {ok, state()}.
user_grant(State=#state{child=Child, handler=Mod}, Username, Grant=#grant{}) ->
    update_child(State, Mod:user_grant(Child, Username, Grant)).

-spec user_revoke(state(), username(), grant()) -> {ok, state()}.
user_revoke(State=#state{child=Child, handler=Mod}, Username, Grant=#grant{}) ->
    update_child(State, Mod:user_revoke(Child, Username, Grant)).

-spec user_passwd(state(), string(), password()) -> {ok, state()}.
user_passwd(State=#state{child=Child, handler=Mod}, Username, Password) ->
    update_child(State, Mod:user_passwd(Child, Username, Password)).

-spec user_join(state(), username(), groupname()) -> {ok, state()} | {error, notfound}.
user_join(State=#state{child=Child, handler=Mod}, Username, Groupname) ->
    update_child(State, Mod:user_join(Child, Username, Groupname)).

-spec user_leave(state(), username(), groupname()) -> {ok, state()} | {error, notfound}.
user_leave(State=#state{child=Child, handler=Mod}, Username, Groupname) ->
    update_child(State, Mod:user_leave(Child, Username, Groupname)).

-spec user_auth(state(), username(), password()) -> {ok, user_context()} | {error, term()}.
user_auth(#state{}, _Username, "") ->
    {error, empty_password};
user_auth(#state{}, _Username, <<"">>) ->
    {error, empty_password};
user_auth(#state{child=Child, handler=Mod, host=Host, port=Port,
                 user_base=UserBase, user_created_cb=OnUserCreated},
          Username, Password) ->
    case eldap:open([Host], [{port, Port}]) of
        {ok, Pid} ->
            DN = "uid=" ++ binary_to_list(Username) ++ "," ++ UserBase,
            case eldap:simple_bind(Pid, DN, Password) of
                ok ->
                    maybe_setup_user(Mod, Child, Username, Password, OnUserCreated),
                    Mod:user_context(Child, Username);
                Other ->
                    lager:info("Error authenticating user ~p: ~p",
                               [Username, Other])
            end;
        Other ->
            lager:info("Error authenticating user on open ~p: ~p",
                       [Username, Other]),
            {error, unauthorized}
    end.

-spec user_allowed(state(), username() | user_context(), resource(), perms()) -> boolean().
user_allowed(#state{child=Child, handler=Mod}, Username, Resource, Perms) ->
    Mod:user_allowed(Child, Username, Resource, Perms).

-spec user_context(state(), username()) -> {ok, user_context()} | {error, notfound}.
user_context(#state{child=Child, handler=Mod}, Username) ->
    Mod:user_context(Child, Username).

%% Group Functions

-spec group_list(state()) -> {ok, groupnames()}.
group_list(#state{child=Child, handler=Mod}) ->
    Mod:group_list(Child).

-spec group_get(state(), groupname()) -> {ok, group()} | {error, notfound}.
group_get(#state{child=Child, handler=Mod}, Groupname) ->
    Mod:group_list(Child, Groupname).

-spec group_add(state(), group()) -> {ok, state()}.
group_add(State=#state{child=Child, handler=Mod}, Group=#group{}) ->
    update_child(State, Mod:group_add(Child, Group)).

-spec group_delete(state(), string()) -> {ok, state()}.
group_delete(State=#state{child=Child, handler=Mod}, Groupname) ->
    update_child(State, Mod:group_delete(Child, Groupname)).

-spec group_grant(state(), groupname(), grant()) -> {ok, state()}.
group_grant(State=#state{child=Child, handler=Mod}, Groupname, Grant=#grant{}) ->
    update_child(State, Mod:group_grant(Child, Groupname, Grant)).

-spec group_revoke(state(), groupname(), grant()) -> {ok, state()}.
group_revoke(State=#state{child=Child, handler=Mod}, Groupname, Grant=#grant{}) ->
    update_child(State, Mod:group_revoke(Child, Groupname, Grant)).

%% Resource Functions

-spec resource_get(state(), resource()) -> {ok, resource_data()}.
resource_get(#state{child=Child, handler=Mod}, Bucket) ->
    Mod:resource_get(Child, Bucket).

%% Internal

update_child(State, {ok, ChildState}) ->
    {ok, State#state{child=ChildState}};
update_child(_State, Other) ->
    Other.

maybe_setup_user(Mod, Child, Username, Password, OnUserCreated) ->
    case Mod:user_get(Child, Username) of
        {ok, _UserData} ->
            ok;
        {error, notfound} ->
            User = #user{username=Username, password=Password, grants=[],
                         groups=[]},
            case Mod:user_add(Child, User) of
                {ok, Child1} ->
                    OnUserCreated(Mod, Child1, User);
                 Other -> Other
            end
    end.
