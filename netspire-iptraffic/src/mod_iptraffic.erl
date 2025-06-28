-module(mod_iptraffic).

-behaviour(gen_module).
-behaviour(gen_server).

%% API
-export([start_link/1,
         access_request/3,
         init_session/4,
         accounting_request/4,
         get_option/2]).

%% gen_module callbacks
-export([start/1, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("netspire.hrl").
-include("radius/radius.hrl").
-include("netflow/netflow_v5.hrl").
-include("netflow/netflow_v9.hrl").
-include("iptraffic.hrl").

start(Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    iptraffic_sup:start(Options).

start_link(Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Options], []).

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    iptraffic_sup:stop().

-spec init(list()) -> {ok, no_state}.
init([Options]) ->
    process_flag(trap_exit, true),
    TrafficClasses = proplists:get_value(traffic_classes, Options, []),
    ok = tclass:load(TrafficClasses),
    ok = init_db_backend(Options),
    {ok, no_state}.

-spec init_db_backend(term()) -> ok | database_backend_not_defined.
init_db_backend(Options) ->
    case application:get_env(netspire, database_backend) of
	{ok, Name} ->
	    Module = lists:concat([?MODULE, "_", Name]),
	    gen_module:start_module(list_to_atom(Module), []),
	    netspire_netflow:add_packet_handler(iptraffic_session, []),
	    netspire_hooks:add(radius_access_request, ?MODULE, access_request),
	    netspire_hooks:add(radius_access_accept, ?MODULE, init_session),
	    netspire_hooks:add(radius_acct_request, ?MODULE, accounting_request),
	    Timeout = proplists:get_value(session_timeout, Options, 60) * 1000,
	    timer:send_interval(Timeout, expire_all),
	    ok;
	undefined ->
	    ?ERROR_MSG("Cannot determine database backend~n", []),
	    database_backend_not_defined
    end.

access_request(_Value, Request, Client) ->
    case radius_util:verify_requirements(Request, ?MODULE) of
        false ->
            {stop, Request};
        true ->
            UserName = radius:attribute_value("User-Name", Request),
            case mod_iptraffic_pgsql:fetch_account(UserName) of
                {ok, Data} ->
		    {Password, Replies, Context} = Data,
		    case perform_authorization(Replies, Context, Client) of
			{accept, NewReplies} ->
			    Response = {auth, {Password, Replies ++ NewReplies, Context}},
			    {stop, Response};
			{reject, Reason} ->
			    ?INFO_MSG("User ~s is denied access for reason (~p), nas (~p)~n",
				      [UserName, Reason, Client#nas_spec.name]),
			    {stop, undefined}
		    end;
                undefined ->
		    ?INFO_MSG("User ~s is denied access for unknown reason, nas (~p)~n",
			      [UserName, Client#nas_spec.name]),
                    {stop, undefined}
            end
    end.

-spec perform_authorization(list(), dict(), term()) -> {accept, list()} | {reject, term()}.
perform_authorization(Replies, Context, Client) ->
    case proplists:get_all_values("Netspire-Allowed-NAS", Replies) of
	[] ->
	    algo_authorization(Context);
	NASes ->
	    case lists:member(atom_to_list(Client#nas_spec.name), NASes) of
		true ->
		    algo_authorization(Context);
		false ->
		    {reject, not_allowed_nas}
	    end
    end.

-spec algo_authorization(term()) -> {accept, list()} | {reject, term()}.
algo_authorization(Context) ->
    PlanData = dict:fetch(plan_data, Context),
    AdminAccess = case dict:find(<<"ADMIN_ACCESS">>, PlanData) of
		      {ok, V} ->
			  V;
		      error ->
			  <<"DEFAULT">>
		  end,
    {M, F} = dict:fetch(auth_algo, Context),
    {Decision, NewReplies} = M:F(dict:fetch(currency, Context),
				 dict:fetch(balance, Context), PlanData),
    case AdminAccess of
	<<"FORCE_ACCEPT">> ->
	    {accept, NewReplies};
	<<"FORCE_REJECT">> ->
	    {reject, force_reject};
	<<"DEFAULT">> ->
	    {Decision, NewReplies}
    end.

init_session(Response, Request, Extra, Client) ->
    UserName = radius:attribute_value("User-Name", Request),
    case netspire_hooks:run_fold(ippool_lease_ip, Response, []) of
        NewResponse when is_record(NewResponse, radius_packet) ->
            case iptraffic_sup:init_session(UserName) of
                {ok, Pid} ->
                    prepare_session(Pid, UserName, Extra, NewResponse, Client);
                {error, Reason} ->
                    ?ERROR_MSG("Can not initialize session for user ~s due to ~p~n", [UserName, Reason]),
                    netspire_hooks:run_fold(ippool_release_ip, NewResponse, []),
                    {reject, []}
            end;
        _ ->
            {reject, []}
    end.

prepare_session(Pid, UserName, Extra, Response, Client) ->
    case iptraffic_session:prepare(Pid, UserName, Extra, Response, Client) of
        ok ->
            Response;
        {error, Reason} ->
            ?ERROR_MSG("Can not prepare session for user ~s due to ~p~n", [UserName, Reason]),
            {reject, []}
    end.

accounting_request(_Response, ?ACCT_START, Request, _Client) ->
    UserName = radius:attribute_value("User-Name", Request),
    IP = radius:attribute_value("Framed-IP-Address", Request),
    SID = radius:attribute_value("Acct-Session-Id", Request),
    CID = radius:attribute_value("Calling-Station-Id", Request),
    ?INFO_MSG("ACCT-START received: UserName=~s, IP=~s, SID=~s, MAC=~s~n",
              [UserName, inet_parse:ntoa(IP), SID, CID]),
    case iptraffic_session:start(UserName, IP, SID, CID) of
        ok ->
            ?INFO_MSG("Session started for Username: ~s, IP: ~s, SID: ~s, MAC: ~s~n",
		      [UserName, inet_parse:ntoa(IP), SID, CID]),
            #radius_packet{code = ?ACCT_RESPONSE};
        _Error ->
            noreply
    end;
accounting_request(_Response, ?INTERIM_UPDATE, Request, _Client) ->
    SID = radius:attribute_value("Acct-Session-Id", Request),
    case iptraffic_session:interim(SID) of
        ok ->
            netspire_hooks:run(ippool_renew_ip, [Request]),
            #radius_packet{code = ?ACCT_RESPONSE};
        _Error ->
            noreply
    end;
accounting_request(_Response, ?ACCT_STOP, Request, _Client) ->
    SID = radius:attribute_value("Acct-Session-Id", Request),
    case iptraffic_session:stop(SID) of
        {ok, State} ->
            Timeout = gen_module:get_option(?MODULE, delay_stop, 5),
            {ok, _} = timer:apply_after(Timeout * 1000, iptraffic_sup, delete_session, [State, Request]),
            #radius_packet{code = ?ACCT_RESPONSE};
        _Error ->
            noreply
    end;
accounting_request(_Response, _, _, _) ->
    noreply.

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(expire_all, State) ->
    Now = netspire_util:timestamp(),
    Guard = fun(S) -> S#ipt_session.expires_at =< Now end,
    Fun = fun(S) ->
        iptraffic_session:expire(S#ipt_session.sid),
        supervisor:delete_child(iptraffic_sup, {session, S#ipt_session.username})
    end,
    traverse_all(Guard, Fun),
    {noreply, State};
handle_info(_Request, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, _State) ->
    netspire_netflow:delete_packet_handler(iptraffic_session),
    netspire_hooks:delete_all(?MODULE).

traverse_all(Guard, Fun) ->
    Key = mnesia:dirty_first(ipt_session),
    traverse_all(Key, Guard, Fun).
traverse_all('$end_of_table', _, _) ->
    ok;
traverse_all(Key, Guard, Fun) ->
    case mnesia:dirty_read(ipt_session, Key) of
        [State] ->
            Next = mnesia:dirty_next(ipt_session, Key),
            case Guard(State) of
                true ->
                    Fun(State),
                    traverse_all(Next, Guard, Fun);
                _ ->
                    traverse_all(Next, Guard, Fun)
            end;
        [] ->
            traverse_all(Guard, Fun)
    end.

get_option(Name, Default) ->
    gen_module:get_option(?MODULE, Name, Default).
