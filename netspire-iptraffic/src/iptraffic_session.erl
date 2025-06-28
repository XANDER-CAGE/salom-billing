-module(iptraffic_session).

-behaviour(gen_server).

%% API
-export([start_link/1, prepare/5, start/3, interim/1, stop/1, expire/1, handle_packet/2, list/0, list/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("netspire.hrl").
-include("netflow/netflow_v5.hrl").
-include("netflow/netflow_v9.hrl").
-include("iptraffic.hrl").
-include_lib("stdlib/include/qlc.hrl").

-import(calendar, [gregorian_seconds_to_datetime/1, time_to_seconds/1, universal_time_to_local_time/1]).

start_link(UUID) ->
    gen_server:start_link(?MODULE, [UUID], []).

prepare(Pid, UserName, Extra, Response, Client) ->
    gen_server:call(Pid, {prepare, UserName, Extra, Response, Client}).

start(UserName, IP, SID) ->
    case fetch({new, UserName}) of
        {ok, State} ->
            gen_server:call(State#ipt_session.pid, {start, IP, SID});
        Error ->
            Error
    end.

interim(SID) ->
    case fetch(SID) of
        {ok, State} ->
            gen_server:call(State#ipt_session.pid, interim);
        Error ->
            Error
    end.

stop(Pid) when is_pid(Pid) ->
    gen_server:call(Pid, stop);
stop(SID) ->
    case fetch(SID) of
        {ok, State} ->
            stop(State#ipt_session.pid);
        Error ->
            Error
    end.

expire(Pid) when is_pid(Pid) ->
    gen_server:call(Pid, expire);
expire(SID) ->
    case fetch(SID) of
        {ok, State} ->
            expire(State#ipt_session.pid);
        Error ->
            Error
    end.

handle_packet(_SrcIP, Pdu) ->
    process_netflow_packet(Pdu).

%% Shows all registered sessions
list() ->
    [list(S) || S <- mnesia:dirty_all_keys(ipt_session)].

%% Shows the session by SID
list(SID) ->
    [Session] = mnesia:dirty_read({ipt_session, SID}), Session.

init([UUID]) ->
    process_flag(trap_exit, true),
    case mnesia:dirty_index_read(ipt_session, UUID, uuid) of
        [] ->
            State = #ipt_session{uuid = UUID,
				 pid = self(),
				 node = node()},
            {ok, State};
        [State] ->
            NewState = State#ipt_session{pid = self(), node = node()},
            mnesia:dirty_write(NewState),
            {ok, NewState};
        _ ->
            {stop, ambiguous_match}
    end.

handle_call({prepare, UserName, Context, Response, Client}, _From, State) ->
    SID = {new, UserName},
    Now = netspire_util:timestamp(),
    Timeout = mod_iptraffic:get_option(session_timeout, 60),
    ExpiresAt = Now + Timeout,
    Shaper = radius:attribute_value("Netspire-Shapers", Response),
    ?INFO_MSG("Shapers are: ~p~n", [Shaper]),
    NewState = State#ipt_session{sid = SID,
				 status = new,
				 username = UserName,
				 nas_spec = Client,
				 disc_req_sent = false,
				 data = Context,
				 started_at = Now,
				 expires_at = ExpiresAt,
				 shaper = Shaper},
    mnesia:dirty_write(NewState),
    {reply, ok, NewState};
handle_call({start, IP, SID, CID}, _From, State) ->
    F = fun() ->
            mnesia:delete_object(State),
            NewState = State#ipt_session{sid = SID, ip = IP, status = active},
            mnesia:write(NewState),
            NewState
        end,
    case mnesia:transaction(F) of
        {atomic, NewState} ->
            Context = NewState#ipt_session.data,
            mod_iptraffic_pgsql:start_session(Context, IP, SID, CID, now()),
	    {reply, ok, NewState};
        Aborted ->
            Reply = {error, Aborted},
            {reply, Reply, State}
    end;
handle_call(interim, _From, State) ->
    Context = State#ipt_session.data,
    Currency = dict:fetch(currency, Context),
    PlanData = dict:fetch(plan_data, Context),
    Balance = dict:fetch(balance, Context),
    {AuthM, AuthF} = dict:fetch(auth_algo, Context),
    State1 = case AuthM:AuthF(Currency, Balance, PlanData) of
		 {accept, Replies} ->
		     update_shapers(State, Replies);
		 {reject, Reason} ->
		     disconnect_session(State, Reason)
	     end,
    Timeout = mod_iptraffic:get_option(session_timeout, 60),
    ExpiresAt = netspire_util:timestamp() + Timeout,
    F = fun() ->
            mnesia:delete_object(State1),
            State2 = State1#ipt_session{expires_at = ExpiresAt},
            mnesia:write(State2),
            State2
        end,
    case mnesia:transaction(F) of
        {atomic, NewState} ->
            #ipt_session{sid = SID, data = Context} = NewState,
	    spawn(fun() -> mod_iptraffic_pgsql:sync_session(Context, SID, now()) end),
	    {reply, ok, NewState};
        Aborted ->
            {reply, {error, Aborted}, State}
    end;
handle_call(stop, _From, State) ->
    case stop_session(State, false) of
        {ok, NewState} ->
            Reply = {ok, NewState},
            {stop, normal, Reply, State};
        {preclosed, NewState} ->
            {reply, {ok, NewState}, NewState};
        _Error ->
            {reply, {error, backend_failure}, State}
    end;
handle_call(expire, _From, State) ->
    case stop_session(State, true) of
        ok -> % status = new
            {stop, normal, ok, State};
        {ok, _} ->
            {stop, normal, ok, State};
        _Error ->
            {reply, {error, backend_failure}, State}
    end.

handle_cast({netflow, Dir, {H, Rec}}, State)
  when is_record(H, nfh_v5), is_record(Rec, nfrec_v5) ->
    IP = case Dir of
	     in ->
		 Rec#nfrec_v5.src_addr;
	     out ->
		 Rec#nfrec_v5.dst_addr
	 end,
    NewState = do_accounting(State, Dir, IP, Rec#nfrec_v5.d_octets),
    mnesia:dirty_write(NewState),
    {noreply, NewState};
handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Request, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(normal, State) ->
    ?INFO_MSG("Session ~s finished successfully~n", [to_string(State)]);
terminate(shutdown, State) ->
    case gen_module:get_option(mod_iptraffic, disconnect_on_shutdown, yes) of
        yes ->
            send_disconnect_request(State);
        _ -> ok
    end,
    stop_session(State, false),
    ?INFO_MSG("Session ~s shutted down successfully~n", [to_string(State)]);
terminate(Reason, State) ->
    ?ERROR_MSG("Session ~s abnormally terminated due to ~p~n", [to_string(State), Reason]).

stop_session(#ipt_session{status = new} = Session, _Expired) ->
    ?INFO_MSG("Discarding session: ~s~n", [to_string(Session)]),
    mnesia:dirty_delete_object(Session),
    {ok, Session};
stop_session(#ipt_session{status = preclosed} = Session, Expired) ->
    #ipt_session{sid = SID, finished_at = FinishedAt, data = Context} = Session,
    mod_iptraffic_pgsql:stop_session(Context, SID, FinishedAt, Expired),
    mnesia:dirty_delete_object(Session),
    {ok, Session};
stop_session(Session, Expired) ->
    NewState = Session#ipt_session{status = preclosed, finished_at = now()},
    case mnesia:transaction(fun() -> mnesia:write(NewState) end) of
        {atomic, ok} ->
            case Expired of
                true ->
                    stop_session(NewState, Expired);
                false ->
                    ?INFO_MSG("Session ~s changed to preclosed~n", [to_string(NewState)]),
                    {preclosed, NewState}
            end;
        Error ->
            ?INFO_MSG("Cannot change status of session ~s due to ~p~n", [to_string(NewState), Error])
    end.

process_netflow_packet({H, Records})
  when is_record(H, nfh_v5), is_list(Records) ->
    Fun = fun(Rec) -> match_record(H, Rec) end,
    lists:foreach(Fun, Records);
process_netflow_packet(_Pdu) ->
    ?WARNING_MSG("Unsupported NetFlow version~n", []).

match_record(H, Rec) when is_record(H, nfh_v5), is_record(Rec, nfrec_v5) ->
    SrcIP = iplib:long2ip(Rec#nfrec_v5.src_addr),
    DstIP = iplib:long2ip(Rec#nfrec_v5.dst_addr),
    case match_session(SrcIP, DstIP) of
        {ok, Matches} ->
            Fun = fun({Dir, Session}) ->
                Message = {netflow, Dir, {H, Rec}},
                gen_server:cast(Session#ipt_session.pid, Message)
            end,
            lists:foreach(Fun, Matches);
        {error, no_matches} ->
            %% ?WARNING_MSG("No active sessions matching flow src/dst: ~s/~s~n",
            %%     [inet_parse:ntoa(SrcIP), inet_parse:ntoa(DstIP)]),
            ok
    end.

match_session(SrcIP, DstIP) ->
    F = fun() ->
            Q = qlc:q([X || X <- mnesia:table(ipt_session),
                    (X#ipt_session.ip == SrcIP orelse X#ipt_session.ip == DstIP) andalso
                    (X#ipt_session.status == active orelse X#ipt_session.status == preclosed)]),
            qlc:e(Q)
    end,
    case mnesia:ets(F) of
        [] ->
            {error, no_matches};
        Res when is_list(Res) ->
            tag_with_direction(Res, SrcIP, DstIP, [])
    end.

tag_with_direction([], _, _, Acc) ->
    {ok, Acc};
tag_with_direction([S | Tail], SrcIP, DstIP, Acc) ->
    S1 = tag_with_direction(S, SrcIP, DstIP),
    tag_with_direction(Tail, SrcIP, DstIP, [S1 | Acc]).
tag_with_direction(S = #ipt_session{ip = DstIP}, _, DstIP) ->
    {in, S};
tag_with_direction(S = #ipt_session{ip = SrcIP}, SrcIP, _) ->
    {out, S}.

do_accounting(Session, Direction, TargetIP, Octets)
  when is_record(Session, ipt_session), is_atom(Direction),
       is_integer(TargetIP), is_integer(Octets) ->
    Context = Session#ipt_session.data,
    Currency = dict:fetch(currency, Context),
    PlanData = dict:fetch(plan_data, Context),
    SessionData = dict:fetch(session_data, Context),
    {AuthM, AuthF} = dict:fetch(auth_algo, Context),
    {AcctM, AcctF} = dict:fetch(acct_algo, Context),
    {Class, Amount, PlanData1} = AcctM:AcctF(Currency, PlanData, SessionData,
					     Direction, TargetIP, Octets),
    SessionData1 = update_session_data(SessionData, Direction, Octets,
				       Amount, Class),
    Balance = dict:fetch(balance, Context) - Amount,
    Context1 = dict:store(plan_data, PlanData1,
			  dict:store(session_data, SessionData1,
				     dict:store(balance, Balance, Context))),
    case AuthM:AuthF(Currency, Balance, PlanData1) of
	{accept, _} ->
	    Session#ipt_session{data = Context1};
	{reject, Reason} ->
	    disconnect_session(Session#ipt_session{data = Context1}, Reason)
    end.

-spec disconnect_session(#ipt_session{}, term()) -> #ipt_session{}.
disconnect_session(Session, Reason)
  when is_record(Session, ipt_session) ->
    case Session#ipt_session.disc_req_sent of
	true ->
	    Session;
	false ->
	    ?INFO_MSG("Disconnecting user ~p, reason ~p~n",
		      [Session#ipt_session.username, Reason]),
	    spawn(fun() -> send_disconnect_request(Session) end),
	    Session#ipt_session{disc_req_sent = true}
    end.

send_disconnect_request(Session) ->
    UserName = Session#ipt_session.username,
    SID = Session#ipt_session.sid,
    IP = Session#ipt_session.ip,
    NasSpec = Session#ipt_session.nas_spec,
    ?INFO_MSG("Disconnecting ~s | SID: ~p~n", [UserName, SID]),
    case netspire_hooks:run_fold(disconnect_client, undef, [UserName, SID, IP, NasSpec]) of
        {ok, _} ->
            ?INFO_MSG("User ~s | SID: ~p successful disconnected~n", [UserName, SID]);
        {error, Reason} ->
            ?ERROR_MSG("Failed to disconnect ~s | SID: ~p due to ~s~n", [UserName, SID, Reason])
    end.

update_session_data(Data, Direction, Octets, Amount, Class)
  when is_atom(Direction), is_integer(Octets), is_binary(Class) ->
    Details = dict:fetch(details, Data),
    [ClassIn, ClassOut] = case dict:find(Class, Details) of
			      {ok, V} -> V;
			      error -> [0, 0]
			  end,
    NewAmount = dict:fetch(amount, Data) + Amount,
    case Direction of
	in ->
	    NewDetails = dict:store(Class, [ClassIn + Octets, ClassOut], Details),
	    dict:store(octets_in, dict:fetch(octets_in, Data) + Octets,
		       dict:store(amount, NewAmount,
				  dict:store(details, NewDetails, Data)));
	out ->
	    NewDetails = dict:store(Class, [ClassIn, ClassOut + Octets], Details),
	    dict:store(octets_out, dict:fetch(octets_out, Data) + Octets,
		       dict:store(amount, NewAmount,
				  dict:store(details, NewDetails, Data)))
    end.

fetch(SID) ->
    case mnesia:dirty_read(ipt_session, SID) of
        [State] ->
            {ok, State};
        [] ->
            {error, not_found}
    end.

to_string(Session) ->
    #ipt_session{username = UserName, sid = SID} = Session,
    io_lib:format("Username: ~s, SID: ~p", [UserName, SID]).

-spec update_shapers(#ipt_session{}, list()) -> #ipt_session{}.
update_shapers(Session, Replies)
  when is_record(Session, ipt_session), is_list(Replies) ->
    Shaper = Session#ipt_session.shaper,
    NewShaper = proplists:get_value("Netspire-Shapers", Replies),
    case NewShaper of
	Shaper ->
	    Session;
	_ ->
	    ?INFO_MSG("Session ~s changes shaper to ~p~n",
		      [to_string(Session), NewShaper]),
	    NewSession = Session#ipt_session{shaper = NewShaper},
	    spawn(fun() -> send_updated_shaper(NewSession) end),
	    NewSession
    end.

-spec send_updated_shaper(#ipt_session{}) -> ok.
send_updated_shaper(Session) when is_record(Session, ipt_session) ->
    UserName = Session#ipt_session.username,
    SID = Session#ipt_session.sid,
    IP = Session#ipt_session.ip,
    NasSpec = Session#ipt_session.nas_spec,
    Shaper = Session#ipt_session.shaper,
    case netspire_hooks:run_fold(send_shaper, undef, [UserName, SID, IP, NasSpec, Shaper]) of
        {ok, _} ->
	    ok;
        {error, Reason} ->
            ?ERROR_MSG("Session ~s failed to send shapers for ~p~n",
		       [to_string(Session), Reason]),
	    ok
    end.
