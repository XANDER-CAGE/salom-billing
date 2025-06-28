-module(algo_builtin).
-include("netspire.hrl").

-export([
	 prepaid_auth/3
	 ,prepaid_acct/6
	 ,andbur_prepaid_auth/3
	 ,limited_prepaid_auth/3
	 ,on_auth/3
	 ,no_overlimit_auth/3
	 ,no_overlimit_acct/6
	]).

prepaid_auth(_Currency, Balance, PlanData) ->
    Credit = case dict:find(<<"CREDIT">>, PlanData) of
		 {ok, V} ->
		     V;
		 error ->
		     0
	     end,
    DefaultShaper = case dict:find(<<"SHAPER">>, PlanData) of
			{ok, S} -> S;
			error -> undefined
		    end,
    IntervalAccess = access_allowed_intervals(PlanData, DefaultShaper),
    case IntervalAccess of
	{accept, Shaper} ->
	    Replies = case Shaper of
			  undefined -> [];
			  _ -> [{"Netspire-Shapers", binary_to_list(Shaper)}]
		      end,
	    case Balance + Credit >= 0 of
		true ->
		    {accept, Replies};
		false ->
		    {reject, low_balance}
	    end;
	_ ->
	    {reject, time_of_day}
    end.

on_auth(_Currency, _Balance, PlanData) ->
    DefaultShaper = case dict:find(<<"SHAPER">>, PlanData) of
			{ok, S} -> S;
			error -> undefined
		    end,
    IntervalAccess = access_allowed_intervals(PlanData, DefaultShaper),
    case IntervalAccess of
	{accept, Shaper} ->
	    Replies = case Shaper of
			  undefined -> [];
			  _ -> [{"Netspire-Shapers", binary_to_list(Shaper)}]
		      end,
	    {accept, Replies};
	_ ->
	    {reject, time_of_day}
    end.

limited_prepaid_auth(_Currency, Balance, PlanData) ->
    Credit = case dict:find(<<"CREDIT">>, PlanData) of
		 {ok, V} ->
		     V;
		 error ->
		     0
	     end,
    DefaultShaper = case dict:find(<<"SHAPER">>, PlanData) of
			{ok, S} -> S;
			error -> undefined
		    end,
    IntervalAccess = access_allowed_intervals(PlanData, DefaultShaper),
    Prepaid = case dict:find(<<"PREPAID">>, PlanData) of {ok, P} -> P; error -> 0 end,
    case IntervalAccess of
	{accept, Shaper} ->
	    Replies = case Shaper of
			  undefined -> [];
			  _ -> [{"Netspire-Shapers", binary_to_list(Shaper)}]
		      end,
	    case Balance + Credit >= 0 of
		true ->
		    case Prepaid > 0 of
			true -> {accept, Replies};
			false -> {reject, low_balance}
		    end;
		false ->
		    {reject, low_balance}
	    end;
	_ ->
	    {reject, time_of_day}
    end.

andbur_prepaid_auth(Currency, Balance, PlanData) ->
    limited_prepaid_auth(Currency, Balance, PlanData).

access_allowed_intervals(PlanData, DefaultShaper) ->
    AccessIntervals = case dict:find(<<"ACCESS_INTERVALS">>, PlanData) of
			  {ok, V} when is_list(V) -> V;
			  error -> []
		      end,
    case AccessIntervals of
	[] ->
	    {accept, DefaultShaper};
	[_|_] ->
	    {_Date, Time} = calendar:local_time(),
	    {Hour, Minute, Second} = Time,
	    TodaySeconds = Hour * 3600 + Minute * 60 + Second,
	    [Current | _] = lists:filter(fun([Boundary | _]) ->
						 TodaySeconds < Boundary
					 end, AccessIntervals),
	    Shaper = case Current of
			 [_, Access] ->
			     DefaultShaper;
			 [_, Access, S] ->
			     S
		     end,
	    case Access of
		<<"accept">> -> {accept, Shaper};
		_ -> reject
	    end
    end.

prepaid_acct(Currency, PlanData, _SessionData, Direction, IP, Octets)
  when is_integer(Currency), is_atom(Direction), is_integer(IP),
       is_integer(Octets) ->
    {_Date, Time} = calendar:local_time(),
    {Hour, Minute, Second} = Time,
    TodaySeconds = Hour * 3600 + Minute * 60 + Second,
    Intervals = dict:fetch(<<"INTERVALS">>, PlanData),
    [[_, Prices] | _] = lists:filter(fun([Boundary | _]) ->
					     TodaySeconds < Boundary
				     end, Intervals),
    Class = list_to_binary(atom_to_list(tclass:classify(IP, internet))),
    ClassPrices = dict:fetch(Class, Prices),
    [IPrice, OPrice] = case ClassPrices of
			   [[_, _, _]|_] ->
			       [[_, I, O]] = lists:filter(fun([X|_]) ->
								  X == Currency
							  end, ClassPrices),
			       [I, O];
			   [I, O] ->
			       [I, O]
		       end,
    Link = list_to_binary(["PREPAID_", Class, "_", atom_to_list(Direction)]),
    Name = case dict:find(Link, PlanData) of {ok, V} -> V; error -> "PREPAID" end,
    Prepaid = case dict:find(Name, PlanData) of {ok, P} -> P; error -> 0 end,
    Price = case Direction of in -> IPrice; out -> OPrice end,
    {PayableOctets, Prepaid1} = case Price == 0 of
				    true ->
					{0, Prepaid};
				    false ->
					overlimit(Octets, Prepaid)
				end,
    Amount = Price * PayableOctets / 1024 / 1024,
    case Prepaid == Prepaid1 of
	true ->
	    {Class, float(Amount), PlanData};
	false ->
	    {Class, float(Amount),
	     dict:store(Name, Prepaid1, PlanData)}
    end.

overlimit(Bytes, Limit) when is_integer(Bytes), is_integer(Limit),
			     Bytes =< Limit ->
    {0, Limit - Bytes};
overlimit(Bytes, Limit) when is_integer(Bytes), is_integer(Limit) ->
    {Bytes - Limit, 0}.

no_overlimit_auth(_Currency, Balance, PlanData) ->
    Credit = case dict:find(<<"CREDIT">>, PlanData) of
		 {ok, V} ->
		     V;
		 error ->
		     0
	     end,
    DefaultShaper = case dict:find(<<"SHAPER">>, PlanData) of
			{ok, S} -> S;
			error -> undefined
		    end,
    DropSpeed = case dict:find(<<"DROP_SPEED">>, PlanData) of
		    {ok, V2} ->
			V2;
		    error ->
			0
		end,
    IntervalAccess = access_allowed_intervals(PlanData, DefaultShaper),
    case IntervalAccess of
	{accept, Shaper} ->
	    Replies = case DropSpeed of
			  1 ->
			      [{"Netspire-Shapers", binary_to_list(DefaultShaper)}];
			  _ ->
			      case Shaper of
				  undefined -> [];
				  _ -> [{"Netspire-Shapers", binary_to_list(Shaper)}]
			      end
		      end,
	    case Balance + Credit >= 0 of
		true ->
		    {accept, Replies};
		false ->
		    {reject, low_balance}
	    end;
	_ ->
	    {reject, time_of_day}
    end.

no_overlimit_acct(Currency, PlanData, SessionData, Direction, IP, Octets)
  when is_integer(Currency), is_atom(Direction), is_integer(IP),
       is_integer(Octets) ->
    {Class, Amount, PlanData1} = prepaid_acct(Currency, PlanData, SessionData, Direction, IP, Octets),
    case Amount > 0 of
	true ->
	    PlanData2 = dict:store(<<"DROP_SPEED">>, 1, PlanData1),
	    {Class, 0, PlanData2};
	false ->
	    {Class, Amount, PlanData1}
    end.
