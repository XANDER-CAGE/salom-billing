-module(tclass).

-behaviour(gen_server).

%% gen_server callbacks
-export([code_change/3, handle_call/3, handle_cast/2, handle_info/2, init/1, terminate/2]).

%% API

-export([
	 classify/1
	 ,classify/2
	 ,load/1
	 ,start_link/0
	]).

-import(lists, [
		flatten/1
		,foldl/3
		,map/2
		,sort/1
	       ]).

-include("netspire.hrl").

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% ====================
%% EXPORTED FUNCTIONS
%% ====================

-spec classify(integer(), atom()) -> atom().
classify(IP, Default)
  when is_integer(IP), is_atom(Default) ->
    case classify(IP) of
	{ok, TrafficClass} ->
	    TrafficClass;
	not_found ->
	    Default
    end.

-spec classify(integer()) -> 'not_found' | {ok, atom()}.
classify(IP) when is_integer(IP) ->
    gen_server:call(?MODULE, {classify, IP}).

-spec load(list()) -> ok | {failed, term()}.
load(File) when is_list(File) ->
    gen_server:call(?MODULE, {load, File}).

%% gen_server callbacks implementation
code_change(_OldVsn, Tree, _Extra) ->
    {ok, Tree}.

handle_call({classify, IP}, _From, Tree) when is_integer(IP) ->
    {reply, tree_search(IP, Tree), Tree};
handle_call({load, File}, _From, Tree) when is_list(File) ->
    ?INFO_MSG("Loading traffic classes from ~s~n", [File]),
    try
	case load_file(File) of
	    {error, Reason} ->
		{reply, {failed, Reason}, Tree};
	    NewTree ->
		{reply, ok, NewTree}
	end
    catch
	_:Error ->
	    {reply, {failed, Error}, Tree}
    end.

handle_cast(_Request, Tree) ->
    {noreply, Tree}.

handle_info(_Info, Tree) ->
    {noreply, Tree}.

init(_) ->
    {ok, empty_tree()}.

terminate(_Reason, _State) ->
    ok.

%% ====================
%% INTERNAL FUNCTIONS
%% ====================

% Search tree manipulation
-opaque ip_search_tree():: any().

-spec empty_tree() -> ip_search_tree().
empty_tree() ->
    empty.

-spec tree_node(integer(), integer(), atom(), ip_search_tree(), ip_search_tree()) -> ip_search_tree().
tree_node(Start, End, Class, LeftTree, RightTree)
  when is_integer(Start), is_integer(End), is_atom(Class) ->
    {Start, End, Class, LeftTree, RightTree}.

-spec tree_search(integer(), 'empty' | ip_search_tree()) -> 'not_found' | {'ok',atom()}.
tree_search(Key, empty) when is_integer(Key) ->
    not_found;
tree_search(Key, {S, _, _, Left, _})
  when is_integer(Key), is_integer(S), Key < S ->
    tree_search(Key, Left);
tree_search(Key, {_, E, _, _, Right})
  when is_integer(Key), is_integer(E), Key > E ->
    tree_search(Key, Right);
tree_search(Key, {_, _, Class, _, _}) when is_integer(Key), is_atom(Class) ->
    {ok, Class}.

tree_from_list(List, 0) when is_list(List) ->
    {empty_tree(), List};
tree_from_list(List, N) when is_integer(N), N > 0 ->
    FirstHalf = (N - 1) div 2,
    SecondHalf = N - 1 - FirstHalf,
    {LeftTree, [{S, E, C} | Rest]} = tree_from_list(List, FirstHalf),
    {RightTree, Unused} = tree_from_list(Rest, SecondHalf),
    {tree_node(S, E, C, LeftTree, RightTree), Unused}.

%% loading config file and building a tree search from that
	   
load_file(File) when is_list(File) ->
    case file:consult(File) of
	{ok, Terms} ->
	    {ok, Tree} = build_tree(Terms),
	    Tree;
	{error, Reason} ->
	    {error, Reason}
    end.

build_tree([]) ->
    {ok, empty_tree()};
build_tree(Terms) when is_list(Terms) ->
    Triples = sort(flatten(map(fun class_to_triples/1, Terms))),
    case check_overlaps(Triples) of
	ok ->
	    Len = length(Triples),
	    {Tree, []} = tree_from_list(Triples, Len),
	    {ok, Tree};
	{overlaps, T1, T2} ->
	    {overlaps, T1, T2}
    end.

class_to_triples({Class, Networks}) when is_atom(Class), is_list(Networks) ->
    map(fun (N) ->
		{Start, End} = network_range(N),
		{Start, End, Class}
	end,
	Networks).

check_overlaps(List) when is_list(List) ->
    check_overlaps({-1, -1, undefined}, List).

check_overlaps(_, []) ->
    ok;
check_overlaps(T1 = {_, E1, _}, [T2 = {S2, _, _} | T]) ->
    case S2 < E1 of
	true ->
	    {overlaps, T1, T2};
	false ->
	    check_overlaps(T2, T)
    end.
   
network_range(Network) when is_list(Network) ->
    case string:tokens(Network, "/") of
	[N, M] ->
	    network(N, list_to_integer(M));
	[N] ->
	    network(N, 32)
    end.

network(IP, Mask) when is_list(IP), is_integer(Mask) ->
    [A, B, C, D] = map(fun list_to_integer/1, string:tokens(IP, ".")),
    Start = (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D,
    End = Start - 1 + (1 bsl (32 - Mask)),
    {Start, End}.
   
