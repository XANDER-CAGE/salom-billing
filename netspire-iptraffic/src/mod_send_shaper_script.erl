-module(mod_send_shaper_script).

-behaviour(gen_module).

%% API
-export([send_shaper/6]).

%% gen_module callbacks
-export([start/1, stop/0]).

-include("netspire.hrl").

start(_Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    netspire_hooks:add(send_shaper, ?MODULE, send_shaper).

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    netspire_hooks:delete(send_shaper, ?MODULE, send_shaper).

send_shaper(_, UserName, SID, IP, NasSpec, Shaper) ->
    {nas_spec, NasIP, _, _, _} = NasSpec,
    Script = gen_module:get_option(?MODULE, send_shaper_script),
    Cmd = string:join([Script, UserName, SID, inet_parse:ntoa(IP), inet_parse:ntoa(NasIP), Shaper], " "),
    case call_external_prog(Cmd) of
        {0, _} -> {ok, []};
        {_, Output} -> {error, string:strip(Output, right, $\n)}
    end.

call_external_prog(Cmd) ->
    call_external_prog(Cmd, "").

call_external_prog(Cmd, Dir) ->
    call_external_prog(Cmd, Dir, []).

call_external_prog(Cmd, Dir, Env) ->
    CD = if Dir =:= "" -> [];
        true -> [{cd, Dir}]
    end,
    SetEnv = if Env =:= [] -> [];
        true -> [{env, Env}]
        end,
    Opt = CD ++ SetEnv ++ [stream, exit_status, use_stdio,
               stderr_to_stdout, in, eof],
    P = open_port({spawn, Cmd}, Opt),
    get_data(P, []).

get_data(P, D) ->
    receive
        {P, {data, D1}} ->
            get_data(P, [D1|D]);
        {P, eof} ->
            port_close(P),
            receive
                {P, {exit_status, N}} ->
                    {N, normalize(lists:flatten(lists:reverse(D)))}
            end
    end.

normalize([$\r, $\n | Cs]) ->
    [$\n | normalize(Cs)];
normalize([$\r | Cs]) ->
    [$\n | normalize(Cs)];
normalize([C | Cs]) ->
    [C | normalize(Cs)];
normalize([]) ->
    [].
