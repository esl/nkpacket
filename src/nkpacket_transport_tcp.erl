%% -------------------------------------------------------------------
%%
%% Copyright (c) 2016 Carlos Gonzalez Florido.  All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------

%% @private TCP/TLS Transport.
%% This module is used for both inbound and outbound TCP and TLS connections.

-module(nkpacket_transport_tcp).
-author('Carlos Gonzalez <carlosj.gf@gmail.com>').

-export([get_listener/1, connect/1, start_link/1]).
-export([init/1, terminate/2, code_change/3, handle_call/3, handle_cast/2,
         handle_info/2]).
-export([start_link/3]).

-include("nkpacket.hrl").


%% ===================================================================
%% Private
%% ===================================================================

%% @private Starts a new listening server
-spec get_listener(nkpacket:nkport()) ->
    supervisor:child_spec().

get_listener(#nkport{listen_ip=Ip, listen_port=Port, transp=Transp}=NkPort)
        when Transp==tcp; Transp==tls ->
    {
        {{Transp, Ip, Port}, make_ref()},
        {?MODULE, start_link, [NkPort]},
        transient,
        5000,
        worker,
        [?MODULE]
    }.


%% @private Starts a new connection to a remote server
-spec connect(nkpacket:nkport()) ->
    {ok, nkpacket:nkport()} | {error, term()}.

connect(NkPort) ->
    #nkport{
        transp = Transp,
        remote_ip = Ip,
        remote_port = Port,
        meta = Meta
    } = NkPort,
    SocketOpts = outbound_opts(NkPort),
    {InetMod, TranspMod, _} = get_modules(Transp),
    ConnTimeout = case maps:get(connect_timeout, Meta, undefined) of
        undefined -> nkpacket_config_cache:connect_timeout();
        Timeout0 -> Timeout0
    end,
    logger:debug("TCP connect to: ~p:~p:~p (~p)", [Transp, Ip, Port, SocketOpts]),
    case TranspMod:connect(Ip, Port, SocketOpts, ConnTimeout) of
        {ok, Socket} ->
            {ok, {LocalIp, LocalPort}} = InetMod:sockname(Socket),
            NkPort1 = NkPort#nkport{
                local_ip = LocalIp,
                local_port = LocalPort,
                socket = Socket
            },
            InetMod:setopts(Socket, [{active, once}]),
            {ok, NkPort1};
        {error, Error} ->
            {error, Error}
    end.



%% ===================================================================
%% gen_server
%% ===================================================================

%% @private
start_link(NkPort) ->
    gen_server:start_link(?MODULE, [NkPort], []).


-record(state, {
    nkport :: nkpacket:nkport(),
    ranch_id :: term(),
    ranch_pid :: pid(),
    protocol :: nkpacket:protocol(),
    proto_state :: term(),
    monitor_ref :: reference()
}).


%% @private
-spec init(term()) ->
    {ok, #state{}} | {stop, term()}.

init([NkPort]) ->
    #nkport{class = Class,
            protocol = Protocol,
            transp = Transp,
            listen_ip = ListenIp,
            listen_port = ListenPort,
            meta = Meta} = NkPort,
    process_flag(trap_exit, true),
    {_InetMod, _, RanchMod} = get_modules(Transp),
    Id = binary_to_atom(nklib_util:hash({tcp, ListenIp, ListenPort})),
    true = register(Id, self()),
    NkPort1 = NkPort#nkport{pid = self()},
    RanchId = {ListenPort, ListenIp, Transp},
    RanchPort = NkPort1#nkport{meta=maps:with(?CONN_LISTEN_OPTS, Meta)},
    TransportOpts = #{socket_opts => listen_opts(NkPort),
                      num_acceptors => maps:get(tcp_listeners, Meta, 100),
                      max_connections => maps:get(tcp_max_connections, Meta, 1024)},
    {ok, RanchPid} = ranch_listener_sup:start_link(RanchId, RanchMod, TransportOpts,
                                                   ?MODULE, RanchPort),
    nklib_proc:put(nkpacket_listeners, {Id, Class}),
    ConnMetaOpts = [tcp_packet | ?CONN_LISTEN_OPTS],
    ConnMeta = maps:with(ConnMetaOpts, Meta),
    ConnPort = NkPort1#nkport{meta=ConnMeta},
    ListenType = case size(ListenIp) of
                     4 -> nkpacket_listen4;
                     8 -> nkpacket_listen6
                 end,
    nklib_proc:put({ListenType, Class, Protocol, Transp}, ConnPort),
    {ok, ProtoState} = nkpacket_util:init_protocol(Protocol, listen_init, NkPort1),
    MonRef = case Meta of
                 #{monitor:=UserRef} -> erlang:monitor(process, UserRef);
                 _ -> undefined
             end,
    State = #state{nkport = ConnPort,
                   ranch_id = RanchId,
                   ranch_pid = RanchPid,
                   protocol = Protocol,
                   proto_state = ProtoState,
                   monitor_ref = MonRef},
    {ok, State}.

%% @private
-spec handle_call(term(), {pid(), term()}, #state{}) ->
    {reply, term(), #state{}} | {noreply, term(), #state{}} |
    {stop, term(), #state{}} | {stop, term(), term(), #state{}}.

handle_call({nkpacket_apply_nkport, Fun}, _From, #state{nkport=NkPort}=State) ->
    {reply, Fun(NkPort), State};

handle_call(nkpacket_stop, _From, State) ->
    {stop, normal, ok, State};

handle_call(Msg, From, #state{nkport=NkPort}=State) ->
    case call_protocol(listen_handle_call, [Msg, From, NkPort], State) of
        undefined -> {noreply, State};
        {ok, State1} -> {noreply, State1};
        {stop, Reason, State1} -> {stop, Reason, State1}
    end.


%% @private
-spec handle_cast(term(), #state{}) ->
    {noreply, #state{}} | {stop, term(), #state{}}.

handle_cast(nkpacket_stop, State) ->
    {stop, normal, State};

handle_cast(Msg, #state{nkport=NkPort}=State) ->
    case call_protocol(listen_handle_cast, [Msg, NkPort], State) of
        undefined -> {noreply, State};
        {ok, State1} -> {noreply, State1};
        {stop, Reason, State1} -> {stop, Reason, State1}
    end.


%% @private
-spec handle_info(term(), #state{}) ->
    {noreply, #state{}} | {stop, term(), #state{}}.

handle_info({'DOWN', MRef, process, _Pid, _Reason}, #state{monitor_ref=MRef}=State) ->
    {stop, normal, State};

handle_info({'EXIT', Pid, Reason}, #state{ranch_pid=Pid}=State) ->
    {stop, {ranch_stop, Reason}, State};

handle_info(Msg, #state{nkport=NkPort}=State) ->
    case call_protocol(listen_handle_info, [Msg, NkPort], State) of
        undefined -> {noreply, State};
        {ok, State1} -> {noreply, State1};
        {stop, Reason, State1} -> {stop, Reason, State1}
    end.


%% @private
-spec code_change(term(), #state{}, term()) ->
    {ok, #state{}}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% @private
-spec terminate(term(), #state{}) ->
    ok.

terminate(Reason, State) ->
    #state{
        ranch_id = RanchId,
        ranch_pid = RanchPid,
        nkport = #nkport{transp=Transp, socket=Socket} = NkPort
    } = State,
    logger:debug("TCP/TLS listener stop: ~p", [Reason]),
    catch call_protocol(listen_stop, [Reason, NkPort], State),
    exit(RanchPid, shutdown),
    timer:sleep(100),   %% Give time to ranch to close acceptors
    catch ranch_server:cleanup_listener_opts(RanchId),
    {_, TranspMod, _} = get_modules(Transp),
    TranspMod:close(Socket),
    ok.


%% ===================================================================
%% Ranch Callbacks
%% ===================================================================


%% @private Ranch's callback, called for every new inbound connection
%% to create a new process to manage it
-spec start_link(term(), atom(), term()) ->
    {ok, pid()}.

start_link(Ref, TranspModule, NkPort) ->
    nkpacket_connection:ranch_start_link(Ref, TranspModule, NkPort).


%% ===================================================================
%% Internal
%% ===================================================================


%% @private Gets socket options for outbound connections
-spec outbound_opts(#nkport{}) ->
    list().

outbound_opts(#nkport{transp=tcp, meta=Opts}) ->
    [
        {packet, case Opts of #{tcp_packet:=Packet} -> Packet; _ -> raw end},
        binary, {active, false}, {nodelay, true}, {keepalive, true}
    ];

outbound_opts(#nkport{transp=tls, meta=Opts}) ->
    [
        {packet, case Opts of #{tcp_packet:=Packet} -> Packet; _ -> raw end},
        binary, {active, false}, {nodelay, true}, {keepalive, true}
    ]
    ++ nkpacket_util:make_tls_opts(Opts).


%% @private Gets socket options for listening connections
-spec listen_opts(#nkport{}) ->
    list().

listen_opts(#nkport{transp = tcp} = NkPort) ->
    basic_listen_opts(NkPort);
listen_opts(#nkport{transp = tls, meta = Opts} = NkPort) ->
    basic_listen_opts(NkPort) ++ nkpacket_util:make_tls_opts(Opts).

basic_listen_opts(#nkport{listen_ip=Ip, listen_port=ListenPort}) ->
    [{port, ListenPort}, {ip, Ip}, {nodelay, true}, {keepalive, true}, {backlog, 1024}].

%% @private
call_protocol(Fun, Args, State) ->
    nkpacket_util:call_protocol(Fun, Args, State, #state.protocol).


%% @private
get_modules(tcp) -> {inet, gen_tcp, ranch_tcp};
get_modules(tls) -> {ssl, ssl, ranch_ssl}.




