-module(frida_example).
-behavior(gen_server).
-compile(export_all).

handle_cast(_, S) -> {noreply, S}.
handle_call(_, _, S) -> {reply, ok, S}.
code_change(_OldVersion, S, _Extra) -> {ok, S}.
terminate(_R, _S) -> ok.

start_link() -> gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%frida_example:start_link().
%erlang:process_info(list_to_pid("<0.122.0>")).

-define(SCRIPT, 
<<"
    console.log('hi');
    setTimeout(function(){console.log('hiagain');}, 2000);
    /*Interceptor.attach(Module.findExportByName('User32.dll', 'GetMessage'), {
        onEnter: function(args) {
            console.log('[*] open(\"' + Memory.readUtf8String(args[0]) + '\")');
        }
    });
    Interceptor.attach(Module.findExportByName('User32.dll', 'DispatchMessage'), {
        onEnter: function(args) {
            console.log('[*] close(' + args[0].toInt32() + ')');
        }
    });*/

    //recv('eval', function onMessage(scriptcode) { console.log('pokeBack'); });
    //recv('eval', function onMessage(scriptcode) { send(scriptcode); });
"/utf8>>
).

init([]) ->
    io:format("~p: Started!~n", [?MODULE]),

    ok = frida_nif:init(),
    DevMan = frida_nif:device_manager_new(),
    frida_nif:device_manager_add_remote_device(DevMan, <<"192.168.6.11:15100">>),
    io:format("1\n"),
    Dev = frida:get_device_by_id(DevMan,  <<"tcp@192.168.6.11:15100">>),
    io:format("2\n"),
    %Pid = frida:get_pid_by_name(Dev, <<"notepad.exe">>),
    Pid = 2972,
    io:format("3\n"),
    {ok, Session} = frida_nif:device_attach(Dev, Pid),
    io:format("4\n"),

    erlang:send_after(1, self(), check_script),
    {ok, #{dev_man=> DevMan, dev=> Dev, session=> Session}}.

handle_info(check_script, S) ->
    erlang:send_after(1000, self(), check_script),

    Session = maps:get(session, S),
    Script = maps:get(script, S, undefined),
    OldScriptHash = maps:get(script_hash, S, undefined),
    NewScriptHash = erlang:phash2(?SCRIPT),
    
    case OldScriptHash == NewScriptHash of
        true -> 
            {noreply, S};
        false ->
            io:format("~p: Script changed~n", [?MODULE]),
            case Script of
                undefined -> ignore;
                _ -> ok = frida_nif:script_unload(Script)
            end,
            io:format("~p: Old Script unloaded~n", [?MODULE]),
            NewScript = frida:run_script(Session, ?SCRIPT),
            io:format("~p: New Script running~n", [?MODULE]),
            {noreply, S#{script=> NewScript, script_hash=> NewScriptHash}}
    end;
    
handle_info({post_message, Msg}, S) ->
    Script = maps:get(script, S),
    ok = frida_nif:script_post(Script, <<"{\"type\": \"eval\"}"/utf8, 0>>, <<"two">>),
    {noreply, S};

%"{\"type\":\"log\",\"level\":\"info\",\"payload\":\"hiagain2\"}"
%"{\"type\":\"send\",\"payload\":\"pokeBack\"}"

handle_info({script_message, _ScriptPtr, Msg, Body}, S) ->
    io:format("~p: script_message ~p~n ~p~n ~p~n", [?MODULE, _ScriptPtr, Msg, Body]),
    {noreply, S}.

