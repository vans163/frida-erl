-module(frida).
-compile(export_all).

get_all_devices(DevMan) ->
    {ok, DevList} = frida_nif:device_manager_enumerate_devices(DevMan),
    DevListSize = frida_nif:device_list_size(DevList),
    R = lists:foldl(fun(DevIndex, A) ->
            Dev = frida_nif:device_list_get(DevList, DevIndex),

            Id = frida_nif:device_get_id(Dev),
            Name = frida_nif:device_get_name(Dev),
            DType = frida_nif:device_get_dtype(Dev),
            %frida_nif:unref(Dev),
            A#{Id=> #{name=> Name, dtype=> DType, ptr=> Dev}}
        end, #{}, lists:seq(0, DevListSize-1)),
    ok = frida_nif:unref(DevList),
    R.

get_device_by_id(DevMan, Id) ->
    case get_all_devices(DevMan) of
        #{Id:= #{ptr:= Dev}} -> Dev;
        _ -> undefined
    end.

get_pid_by_name(Dev, ProcName) when is_binary(ProcName) ->
    io:format("pid_by_name_start\n"),
    case frida_nif:device_get_process_by_name(Dev, ProcName) of
        {ok, Proc} -> 
            io:format("pid_by_name_end~n"),
            frida_nif:process_get_pid(Proc);
        _ -> 
            io:format("pid_by_name_end~n"),
            undefined
    end.


test() ->
    ok = frida_nif:init(),
    DevMan = frida_nif:device_manager_new(),
    frida_nif:device_manager_add_remote_device(DevMan, <<"192.168.6.11:15100">>),
    io:format("1\n"),
    Dev = get_device_by_id(DevMan,  <<"tcp@192.168.6.11:15100">>),
    io:format("2\n"),
    Pid = get_pid_by_name(Dev, <<"notepad.exe">>),
    io:format("3\n"),
    {ok, Session} = frida_nif:device_attach(Dev, Pid),
    io:format("4\n"),

    {ok, ErlFridaScript} = run_script(Session,  
        <<"
        console.log('hi');
        console.log('bye');
        setTimeout(function(){ console.log('Hello'); }, 3000);
        setTimeout(function(){ console.log('Hello2'); }, 2000);
        //console.log('bye');
        /*Interceptor.attach(Module.findExportByName(null, 'open'), {
            onEnter: function (args) {
                console.log('[*] open(\"' + Memory.readUtf8String(args[0]) + '\")');
            }
        });
        Interceptor.attach(Module.findExportByName(null, 'close'), {
            onEnter: function (args) {
                console.log('[*] close(' + args[0].toInt32() + ')');
            }
        });*/
        "/utf8, 0>>).

run_script(Session, ScriptBin) ->
    {ok, Script} = frida_nif:session_create_script(Session, <<"default_script", 0>>, ScriptBin),

    frida_nif:connect_signal_message(Script),
    frida_nif:script_load(Script),

    Loop = frida_nif:create_loop(),
    %LoopPid = spawn(fun()->  
    %    io:format("start loop~n"),
    %    frida_nif:run_loop(Loop),
    %    io:format("loop_done~n")
    %end),

    %frida_script_unload_sync (script, NULL),

    {ok, Loop}.

    
%receive X-> X after 1 -> ok end.