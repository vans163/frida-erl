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

run_script(Session, ScriptBin) ->    
    {ok, Script} = frida_nif:session_create_script(Session, <<"default_script", 0>>, <<ScriptBin/binary, 0>>),

    frida_nif:connect_signal_message(Script, self()),
    frida_nif:script_load(Script),

    Script.