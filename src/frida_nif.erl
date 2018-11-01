-module(frida_nif).
-on_load(load_nif/0).

-compile(export_all).

load_nif() ->
    Path = case code:priv_dir(?MODULE) of
        {error, _} ->
            EbinDir = filename:dirname(code:which(?MODULE)),
            AppPath = filename:dirname(EbinDir),
            filename:join(AppPath, "priv");
        P ->
            P
    end,
    NifName = case os:type() of
        {win32, nt} -> <<"frida_nif_win_x86_64">>;
        {unix, linux} -> <<"frida_nif_linux_x86_64">> 
    end,
    FullPath = filename:join([Path, NifName]),
    
    Res = erlang:load_nif(FullPath, 0),
    Res.

%/* Library lifetime */
init() -> "NIF library not loaded".
shutdown() -> "NIF library not loaded".
deinit() -> "NIF library not loaded".
get_main_context() -> "NIF library not loaded".

%/* Object lifetime */
unref(_) -> "NIF library not loaded".

%/* Library versioning */
version() -> "NIF library not loaded".
version_string() -> "NIF library not loaded".

%/* DeviceManager */
device_manager_new() -> "NIF library not loaded".
device_manager_close(_) -> "NIF library not loaded".
device_manager_get_device_by_id(_,_,_,_) -> "NIF library not loaded".
device_manager_get_device_by_type(_,_,_,_,_) -> "NIF library not loaded".
device_manager_get_device(_,_,_,_,_) -> "NIF library not loaded".
device_manager_find_device_by_id(_,_,_,_,_) -> "NIF library not loaded".
device_manager_find_device_by_type(_,_,_,_,_) -> "NIF library not loaded".
device_manager_find_device(_,_,_,_,_) -> "NIF library not loaded".
device_manager_enumerate_devices(_) -> "NIF library not loaded".
device_manager_add_remote_device(_,_) -> "NIF library not loaded".
device_manager_remove_remote_device(_,_) -> "NIF library not loaded".

%/* DeviceList */
device_list_size(_) -> "NIF library not loaded".
device_list_get(_,_) -> "NIF library not loaded".

%/* Device */
device_get_id(_) -> "NIF library not loaded".
device_get_name(_) -> "NIF library not loaded".
device_get_icon(_) -> "NIF library not loaded".
device_get_dtype(_) -> "NIF library not loaded".
device_get_manager(_) -> "NIF library not loaded".

device_is_lost(_) -> "NIF library not loaded".
device_get_frontmost_application(_) -> "NIF library not loaded".
device_enumerate_applications(_) -> "NIF library not loaded".
device_get_process_by_pid(_,_) -> "NIF library not loaded".
device_get_process_by_name(_,_,_) -> "NIF library not loaded".
device_get_process(_,_,_,_) -> "NIF library not loaded".
device_find_process_by_pid(_,_) -> "NIF library not loaded".
device_find_process_by_name(_,_,_) -> "NIF library not loaded".
device_find_process(_,_,_,_) -> "NIF library not loaded".
device_enumerate_processes(_) -> "NIF library not loaded".
device_enable_spawn_gating(_) -> "NIF library not loaded".
device_disable_spawn_gating(_) -> "NIF library not loaded".
device_enumerate_pending_spawn(_) -> "NIF library not loaded".
device_enumerate_pending_children(_) -> "NIF library not loaded".
device_spawn(_,_,_) -> "NIF library not loaded".
device_input(_,_) -> "NIF library not loaded".
device_resume(_,_) -> "NIF library not loaded".
device_kill(_,_) -> "NIF library not loaded".
device_attach(_,_) -> "NIF library not loaded".
device_inject_library_file(_,_,_,_,_) -> "NIF library not loaded".
device_inject_library_blob(_,_,_,_,_) -> "NIF library not loaded".

%/* ApplicationList */
application_list_size(_) -> "NIF library not loaded".
application_list_get(_,_) -> "NIF library not loaded".

%/* Application */
application_get_identifier(_) -> "NIF library not loaded".
application_get_name(_) -> "NIF library not loaded".
application_get_pid(_) -> "NIF library not loaded".
application_get_small_icon(_) -> "NIF library not loaded".
application_get_large_icon(_) -> "NIF library not loaded".

%/* ProcessList */
process_list_size(_) -> "NIF library not loaded".
process_list_get(_,_) -> "NIF library not loaded".

%/* Process */
process_get_pid(_) -> "NIF library not loaded".
process_get_name(_) -> "NIF library not loaded".
process_get_small_icon(_) -> "NIF library not loaded".
process_get_large_icon(_) -> "NIF library not loaded".

%/* SpawnOptions */
spawn_options_new() -> "NIF library not loaded".
spawn_options_get_argv(_) -> "NIF library not loaded".
spawn_options_get_envp(_) -> "NIF library not loaded".
spawn_options_get_env(_) -> "NIF library not loaded".
spawn_options_get_cwd(_) -> "NIF library not loaded".
spawn_options_get_stdio(_) -> "NIF library not loaded".
spawn_options_get_aux(_) -> "NIF library not loaded".

spawn_options_set_argv(_,_,_) -> "NIF library not loaded".
spawn_options_set_envp(_,_,_) -> "NIF library not loaded".
spawn_options_set_env(_,_,_) -> "NIF library not loaded".
spawn_options_set_cwd(_,_) -> "NIF library not loaded".
spawn_options_set_stdio(_,_) -> "NIF library not loaded".

%/* SpawnList */
spawn_list_size(_) -> "NIF library not loaded".
spawn_list_get(_,_) -> "NIF library not loaded".

%/* Spawn */
spawn_get_pid(_) -> "NIF library not loaded".
spawn_get_identifier(_) -> "NIF library not loaded".

%/* ChildList */
child_list_size(_) -> "NIF library not loaded".
child_list_get(_,_) -> "NIF library not loaded".

%/* Child */
child_get_pid(_) -> "NIF library not loaded".
child_get_parent_pid(_) -> "NIF library not loaded".
child_get_origin(_) -> "NIF library not loaded".
child_get_identifier(_) -> "NIF library not loaded".
child_get_path(_) -> "NIF library not loaded".
child_get_argv(_) -> "NIF library not loaded".
child_get_envp(_) -> "NIF library not loaded".

%/* Icon */
icon_get_width(_) -> "NIF library not loaded".
icon_get_height(_) -> "NIF library not loaded".
icon_get_rowstride(_) -> "NIF library not loaded".
icon_get_pixels(_) -> "NIF library not loaded".

%/* Session */
session_get_pid(_) -> "NIF library not loaded".
session_get_device(_) -> "NIF library not loaded".
session_is_detached(_) -> "NIF library not loaded".
session_detach(_) -> "NIF library not loaded".
session_enable_child_gating(_) -> "NIF library not loaded".
session_disable_child_gating(_) -> "NIF library not loaded".
session_create_script(_,_,_) -> "NIF library not loaded".
session_create_script_from_bytes(_,_) -> "NIF library not loaded".
session_compile_script(_,_,_) -> "NIF library not loaded".
session_enable_debugger(_,_) -> "NIF library not loaded".
session_disable_debugger(_) -> "NIF library not loaded".
session_enable_jit(_) -> "NIF library not loaded".

%/* Script */
script_get_id(_) -> "NIF library not loaded".
script_is_destroyed(_) -> "NIF library not loaded".
script_load(_) -> "NIF library not loaded".
script_unload(_) -> "NIF library not loaded".
script_eternalize(_) -> "NIF library not loaded".
script_post(_,_,_) -> "NIF library not loaded".

%/* Injector */
injector_new() -> "NIF library not loaded".
injector_new_inprocess() -> "NIF library not loaded".
injector_close(_) -> "NIF library not loaded".
injector_inject_library_file(_,_,_,_,_) -> "NIF library not loaded".
injector_inject_library_blob(_,_,_,_,_) -> "NIF library not loaded".
injector_demonitor_and_clone_state(_,_) -> "NIF library not loaded".
injector_recreate_thread(_,_,_) -> "NIF library not loaded".

%/* FileMonitor */
file_monitor_new(_) -> "NIF library not loaded".
file_monitor_get_path(_) -> "NIF library not loaded".
file_monitor_enable(_) -> "NIF library not loaded".
file_monitor_disable(_) -> "NIF library not loaded".

%Extra?
connect_signal_message(_,_) -> "NIF library not loaded".