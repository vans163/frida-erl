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
    FullPath = filename:join([Path, "build", "frida_nif_linux_x86_64"]),
    erlang:load_nif(FullPath, 0).

%/* Library lifetime */
init() -> "NIF library not loaded".
shutdown() -> "NIF library not loaded".
deinit() -> "NIF library not loaded".
get_main_context() -> "NIF library not loaded".

%/* Object lifetime */
unref(_) -> "NIF library not loaded".

%/* DeviceManager */
device_manager_new() -> "NIF library not loaded".
device_manager_close(_) -> "NIF library not loaded".
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

device_is_lost(_) -> "NIF library not loaded".
device_get_frontmost_application(_) -> "NIF library not loaded".
device_enumerate_applications(_) -> "NIF library not loaded".
device_get_process_by_pid(_,_) -> "NIF library not loaded".
device_get_process_by_name(_,_) -> "NIF library not loaded".
device_enumerate_processes(_) -> "NIF library not loaded".
device_attach(_,_) -> "NIF library not loaded".

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

%/* Session */
session_create_script(_,_,_) -> "NIF library not loaded".

%/* Script */
script_load(_) -> "NIF library not loaded".
script_unload(_) -> "NIF library not loaded".
script_post(_,_,_) -> "NIF library not loaded".

%Extra?
connect_signal_message(_,_) -> "NIF library not loaded".