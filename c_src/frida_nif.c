#include "erl_nif.h"
#include "frida-core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ERL_NIF_TERM mk_atom(ErlNifEnv* env, const char* atom)
{
    ERL_NIF_TERM ret;
    if(!enif_make_existing_atom(env, atom, &ret, ERL_NIF_LATIN1))
        return enif_make_atom(env, atom);
    return ret;
}

ERL_NIF_TERM mk_error(ErlNifEnv* env, const char* mesg)
{
    return enif_make_tuple2(env, mk_atom(env, "error"), mk_atom(env, mesg));
}

ERL_NIF_TERM mk_error_int(ErlNifEnv* env, unsigned long value)
{
    return enif_make_tuple2(env, mk_atom(env, "error"), enif_make_int64(env, value));
}

ERL_NIF_TERM mk_gerror(ErlNifEnv* env, GError* error)
{
    ErlNifBinary error_text;
    enif_alloc_binary(strlen(error->message), &error_text);
    memcpy(error_text.data, error->message, strlen(error->message));

    return enif_make_tuple2(env, 
        mk_atom(env, "error"), 
        enif_make_tuple2(env, enif_make_int(env, error->code), enif_make_binary(env, &error_text))
    );
}

ERL_NIF_TERM mk_ok_atom(ErlNifEnv* env, const char* atom)
{
    return enif_make_tuple2(env, mk_atom(env, "ok"), mk_atom(env, atom));
}

ERL_NIF_TERM mk_ok_int(ErlNifEnv* env, int value)
{
    return enif_make_tuple2(env, mk_atom(env, "ok"), enif_make_int(env, value));
}

ERL_NIF_TERM mk_ok_uint64(ErlNifEnv* env, unsigned long value)
{
    return enif_make_tuple2(env, mk_atom(env, "ok"), enif_make_uint64(env, value));
}

ERL_NIF_TERM mk_ok_binary(ErlNifEnv* env, const gchar* text, int size)
{
    ErlNifBinary bin_text;
    enif_alloc_binary(size, &bin_text);
    memcpy(bin_text.data, text, size);

    return enif_make_tuple2(env, 
        mk_atom(env, "ok"), 
        enif_make_binary(env, &bin_text)
    );
}

ERL_NIF_TERM mk_gboolean(ErlNifEnv* env, int boolean)
{
    if (boolean == 0) {
        return mk_atom(env, "false");
    } else {
        return mk_atom(env, "true");
    }
}

/* Library lifetime */
static ERL_NIF_TERM init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    frida_init();
    return mk_atom(env, "ok");
}
static ERL_NIF_TERM shutdown(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    frida_shutdown();
    return mk_atom(env, "ok");
}
static ERL_NIF_TERM deinit(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    frida_deinit();
    return mk_atom(env, "ok");
}
static ERL_NIF_TERM get_main_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long context = (unsigned long)frida_get_main_context();
    return enif_make_uint64(env, context);
}

/* Object lifetime */
static ERL_NIF_TERM unref(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_gpointer;
    if (!enif_get_ulong(env, argv[0], &p_gpointer))
        return mk_error(env, "not_a_number");

    frida_unref((gpointer)p_gpointer);
    return mk_atom(env, "ok");
}

/* DeviceManager */
static ERL_NIF_TERM device_manager_new(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long device_manager = (unsigned long)frida_device_manager_new();
    return enif_make_uint64(env, device_manager);
}
static ERL_NIF_TERM device_manager_close(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDeviceManager;
    if (!enif_get_ulong(env, argv[0], &p_FridaDeviceManager))
        return mk_error(env, "not_a_number");

    frida_device_manager_close_sync((FridaDeviceManager*)p_FridaDeviceManager);
    frida_unref((FridaDeviceManager*)p_FridaDeviceManager);
    return mk_atom(env, "ok");
}
static ERL_NIF_TERM device_manager_enumerate_devices(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDeviceManager;
    if (!enif_get_ulong(env, argv[0], &p_FridaDeviceManager))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* device = (void*)frida_device_manager_enumerate_devices_sync((FridaDeviceManager*)p_FridaDeviceManager, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)device);
    }
}
static ERL_NIF_TERM device_manager_add_remote_device(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDeviceManager;
    if (!enif_get_ulong(env, argv[0], &p_FridaDeviceManager))
        return mk_error(env, "not_a_number");
    ErlNifBinary host;
    if (!enif_inspect_binary(env, argv[1], &host))
        return mk_error(env, "not_a_binary");

    GError* error = NULL;
    void* device = (void*)frida_device_manager_add_remote_device_sync((FridaDeviceManager*)p_FridaDeviceManager, (const gchar*)host.data, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)device);
    }
}
static ERL_NIF_TERM device_manager_remove_remote_device(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDeviceManager;
    if (!enif_get_ulong(env, argv[0], &p_FridaDeviceManager))
        return mk_error(env, "not_a_number");
    ErlNifBinary host;
    if (!enif_inspect_binary(env, argv[1], &host))
        return mk_error(env, "not_a_binary");

    GError* error = NULL;
    frida_device_manager_remove_remote_device_sync((FridaDeviceManager*)p_FridaDeviceManager, (const gchar*)host.data, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}

/* DeviceList */
static ERL_NIF_TERM device_list_size(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDeviceList;
    if (!enif_get_ulong(env, argv[0], &p_FridaDeviceList))
        return mk_error(env, "not_a_number");

    int size = (int)frida_device_list_size((FridaDeviceList*)p_FridaDeviceList);
    return enif_make_int(env, size);
}
static ERL_NIF_TERM device_list_get(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDeviceList;
    if (!enif_get_ulong(env, argv[0], &p_FridaDeviceList))
        return mk_error(env, "not_a_number");
    unsigned long index;
    if (!enif_get_ulong(env, argv[1], &index))
        return mk_error(env, "not_a_number");

    unsigned long device = (unsigned long)frida_device_list_get((FridaDeviceList*)p_FridaDeviceList, index);
    return enif_make_uint64(env, device);
}


/* Device */
static ERL_NIF_TERM device_get_id(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");

    const gchar* id = frida_device_get_id((FridaDevice*)p_FridaDevice);

    ErlNifBinary bin_text;
    enif_alloc_binary(strlen(id), &bin_text);
    memcpy(bin_text.data, id, strlen(id));

    return enif_make_binary(env, &bin_text);
}
static ERL_NIF_TERM device_get_name(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");

    const gchar* name = frida_device_get_name((FridaDevice*)p_FridaDevice);

    ErlNifBinary bin_text;
    enif_alloc_binary(strlen(name), &bin_text);
    memcpy(bin_text.data, name, strlen(name));

    return enif_make_binary(env, &bin_text);
}
static ERL_NIF_TERM device_get_icon(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");

    unsigned long icon = (unsigned long)frida_device_get_icon((FridaDevice*)p_FridaDevice);
    return enif_make_uint64(env, icon);
}
static ERL_NIF_TERM device_get_dtype(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");

    FridaDeviceType dtype = frida_device_get_dtype((FridaDevice*)p_FridaDevice);
    if (dtype == FRIDA_DEVICE_TYPE_LOCAL) {
        return mk_atom(env, "local");
    } else if (dtype == FRIDA_DEVICE_TYPE_TETHER) {
        return mk_atom(env, "tether");
    } else { //FRIDA_DEVICE_TYPE_REMOTE
        return mk_atom(env, "remote");
    }
}

static ERL_NIF_TERM device_is_lost(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");

    int is_lost = (int)frida_device_is_lost((FridaDevice*)p_FridaDevice);
    return mk_gboolean(env, is_lost);
}
static ERL_NIF_TERM device_get_frontmost_application(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* app = (void*)frida_device_get_frontmost_application_sync((FridaDevice*)p_FridaDevice, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)app);
    }
}
static ERL_NIF_TERM device_enumerate_applications(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* applist = (void*)frida_device_enumerate_applications_sync((FridaDevice*)p_FridaDevice, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)applist);
    }
}
static ERL_NIF_TERM device_get_process_by_pid(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");
    unsigned long pid;
    if (!enif_get_ulong(env, argv[1], &pid))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* proc = (void*)frida_device_get_process_by_pid_sync((FridaDevice*)p_FridaDevice, pid, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)proc);
    }
}
static ERL_NIF_TERM device_get_process_by_name(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");
    ErlNifBinary name;
    if (!enif_inspect_binary(env, argv[1], &name))
        return mk_error(env, "not_a_binary");

    GError* error = NULL;
    void* proc = (void*)frida_device_get_process_by_name_sync((FridaDevice*)p_FridaDevice, (const gchar*)name.data, 1, NULL, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)proc);
    }
}
static ERL_NIF_TERM device_enumerate_processes(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* proclist = (void*)frida_device_enumerate_processes_sync((FridaDevice*)p_FridaDevice, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)proclist);
    }
}
static ERL_NIF_TERM device_attach(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");
    unsigned long pid;
    if (!enif_get_ulong(env, argv[1], &pid))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* session = (void*)frida_device_attach_sync((FridaDevice*)p_FridaDevice, pid, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)session);
    }
}


/* ApplicationList */
static ERL_NIF_TERM application_list_size(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaApplicationList;
    if (!enif_get_ulong(env, argv[0], &p_FridaApplicationList))
        return mk_error(env, "not_a_number");

    int size = (int)frida_application_list_size((FridaApplicationList*)p_FridaApplicationList);
    return enif_make_int(env, size);
}
static ERL_NIF_TERM application_list_get(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaApplicationList;
    if (!enif_get_ulong(env, argv[0], &p_FridaApplicationList))
        return mk_error(env, "not_a_number");
    unsigned long index;
    if (!enif_get_ulong(env, argv[1], &index))
        return mk_error(env, "not_a_number");

    unsigned long app = (unsigned long)frida_application_list_get((FridaApplicationList*)p_FridaApplicationList, index);
    return enif_make_uint64(env, app);
}


/* Application */
static ERL_NIF_TERM application_get_identifier(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaApplication;
    if (!enif_get_ulong(env, argv[0], &p_FridaApplication))
        return mk_error(env, "not_a_number");

    const gchar* identifier = frida_application_get_identifier((FridaApplication*)p_FridaApplication);

    ErlNifBinary bin_text;
    enif_alloc_binary(strlen(identifier), &bin_text);
    memcpy(bin_text.data, identifier, strlen(identifier));

    return enif_make_binary(env, &bin_text);
}
static ERL_NIF_TERM application_get_name(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaApplication;
    if (!enif_get_ulong(env, argv[0], &p_FridaApplication))
        return mk_error(env, "not_a_number");

    const gchar* name = frida_application_get_name((FridaApplication*)p_FridaApplication);

    ErlNifBinary bin_text;
    enif_alloc_binary(strlen(name), &bin_text);
    memcpy(bin_text.data, name, strlen(name));

    return enif_make_binary(env, &bin_text);
}
static ERL_NIF_TERM application_get_pid(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaApplication;
    if (!enif_get_ulong(env, argv[0], &p_FridaApplication))
        return mk_error(env, "not_a_number");

    unsigned long pid = (unsigned long)frida_application_get_pid((FridaApplication*)p_FridaApplication);
    return enif_make_uint64(env, pid);
}
static ERL_NIF_TERM application_get_small_icon(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaApplication;
    if (!enif_get_ulong(env, argv[0], &p_FridaApplication))
        return mk_error(env, "not_a_number");

    unsigned long icon = (unsigned long)frida_application_get_small_icon((FridaApplication*)p_FridaApplication);
    return enif_make_uint64(env, icon);
}
static ERL_NIF_TERM application_get_large_icon(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaApplication;
    if (!enif_get_ulong(env, argv[0], &p_FridaApplication))
        return mk_error(env, "not_a_number");

    unsigned long icon = (unsigned long)frida_application_get_large_icon((FridaApplication*)p_FridaApplication);
    return enif_make_uint64(env, icon);
}


/* ProcessList */
static ERL_NIF_TERM process_list_size(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaProcessList;
    if (!enif_get_ulong(env, argv[0], &p_FridaProcessList))
        return mk_error(env, "not_a_number");

    int size = (int)frida_process_list_size((FridaProcessList*)p_FridaProcessList);
    return enif_make_int(env, size);
}
static ERL_NIF_TERM process_list_get(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaProcessList;
    if (!enif_get_ulong(env, argv[0], &p_FridaProcessList))
        return mk_error(env, "not_a_number");
    unsigned long index;
    if (!enif_get_ulong(env, argv[1], &index))
        return mk_error(env, "not_a_number");

    unsigned long proc = (unsigned long)frida_process_list_get((FridaProcessList*)p_FridaProcessList, index);
    return enif_make_uint64(env, proc);
}


/* Process */
static ERL_NIF_TERM process_get_pid(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaProcess;
    if (!enif_get_ulong(env, argv[0], &p_FridaProcess))
        return mk_error(env, "not_a_number");

    unsigned long pid = (unsigned long)frida_process_get_pid((FridaProcess*)p_FridaProcess);
    return enif_make_uint64(env, pid);
}
static ERL_NIF_TERM process_get_name(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaProcess;
    if (!enif_get_ulong(env, argv[0], &p_FridaProcess))
        return mk_error(env, "not_a_number");

    const gchar* name = frida_process_get_name((FridaProcess*)p_FridaProcess);

    ErlNifBinary bin_text;
    enif_alloc_binary(strlen(name), &bin_text);
    memcpy(bin_text.data, name, strlen(name));

    return enif_make_binary(env, &bin_text);
}
static ERL_NIF_TERM process_get_small_icon(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaProcess;
    if (!enif_get_ulong(env, argv[0], &p_FridaProcess))
        return mk_error(env, "not_a_number");

    unsigned long icon = (unsigned long)frida_process_get_small_icon((FridaProcess*)p_FridaProcess);
    return enif_make_uint64(env, icon);
}
static ERL_NIF_TERM process_get_large_icon(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaProcess;
    if (!enif_get_ulong(env, argv[0], &p_FridaProcess))
        return mk_error(env, "not_a_number");

    unsigned long icon = (unsigned long)frida_process_get_large_icon((FridaProcess*)p_FridaProcess);
    return enif_make_int64(env, icon);
}


/* Session */
static ERL_NIF_TERM session_create_script(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSession;
    if (!enif_get_ulong(env, argv[0], &p_FridaSession))
        return mk_error(env, "not_a_number");
    ErlNifBinary name;
    if (!enif_inspect_binary(env, argv[1], &name))
        return mk_error(env, "not_a_binary");
    ErlNifBinary source;
    if (!enif_inspect_binary(env, argv[2], &source))
        return mk_error(env, "not_a_binary");

    GError* error = NULL;
    void* script = (void*)frida_session_create_script_sync((FridaSession*)p_FridaSession, (const gchar*)name.data, (const gchar*)source.data, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)script);
    }
}


/* Script */
static ERL_NIF_TERM script_load(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaScript;
    if (!enif_get_ulong(env, argv[0], &p_FridaScript))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_script_load_sync((FridaScript*)p_FridaScript, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}
static ERL_NIF_TERM script_unload(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaScript;
    if (!enif_get_ulong(env, argv[0], &p_FridaScript))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_script_unload_sync((FridaScript*)p_FridaScript, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}
static ERL_NIF_TERM script_post(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaScript;
    if (!enif_get_ulong(env, argv[0], &p_FridaScript))
        return mk_error(env, "not_a_number");
    ErlNifBinary message;
    if (!enif_inspect_binary(env, argv[1], &message))
        return mk_error(env, "not_a_binary");
    ErlNifBinary bytes;
    if (!enif_inspect_binary(env, argv[2], &bytes))
        return mk_error(env, "not_a_binary");

    GBytes* gbytes = g_bytes_new(bytes.data, bytes.size);
    GError* error = NULL;
    frida_script_post_sync((FridaScript*)p_FridaScript, (const gchar*)message.data, gbytes, &error);
    g_bytes_unref(gbytes);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}

/* Extra? */
static void on_message(FridaScript* script, const gchar* message, GBytes* data, gpointer user_data)
{
    ErlNifPid* my_pid = (ErlNifPid*)user_data;

    ErlNifBinary bin_message;
    enif_alloc_binary(strlen(message), &bin_message);
    memcpy(bin_message.data, message, strlen(message));

    ErlNifBinary bin_data;
    if (data == NULL) {
        enif_alloc_binary(0, &bin_data);
    } else {
        unsigned long data_size = g_bytes_get_size(data);
        enif_alloc_binary(data_size, &bin_data);
        memcpy(bin_data.data, (char*)g_bytes_get_data(data, &data_size), data_size);
    }

    ErlNifEnv* msg_env = enif_alloc_env();

    ERL_NIF_TERM term = enif_make_tuple4(msg_env, 
        mk_atom(msg_env, "script_message"), 
        enif_make_uint64(msg_env, (unsigned long)script),
        enif_make_binary(msg_env, &bin_message),
        enif_make_binary(msg_env, &bin_data)
    );

    //Threadsafe??
    enif_send(NULL, my_pid, msg_env, term);
    enif_free_env(msg_env);
}

static ERL_NIF_TERM connect_signal_message(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaScript;
    if (!enif_get_ulong(env, argv[0], &p_FridaScript))
        return mk_error(env, "not_a_number");
    ErlNifPid pid;
    if (!enif_get_local_pid(env, argv[1], &pid))
        return mk_error(env, "not_a_pid");

    //This leaks, since we dont know when to clean, screw it?
    ErlNifPid* p_Pid = g_slice_dup(ErlNifPid, &pid);

    g_signal_connect((FridaScript*)p_FridaScript, "message", G_CALLBACK (on_message), p_Pid);
    return mk_atom(env, "ok");
}

int upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

static ErlNifFunc nif_funcs[] = {
    /* Library lifetime */
    {"init", 0, init},
    {"shutdown", 0, shutdown},
    {"deinit", 0, deinit},
    {"get_main_context", 0, get_main_context},

    /* Object lifetime */
    {"unref", 1, unref},

    /* DeviceManager */
    {"device_manager_new", 0, device_manager_new},
    {"device_manager_close", 1, device_manager_close},
    {"device_manager_enumerate_devices", 1, device_manager_enumerate_devices},
    {"device_manager_add_remote_device", 2, device_manager_add_remote_device},
    {"device_manager_remove_remote_device", 2, device_manager_remove_remote_device},

    /* DeviceList */
    {"device_list_size", 1, device_list_size},
    {"device_list_get", 2, device_list_get},

    /* Device */
    {"device_get_id", 1, device_get_id},
    {"device_get_name", 1, device_get_name},
    {"device_get_icon", 1, device_get_icon},
    {"device_get_dtype", 1, device_get_dtype},

    {"device_is_lost", 1, device_is_lost},
    {"device_get_frontmost_application", 1, device_get_frontmost_application},
    {"device_enumerate_applications", 1, device_enumerate_applications},
    {"device_get_process_by_pid", 2, device_get_process_by_pid},
    {"device_get_process_by_name", 2, device_get_process_by_name},
    {"device_enumerate_processes", 1, device_enumerate_processes},
    {"device_attach", 2, device_attach},

    /* ApplicationList */
    {"application_list_size", 1, application_list_size},
    {"application_list_get", 2, application_list_get},

    /* Application */
    {"application_get_identifier", 1, application_get_identifier},
    {"application_get_name", 1, application_get_name},
    {"application_get_pid", 1, application_get_pid},
    {"application_get_small_icon", 1, application_get_small_icon},
    {"application_get_large_icon", 1, application_get_large_icon},

    /* ProcessList */
    {"process_list_size", 1, process_list_size},
    {"process_list_get", 2, process_list_get},

    /* Process */
    {"process_get_pid", 1, process_get_pid},
    {"process_get_name", 1, process_get_name},
    {"process_get_small_icon", 1, process_get_small_icon},
    {"process_get_large_icon", 1, process_get_large_icon},

    /* Session */
    {"session_create_script", 3, session_create_script},

    /* Script */
    {"script_load", 1, script_load},
    {"script_unload", 1, script_unload},
    {"script_post", 3, script_post},

    /* Extra? */
    {"connect_signal_message", 2, connect_signal_message},
};


ERL_NIF_INIT(frida_nif, nif_funcs, NULL, NULL, &upgrade, NULL)