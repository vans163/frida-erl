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

/* Library versioning */
static ERL_NIF_TERM version(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    guint major, minor, micro, nano;
    frida_version(&major, &minor, &micro, &nano);
    return enif_make_tuple4(env, 
        enif_make_int(env, major),
        enif_make_int(env, minor),
        enif_make_int(env, micro),
        enif_make_int(env, nano)
    );
}
static ERL_NIF_TERM version_string(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    const gchar* bin = frida_version_string();
    
    ErlNifBinary bin_text;
    enif_alloc_binary(strlen(bin), &bin_text);
    memcpy(bin_text.data, bin, strlen(bin));

    return enif_make_binary(env, &bin_text);
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
static ERL_NIF_TERM device_manager_get_device_by_id(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDeviceManager;
    if (!enif_get_ulong(env, argv[0], &p_FridaDeviceManager))
        return mk_error(env, "not_a_number");
    ErlNifBinary id;
    if (!enif_inspect_binary(env, argv[1], &id))
        return mk_error(env, "not_a_binary");
    unsigned long timeout;
    if (!enif_get_ulong(env, argv[2], &timeout))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* device = (void*)frida_device_manager_get_device_by_id_sync((FridaDeviceManager*)p_FridaDeviceManager, (const gchar*)id.data, timeout, NULL, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)device);
    }
}
static ERL_NIF_TERM device_manager_get_device_by_type(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDeviceManager;
    if (!enif_get_ulong(env, argv[0], &p_FridaDeviceManager))
        return mk_error(env, "not_a_number");
    unsigned long dev_type;
    if (!enif_get_ulong(env, argv[1], &dev_type))
        return mk_error(env, "not_a_number");
    unsigned long timeout;
    if (!enif_get_ulong(env, argv[2], &timeout))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* device = (void*)frida_device_manager_get_device_by_type_sync((FridaDeviceManager*)p_FridaDeviceManager, dev_type, timeout, NULL, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)device);
    }
}
static ERL_NIF_TERM device_manager_get_device(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM device_manager_find_device_by_id(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDeviceManager;
    if (!enif_get_ulong(env, argv[0], &p_FridaDeviceManager))
        return mk_error(env, "not_a_number");
    ErlNifBinary id;
    if (!enif_inspect_binary(env, argv[1], &id))
        return mk_error(env, "not_a_binary");
    unsigned long timeout;
    if (!enif_get_ulong(env, argv[2], &timeout))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* device = (void*)frida_device_manager_find_device_by_id_sync((FridaDeviceManager*)p_FridaDeviceManager, (const gchar*)id.data, timeout, NULL, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)device);
    }
}
static ERL_NIF_TERM device_manager_find_device_by_type(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDeviceManager;
    if (!enif_get_ulong(env, argv[0], &p_FridaDeviceManager))
        return mk_error(env, "not_a_number");
    unsigned long dev_type;
    if (!enif_get_ulong(env, argv[1], &dev_type))
        return mk_error(env, "not_a_number");
    unsigned long timeout;
    if (!enif_get_ulong(env, argv[2], &timeout))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* device = (void*)frida_device_manager_find_device_by_type_sync((FridaDeviceManager*)p_FridaDeviceManager, dev_type, timeout, NULL, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)device);
    }
}
static ERL_NIF_TERM device_manager_find_device(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
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
    } else if (dtype == FRIDA_DEVICE_TYPE_REMOTE) {
        return mk_atom(env, "remote");
    } else { //FRIDA_DEVICE_TYPE_USB
        return mk_atom(env, "usb");
    }
}
static ERL_NIF_TERM device_get_manager(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");

    unsigned long deviceMan = (unsigned long)frida_device_get_manager((FridaDevice*)p_FridaDevice);
    return enif_make_uint64(env, deviceMan);
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
    unsigned long timeout;
    if (!enif_get_ulong(env, argv[2], &timeout))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* proc = (void*)frida_device_get_process_by_name_sync((FridaDevice*)p_FridaDevice, (const gchar*)name.data, timeout, NULL, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)proc);
    }
}
static ERL_NIF_TERM device_get_process(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM device_find_process_by_pid(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");
    unsigned long pid;
    if (!enif_get_ulong(env, argv[1], &pid))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* proc = (void*)frida_device_find_process_by_pid_sync((FridaDevice*)p_FridaDevice, pid, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)proc);
    }
}
static ERL_NIF_TERM device_find_process_by_name(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");
    ErlNifBinary name;
    if (!enif_inspect_binary(env, argv[1], &name))
        return mk_error(env, "not_a_binary");
    unsigned long timeout;
    if (!enif_get_ulong(env, argv[2], &timeout))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* proc = (void*)frida_device_find_process_by_name_sync((FridaDevice*)p_FridaDevice, (const gchar*)name.data, timeout, NULL, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)proc);
    }
}
static ERL_NIF_TERM device_find_process(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
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
static ERL_NIF_TERM device_enable_spawn_gating(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_device_enable_spawn_gating_sync((FridaDevice*)p_FridaDevice, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}
static ERL_NIF_TERM device_disable_spawn_gating(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_device_disable_spawn_gating_sync((FridaDevice*)p_FridaDevice, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}
static ERL_NIF_TERM device_enumerate_pending_spawn(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* spawnlist = (void*)frida_device_enumerate_pending_spawn_sync((FridaDevice*)p_FridaDevice, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)spawnlist);
    }
}
static ERL_NIF_TERM device_enumerate_pending_children(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    void* childlist = (void*)frida_device_enumerate_pending_children_sync((FridaDevice*)p_FridaDevice, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)childlist);
    }
}
static ERL_NIF_TERM device_spawn(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");
    ErlNifBinary program;
    if (!enif_inspect_binary(env, argv[1], &program))
        return mk_error(env, "not_a_binary");
    unsigned long p_spawn_opts;
    if (!enif_get_ulong(env, argv[2], &p_spawn_opts))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    guint spawn_res = frida_device_spawn_sync((FridaDevice*)p_FridaDevice, (const gchar*)program.data, (FridaSpawnOptions*)p_spawn_opts, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)spawn_res);
    }
}
static ERL_NIF_TERM device_input(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");
    unsigned long pid;
    if (!enif_get_ulong(env, argv[1], &pid))
        return mk_error(env, "not_a_number");
    ErlNifBinary bytes;
    if (!enif_inspect_binary(env, argv[2], &bytes))
        return mk_error(env, "not_a_binary");

    GBytes* gbytes = g_bytes_new(bytes.data, bytes.size);

    GError* error = NULL;
    frida_device_input_sync((FridaDevice*)p_FridaDevice, (guint)pid, gbytes, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}
static ERL_NIF_TERM device_resume(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");
    unsigned long pid;
    if (!enif_get_ulong(env, argv[1], &pid))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_device_resume_sync((FridaDevice*)p_FridaDevice, (guint)pid, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}
static ERL_NIF_TERM device_kill(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");
    unsigned long pid;
    if (!enif_get_ulong(env, argv[1], &pid))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_device_kill_sync((FridaDevice*)p_FridaDevice, (guint)pid, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
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
static ERL_NIF_TERM device_inject_library_file(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");
    unsigned long pid;
    if (!enif_get_ulong(env, argv[1], &pid))
        return mk_error(env, "not_a_number");
    ErlNifBinary path;
    if (!enif_inspect_binary(env, argv[2], &path))
        return mk_error(env, "not_a_binary");
    ErlNifBinary entry;
    if (!enif_inspect_binary(env, argv[3], &entry))
        return mk_error(env, "not_a_binary");
    ErlNifBinary data;
    if (!enif_inspect_binary(env, argv[4], &data))
        return mk_error(env, "not_a_binary");

    GError* error = NULL;
    guint res = frida_device_inject_library_file_sync((FridaDevice*)p_FridaDevice, pid, (const gchar*)path.data, (const gchar*)entry.data, (const gchar*)data.data, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)res);
    }
}
static ERL_NIF_TERM device_inject_library_blob(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaDevice;
    if (!enif_get_ulong(env, argv[0], &p_FridaDevice))
        return mk_error(env, "not_a_number");
    unsigned long pid;
    if (!enif_get_ulong(env, argv[1], &pid))
        return mk_error(env, "not_a_number");

    ErlNifBinary blob;
    if (!enif_inspect_binary(env, argv[2], &blob))
        return mk_error(env, "not_a_binary");
    GBytes* gblob = g_bytes_new(blob.data, blob.size);

    ErlNifBinary entry;
    if (!enif_inspect_binary(env, argv[3], &entry))
        return mk_error(env, "not_a_binary");
    ErlNifBinary data;
    if (!enif_inspect_binary(env, argv[4], &data))
        return mk_error(env, "not_a_binary");

    GError* error = NULL;
    guint res = frida_device_inject_library_blob_sync((FridaDevice*)p_FridaDevice, pid, gblob, (const gchar*)entry.data, (const gchar*)data.data, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)res);
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

/* SpawnOptions */
static ERL_NIF_TERM spawn_options_new(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long spawn_opt = (unsigned long)frida_spawn_options_new();
    return enif_make_int64(env, spawn_opt);
}
static ERL_NIF_TERM spawn_options_get_argv(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM spawn_options_get_envp(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM spawn_options_get_env(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM spawn_options_get_cwd(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM spawn_options_get_stdio(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM spawn_options_get_aux(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}

static ERL_NIF_TERM spawn_options_set_argv(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM spawn_options_set_envp(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM spawn_options_set_env(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM spawn_options_set_cwd(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM spawn_options_set_stdio(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}

/* SpawnList */
static ERL_NIF_TERM spawn_list_size(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSpawnList;
    if (!enif_get_ulong(env, argv[0], &p_FridaSpawnList))
        return mk_error(env, "not_a_number");

    gint size = frida_spawn_list_size((FridaSpawnList*)p_FridaSpawnList);
    return enif_make_int(env, (int)size);
}
static ERL_NIF_TERM spawn_list_get(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSpawnList;
    if (!enif_get_ulong(env, argv[0], &p_FridaSpawnList))
        return mk_error(env, "not_a_number");
    unsigned long index;
    if (!enif_get_ulong(env, argv[1], &index))
        return mk_error(env, "not_a_number");

    unsigned long p_FridaSpawn = (unsigned long)frida_spawn_list_get((FridaSpawnList*)p_FridaSpawnList, index);
    return enif_make_int64(env, p_FridaSpawn);
}

/* Spawn */
static ERL_NIF_TERM spawn_get_pid(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSpawn;
    if (!enif_get_ulong(env, argv[0], &p_FridaSpawn))
        return mk_error(env, "not_a_number");

    guint pid = frida_spawn_get_pid((FridaSpawn*)p_FridaSpawn);
    return enif_make_uint(env, (uint)pid);
}
static ERL_NIF_TERM spawn_get_identifier(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSpawn;
    if (!enif_get_ulong(env, argv[0], &p_FridaSpawn))
        return mk_error(env, "not_a_number");

    const gchar* id = frida_spawn_get_identifier((FridaSpawn*)p_FridaSpawn);

    ErlNifBinary bin_text;
    enif_alloc_binary(strlen(id), &bin_text);
    memcpy(bin_text.data, id, strlen(id));

    return enif_make_binary(env, &bin_text);
}

/* ChildList */
static ERL_NIF_TERM child_list_size(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaChildList;
    if (!enif_get_ulong(env, argv[0], &p_FridaChildList))
        return mk_error(env, "not_a_number");

    gint size = frida_child_list_size((FridaChildList*)p_FridaChildList);
    return enif_make_int(env, (int)size);
}
static ERL_NIF_TERM child_list_get(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaChildList;
    if (!enif_get_ulong(env, argv[0], &p_FridaChildList))
        return mk_error(env, "not_a_number");
    unsigned long index;
    if (!enif_get_ulong(env, argv[1], &index))
        return mk_error(env, "not_a_number");

    unsigned long p_FridaChild = (unsigned long)frida_child_list_get((FridaChildList*)p_FridaChildList, index);
    return enif_make_int64(env, p_FridaChild);
}

/* Child */
static ERL_NIF_TERM child_get_pid(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaChild;
    if (!enif_get_ulong(env, argv[0], &p_FridaChild))
        return mk_error(env, "not_a_number");

    guint pid = frida_child_get_pid((FridaChild*)p_FridaChild);
    return enif_make_uint(env, (uint)pid);
}
static ERL_NIF_TERM child_get_parent_pid(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaChild;
    if (!enif_get_ulong(env, argv[0], &p_FridaChild))
        return mk_error(env, "not_a_number");

    guint pid = frida_child_get_parent_pid((FridaChild*)p_FridaChild);
    return enif_make_uint(env, (uint)pid);
}
static ERL_NIF_TERM child_get_origin(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM child_get_identifier(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM child_get_path(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM child_get_argv(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}
static ERL_NIF_TERM child_get_envp(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}

/* Icon */
static ERL_NIF_TERM icon_get_width(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaIcon;
    if (!enif_get_ulong(env, argv[0], &p_FridaIcon))
        return mk_error(env, "not_a_number");

    gint width = frida_icon_get_width((FridaIcon*)p_FridaIcon);
    return enif_make_int(env, (int)width);
}
static ERL_NIF_TERM icon_get_height(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaIcon;
    if (!enif_get_ulong(env, argv[0], &p_FridaIcon))
        return mk_error(env, "not_a_number");

    gint height = frida_icon_get_height((FridaIcon*)p_FridaIcon);
    return enif_make_int(env, (int)height);
}
static ERL_NIF_TERM icon_get_rowstride(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaIcon;
    if (!enif_get_ulong(env, argv[0], &p_FridaIcon))
        return mk_error(env, "not_a_number");

    gint rowstride = frida_icon_get_rowstride((FridaIcon*)p_FridaIcon);
    return enif_make_int(env, (int)rowstride);
}
static ERL_NIF_TERM icon_get_pixels(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return mk_error(env, "not_implemented");
}

/* Session */
static ERL_NIF_TERM session_get_pid(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSession;
    if (!enif_get_ulong(env, argv[0], &p_FridaSession))
        return mk_error(env, "not_a_number");

    guint pid = frida_session_get_pid((FridaSession*)p_FridaSession);
    return enif_make_int(env, (uint)pid);
}
static ERL_NIF_TERM session_get_device(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSession;
    if (!enif_get_ulong(env, argv[0], &p_FridaSession))
        return mk_error(env, "not_a_number");

    unsigned long p_FridaDevice = (unsigned long)frida_session_get_device((FridaSession*)p_FridaSession);
    return enif_make_int64(env, p_FridaDevice);    
}
static ERL_NIF_TERM session_is_detached(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSession;
    if (!enif_get_ulong(env, argv[0], &p_FridaSession))
        return mk_error(env, "not_a_number");

    int is_lost = (int)frida_session_is_detached((FridaSession*)p_FridaSession);
    return mk_gboolean(env, is_lost);
}
static ERL_NIF_TERM session_detach(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSession;
    if (!enif_get_ulong(env, argv[0], &p_FridaSession))
        return mk_error(env, "not_a_number");

    frida_session_detach_sync((FridaSession*)p_FridaSession);
    return mk_atom(env, "ok");
}
static ERL_NIF_TERM session_enable_child_gating(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSession;
    if (!enif_get_ulong(env, argv[0], &p_FridaSession))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_session_enable_child_gating_sync((FridaSession*)p_FridaSession, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}
static ERL_NIF_TERM session_disable_child_gating(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSession;
    if (!enif_get_ulong(env, argv[0], &p_FridaSession))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_session_disable_child_gating_sync((FridaSession*)p_FridaSession, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}
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
static ERL_NIF_TERM session_create_script_from_bytes(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSession;
    if (!enif_get_ulong(env, argv[0], &p_FridaSession))
        return mk_error(env, "not_a_number");
    ErlNifBinary bytes;
    if (!enif_inspect_binary(env, argv[1], &bytes))
        return mk_error(env, "not_a_binary");

    GBytes* gbytes = g_bytes_new(bytes.data, bytes.size);

    GError* error = NULL;
    void* script = (void*)frida_session_create_script_from_bytes_sync((FridaSession*)p_FridaSession, gbytes, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)script);
    }
}
static ERL_NIF_TERM session_compile_script(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
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
    GBytes* gbytes = frida_session_compile_script_sync((FridaSession*)p_FridaSession, (const gchar*)name.data, (const gchar*)source.data, &error);

    gsize size;
    gconstpointer data = g_bytes_get_data(gbytes, &size);

    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_binary(env, (const char*)data, size);
    }
}
static ERL_NIF_TERM session_enable_debugger(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSession;
    if (!enif_get_ulong(env, argv[0], &p_FridaSession))
        return mk_error(env, "not_a_number");
    unsigned long port;
    if (!enif_get_ulong(env, argv[1], &port))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_session_enable_debugger_sync((FridaSession*)p_FridaSession, port, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}
static ERL_NIF_TERM session_disable_debugger(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSession;
    if (!enif_get_ulong(env, argv[0], &p_FridaSession))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_session_disable_debugger_sync((FridaSession*)p_FridaSession, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}
static ERL_NIF_TERM session_enable_jit(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaSession;
    if (!enif_get_ulong(env, argv[0], &p_FridaSession))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_session_enable_jit_sync((FridaSession*)p_FridaSession, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}

/* Script */
static ERL_NIF_TERM script_get_id(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaScript;
    if (!enif_get_ulong(env, argv[0], &p_FridaScript))
        return mk_error(env, "not_a_number");

    uint id = (uint)frida_script_get_id((FridaScript*)p_FridaScript);
    return enif_make_uint64(env, id);
}
static ERL_NIF_TERM script_is_destroyed(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaScript;
    if (!enif_get_ulong(env, argv[0], &p_FridaScript))
        return mk_error(env, "not_a_number");

    int is_lost = (int)frida_script_is_destroyed((FridaScript*)p_FridaScript);
    return mk_gboolean(env, is_lost);
}
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
static ERL_NIF_TERM script_eternalize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaScript;
    if (!enif_get_ulong(env, argv[0], &p_FridaScript))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_script_eternalize_sync((FridaScript*)p_FridaScript, &error);
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

/* Injector */
static ERL_NIF_TERM injector_new(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long injector = (unsigned long)frida_injector_new();
    return enif_make_int64(env, injector);
}
static ERL_NIF_TERM injector_new_inprocess(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long injector = (unsigned long)frida_injector_new_inprocess();
    return enif_make_int64(env, injector);
}
static ERL_NIF_TERM injector_close(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaInjector;
    if (!enif_get_ulong(env, argv[0], &p_FridaInjector))
        return mk_error(env, "not_a_number");

    frida_injector_close_sync((FridaInjector*)p_FridaInjector);
    frida_unref((FridaInjector*)p_FridaInjector);
    return mk_atom(env, "ok");
}
static ERL_NIF_TERM injector_inject_library_file(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaInjector;
    if (!enif_get_ulong(env, argv[0], &p_FridaInjector))
        return mk_error(env, "not_a_number");
    unsigned long pid;
    if (!enif_get_ulong(env, argv[1], &pid))
        return mk_error(env, "not_a_number");
    ErlNifBinary path;
    if (!enif_inspect_binary(env, argv[2], &path))
        return mk_error(env, "not_a_binary");
    ErlNifBinary entry;
    if (!enif_inspect_binary(env, argv[3], &entry))
        return mk_error(env, "not_a_binary");
    ErlNifBinary data;
    if (!enif_inspect_binary(env, argv[4], &data))
        return mk_error(env, "not_a_binary");

    GError* error = NULL;
    guint res = frida_injector_inject_library_file_sync((FridaInjector*)p_FridaInjector, pid, (const gchar*)path.data, (const gchar*)entry.data, (const gchar*)data.data, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)res);
    }
}
static ERL_NIF_TERM injector_inject_library_blob(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaInjector;
    if (!enif_get_ulong(env, argv[0], &p_FridaInjector))
        return mk_error(env, "not_a_number");
    unsigned long pid;
    if (!enif_get_ulong(env, argv[1], &pid))
        return mk_error(env, "not_a_number");

    ErlNifBinary blob;
    if (!enif_inspect_binary(env, argv[2], &blob))
        return mk_error(env, "not_a_binary");
    GBytes* gblob = g_bytes_new(blob.data, blob.size);

    ErlNifBinary entry;
    if (!enif_inspect_binary(env, argv[3], &entry))
        return mk_error(env, "not_a_binary");
    ErlNifBinary data;
    if (!enif_inspect_binary(env, argv[4], &data))
        return mk_error(env, "not_a_binary");

    GError* error = NULL;
    guint res = frida_injector_inject_library_blob_sync((FridaInjector*)p_FridaInjector, pid, gblob, (const gchar*)entry.data, (const gchar*)data.data, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)res);
    }
}
static ERL_NIF_TERM injector_demonitor_and_clone_state(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaInjector;
    if (!enif_get_ulong(env, argv[0], &p_FridaInjector))
        return mk_error(env, "not_a_number");
    unsigned long id;
    if (!enif_get_ulong(env, argv[1], &id))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    guint res = frida_injector_demonitor_and_clone_state_sync((FridaInjector*)p_FridaInjector, id, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_ok_uint64(env, (unsigned long)res);
    }
}
static ERL_NIF_TERM injector_recreate_thread(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaInjector;
    if (!enif_get_ulong(env, argv[0], &p_FridaInjector))
        return mk_error(env, "not_a_number");
    unsigned long pid;
    if (!enif_get_ulong(env, argv[1], &pid))
        return mk_error(env, "not_a_number");
    unsigned long id;
    if (!enif_get_ulong(env, argv[2], &id))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_injector_recreate_thread_sync((FridaInjector*)p_FridaInjector, pid, id, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}

/* FileMonitor */
static ERL_NIF_TERM file_monitor_new(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary path;
    if (!enif_inspect_binary(env, argv[0], &path))
        return mk_error(env, "not_a_binary");

    unsigned long file_mon = (unsigned long)frida_file_monitor_new((const gchar*)path.data);
    return enif_make_int64(env, file_mon);
}
static ERL_NIF_TERM file_monitor_get_path(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaFileMonitor;
    if (!enif_get_ulong(env, argv[0], &p_FridaFileMonitor))
        return mk_error(env, "not_a_number");

    const gchar * path = frida_file_monitor_get_path((FridaFileMonitor*)p_FridaFileMonitor);

    ErlNifBinary bin_message;
    enif_alloc_binary(strlen(path), &bin_message);
    memcpy(bin_message.data, path, strlen(path));

    return enif_make_binary(env, &bin_message);
}
static ERL_NIF_TERM file_monitor_enable(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaFileMonitor;
    if (!enif_get_ulong(env, argv[0], &p_FridaFileMonitor))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_file_monitor_enable_sync((FridaFileMonitor*)p_FridaFileMonitor, NULL, &error);
    if (error != NULL) {
        return mk_gerror(env, error);
    } else {
        return mk_atom(env, "ok");
    }
}
static ERL_NIF_TERM file_monitor_disable(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned long p_FridaFileMonitor;
    if (!enif_get_ulong(env, argv[0], &p_FridaFileMonitor))
        return mk_error(env, "not_a_number");

    GError* error = NULL;
    frida_file_monitor_disable_sync((FridaFileMonitor*)p_FridaFileMonitor, &error);
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

    /* Library versioning */
    {"version", 0, version},
    {"version_string", 0, version_string},

    /* DeviceManager */
    {"device_manager_new", 0, device_manager_new},
    {"device_manager_close", 1, device_manager_close},
    {"device_manager_get_device_by_id", 4, device_manager_get_device_by_id},
    {"device_manager_get_device_by_type", 5, device_manager_get_device_by_type},
    {"device_manager_get_device", 5, device_manager_get_device},
    {"device_manager_find_device_by_id", 5, device_manager_find_device_by_id},
    {"device_manager_find_device_by_type", 5, device_manager_find_device_by_type},
    {"device_manager_find_device", 5, device_manager_find_device},
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
    {"device_get_manager", 1, device_get_manager},

    {"device_is_lost", 1, device_is_lost},
    {"device_get_frontmost_application", 1, device_get_frontmost_application},
    {"device_enumerate_applications", 1, device_enumerate_applications},
    {"device_get_process_by_pid", 2, device_get_process_by_pid},
    {"device_get_process_by_name", 3, device_get_process_by_name},
    {"device_get_process", 4, device_get_process},
    {"device_find_process_by_pid", 2, device_find_process_by_pid},
    {"device_find_process_by_name", 3, device_find_process_by_name},
    {"device_find_process", 4, device_find_process},
    {"device_enumerate_processes", 1, device_enumerate_processes},
    {"device_enable_spawn_gating", 1, device_enable_spawn_gating},
    {"device_disable_spawn_gating", 1, device_disable_spawn_gating},
    {"device_enumerate_pending_spawn", 1, device_enumerate_pending_spawn},
    {"device_enumerate_pending_children", 1, device_enumerate_pending_children},
    {"device_spawn", 3, device_spawn},
    {"device_input", 2, device_input},
    {"device_resume", 2, device_resume},
    {"device_kill", 2, device_kill},
    {"device_attach", 2, device_attach},
    {"device_inject_library_file", 5, device_inject_library_file},
    {"device_inject_library_blob", 5, device_inject_library_blob},

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

    /* SpawnOptions */
    {"spawn_options_new", 0, spawn_options_new},
    {"spawn_options_get_argv", 1, spawn_options_get_argv},
    {"spawn_options_get_envp", 1, spawn_options_get_envp},
    {"spawn_options_get_env", 1, spawn_options_get_env},
    {"spawn_options_get_cwd", 1, spawn_options_get_cwd},
    {"spawn_options_get_stdio", 1, spawn_options_get_stdio},
    {"spawn_options_get_aux", 1, spawn_options_get_aux},

    {"spawn_options_set_argv", 3, spawn_options_set_argv},
    {"spawn_options_set_envp", 3, spawn_options_set_envp},
    {"spawn_options_set_env", 3, spawn_options_set_env},
    {"spawn_options_set_cwd", 2, spawn_options_set_cwd},
    {"spawn_options_set_stdio", 2, spawn_options_set_stdio},

    /* SpawnList */
    {"spawn_list_size", 1, spawn_list_size},
    {"spawn_list_get", 2, spawn_list_get},

    /* Spawn */
    {"spawn_get_pid", 1, spawn_get_pid},
    {"spawn_get_identifier", 1, spawn_get_identifier},

    /* ChildList */
    {"child_list_size", 1, child_list_size},
    {"child_list_get", 2, child_list_get},

    /* Child */
    {"child_get_pid", 1, child_get_pid},
    {"child_get_parent_pid", 1, child_get_parent_pid},
    {"child_get_origin", 1, child_get_origin},
    {"child_get_identifier", 1, child_get_identifier},
    {"child_get_path", 1, child_get_path},
    {"child_get_argv", 1, child_get_argv},
    {"child_get_envp", 1, child_get_envp},

    /* Icon */
    {"icon_get_width", 1, icon_get_width},
    {"icon_get_height", 1, icon_get_height},
    {"icon_get_rowstride", 1, icon_get_rowstride},
    {"icon_get_pixels", 1, icon_get_pixels},

    /* Session */
    {"session_get_pid", 1, session_get_pid},
    {"session_get_device", 1, session_get_device},
    {"session_is_detached", 1, session_is_detached},
    {"session_detach", 1, session_detach},
    {"session_enable_child_gating", 1, session_enable_child_gating},
    {"session_disable_child_gating", 1, session_disable_child_gating},
    {"session_create_script", 3, session_create_script},
    {"session_create_script_from_bytes", 2, session_create_script_from_bytes},
    {"session_compile_script", 3, session_compile_script},
    {"session_enable_debugger", 2, session_enable_debugger},
    {"session_disable_debugger", 1, session_disable_debugger},
    {"session_enable_jit", 1, session_enable_jit},

    /* Script */
    {"script_get_id", 1, script_get_id},
    {"script_is_destroyed", 1, script_is_destroyed},
    {"script_load", 1, script_load},
    {"script_unload", 1, script_unload},
    {"script_eternalize", 1, script_eternalize},
    {"script_post", 3, script_post},

    /* Injector */
    {"injector_new", 0, injector_new},
    {"injector_new_inprocess", 0, injector_new_inprocess},
    {"injector_close", 1, injector_close},
    {"injector_inject_library_file", 5, injector_inject_library_file},
    {"injector_inject_library_blob", 5, injector_inject_library_blob},
    {"injector_demonitor_and_clone_state", 2, injector_demonitor_and_clone_state},
    {"injector_recreate_thread", 3, injector_recreate_thread},

    /* FileMonitor */
    {"file_monitor_new", 1, file_monitor_new},
    {"file_monitor_get_path", 1, file_monitor_get_path},
    {"file_monitor_enable", 1, file_monitor_enable},
    {"file_monitor_disable", 1, file_monitor_disable},
};

ERL_NIF_INIT(frida_nif, nif_funcs, NULL, NULL, &upgrade, NULL)