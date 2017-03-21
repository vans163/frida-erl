# frida-erl
Erlang bindings for frida-core

## Supported platforms
There is a pre-compiled nif shipped with the bindings, if you
wish to compile your own for your own enviroment, see way below.
- Linux x86_64

## Usage
How you may probably use this:  

```erlang
%Start your target environment, say windows vm.
%Download frida-server only (https://github.com/frida/frida/releases) and run in cmd.exe

%> frida-server -l 0.0.0.0:15100

%On your host environment do the following:

ok = frida_nif:init(),
DevMan = frida_nif:device_manager_new(),

frida_nif:device_manager_add_remote_device(DevMan, <<"192.168.6.11:15100">>),
Dev = get_device_by_id(DevMan,  <<"tcp@192.168.6.11:15100">>),

Pid = get_pid_by_name(Dev, <<"notepad.exe">>),
{ok, Session} = frida_nif:device_attach(Dev, Pid),

{ok, ErlFridaScript} = run_script(Session,  
    <<"
    console.log('hi');
    Interceptor.attach(Module.findExportByName(null, 'GetMessage'), {
        onEnter: function (args) {
            console.log('[*] GetMessage(\"' + Memory.readUtf8String(args[0]) + '\")');
        }
    });
    Interceptor.attach(Module.findExportByName(null, 'DispatchMessage'), {
        onEnter: function (args) {
            console.log('[*] DispatchMessage(' + args[0].toInt32() + ')');
        }
    });
    "/utf8, 0>>).
```

## API
The nif is a 1:1 wrapper for frida-core. Look at c_src/frida-core.guide to learn more about it.  
  
The naming convention is strip frida_ and _sync, so frida_device_manager_close_sync becomes
frida_nif:device_manager_close/1.  
  
DevicePtr = frida:get_device_by_id(DeviceManagerPtr, BinId)  
DevicesListOfMap = frida:get_all_devices(DeviceManagerPtr)  
Pid = frida:get_pid_by_name(DevicePtr, BinProcessName)  

## Building the NIF

Download frida-core-devkit from the frida releases and link frida-core.a