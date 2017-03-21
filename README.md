# frida-erl
Erlang bindings for frida-core

## Supported platforms
There is a pre-compiled nif shipped with the bindings, if you
wish to compile your own for your own enviroment, see way below.
- Linux x86_64

## Usage
How you may probably use this:  

```
Start your target environment, say windows vm.
Download frida-server only (https://github.com/frida/frida/releases) and run in cmd.exe

> frida-server -l 0.0.0.0:15100

On your host environment see frida_example.erl
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