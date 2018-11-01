# frida-erl
Erlang bindings for frida-core sync

## Last version supported
12.2.18 (It may work for future versions as bindings rarely change)

## Where is the API outlined?
https://gist.github.com/oleavr/e6af8791adbef8fbde06 and also inside the file priv/frida-core.guide.h.

```
priv/frida-core.guide.h

curl -sL https://gist.githubusercontent.com/oleavr/e6af8791adbef8fbde06/raw/b6f2c8508db7b5c6aa6af50c2228e45b5d7c4729/frida-core.h | sha256sum | cut -d ' ' -f 1
56fe0b74e3d19d3f7c645960b314d94bd24746eab828b92f0ca120031d66c0ce
```

## Supported platforms
There is a pre-compiled nif shipped with the bindings for amd64 linux (static compiled on ubuntu 18.04), if you
wish to compile your own for your own enviroment, see below.
- Linux x86_64

## Building the NIF
Download a frida-core-devkit from the frida releases and include frida-core.h + static compile libfrida-core.a.
Look at make_linux_x86_64.sh for more help.

## Usage
How you may use this:  

```
Start your target environment, say windows vm.
Download frida-server only (https://github.com/frida/frida/releases) and run in cmd.exe

> frida-server -l 0.0.0.0:15100

On your host environment see frida_example.erl
```

## Navigating the API
The nif is a 1:1 wrapper for frida-core. Look at priv/frida-core.guide.h to learn more about it.  
  
The naming convention is strip frida_ and _sync, so frida_device_manager_close_sync becomes
frida_nif:device_manager_close/1.  

```
DevicePtr = frida:get_device_by_id(DeviceManagerPtr, BinId)
DevicesListOfMap = frida:get_all_devices(DeviceManagerPtr)
Pid = frida:get_pid_by_name(DevicePtr, BinProcessName)
```