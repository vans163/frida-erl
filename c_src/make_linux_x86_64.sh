#!/bin/bash
/usr/bin/gcc -static-libgcc -fPIC -shared -m64 -ffunction-sections -fdata-sections \
-Wall -Os -pipe \
-I../priv/frida-core-devkit-12.2.18-linux-x86_64/ \
-I/usr/lib/erlang/usr/include/ \
-g3 ./frida_nif.c -o ./../priv/frida_nif_linux_x86_64.so \
-L../priv/frida-core-devkit-12.2.18-linux-x86_64/ \
-L/usr/lib/erlang/usr/lib/ \
-lfrida-core -ldl -lm -lrt -lresolv -lpthread -Wl,--export-dynamic -Wl,--gc-sections,-z,noexecstack


#/usr/bin/gcc -m32 -g3 frida-core-example.c -o frida-core-example 
#-L. -lfrida-core -ldl -lm -ldl -lm -ldl -lrt -ldl -lrt -ldl -lresolv -ldl -lrt -Wl,--export-dynamic -Wl,--gc-sections,-z,noexecstack 
#-L/worker/frida-linux-x86/build/build/frida-linux-x86/lib 
#-L/worker/frida-linux-x86/build/build/sdk-linux-x86/lib