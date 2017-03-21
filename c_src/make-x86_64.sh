#!/bin/bash
/usr/bin/gcc -static-libgcc -fPIC -shared -m64 -ffunction-sections -fdata-sections \
-I./priv/9.1.16-core-linux-x86_64/ \
-I/usr/lib/erlang/usr/include/ \
-Wall -Os -pipe \
-g3 ./c_src/frida_nif.c -o ./priv/build/frida_nif_linux_x86_64.so \
-L./priv/9.1.16-core-linux-x86_64/ \
-L/usr/lib/erlang/usr/lib/ \
-lfrida-core -lrt -ldl -ldl -lresolv -lrt -ldl -lrt -lpthread -Wl,--export-dynamic -Wl,--gc-sections