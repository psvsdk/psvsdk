#!/bin/sh
[ $# -eq 0 ] && echo "$(basename $0): no args" && exit 1;
$CC=arm-none-eabi-gcc
$MFLAGS="-march=armv7-a -mtune=cortex-a9 -mfpu=neon -mfloat-abi=hard -mthumb" # -mcpu=cortex-a9 -mvectorize-with-neon-quad
$CFLAGS="-D__vita__ -nostdlib"
$CC $MFLAGS $CFLAGS \
	-I "$(dirname $0)/../headers/include" \
	-I "$VITASDK/arm-vita-eabi/include/" \
	-L "$VITASDK/arm-vita-eabi/lib/ $@

# Optional could redirect to clang (but still rely on the GNU linker :/ )
# clang-6.0 -c -target arm-none-eabi  -I $VITASDK/arm-vita-eabi/include/ $@ && arm-none-eabi-ld -L $VITASDK/arm-vita-eabi/lib/ $@
