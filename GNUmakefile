.PHONY: all build install clean
all: build
	ninja -C $< $@

install: all
	ninja -C build install

build:
	mkdir -p $@
	cmake -B $@ -S . -G Ninja -D OPTION_OPENSSL=NO -D OPTION_LIBDES=NO -D OPTION_LIBTOMCRYPT=YES -D OPTION_LOGGING=NO # -D OPTION_SNMPv3=NO
clean:
	rm -rf build
#
