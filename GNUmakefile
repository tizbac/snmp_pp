.PHONY: all build install clean distclean
all: build
	ninja -C $< $@

install: all
	ninja -C build install

build:
	mkdir -p $@
	cmake -B $@ -S . -G Ninja -D OPTION_OPENSSL=YES -D OPTION_LIBDES=NO -D OPTION_LIBTOMCRYPT=NO -D OPTION_LOGGING=NO # -D OPTION_SNMPv3=NO

clean: build
	rm -f include/snmp_pp/config_snmp_pp.h
	-ninja -C $< clean

distclean: clean
	rm -rf build
#
