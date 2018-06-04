CC=gcc
CFLAGS=

build/unimigparser:
	mkdir -p build;
	$(CC) $(CFLAGS) src/*.c -o $@

.PHONY:install
install:build/unimigparser
	mkdir -p /usr/local/bin
	cp build/unimigparser /usr/local/bin/unimigparser

.PHONY:uninstall
uninstall:
	rm /usr/local/bin/unimigparser

.PHONY:clean
clean:
	rm -rf build
