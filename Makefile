CC      ?= gcc
LD      ?= ld
OBJCOPY ?= objcopy
CFLAGS  ?= -O2 -Wall -Wextra -std=c11

PARASITE_CFLAGS = -O2 -fPIE -fno-plt -ffreestanding -nostdlib -nostartfiles \
                  -fno-stack-protector -fno-asynchronous-unwind-tables \
                  -fcf-protection=none \
                  -Wall -Wextra -std=c11

all: injector test_hello

injector: injector.c parasite_blob.h
	$(CC) $(CFLAGS) -o $@ $<

test_hello: test_hello.c
	$(CC) $(CFLAGS) -o $@ $<

parasite.o: parasite.c
	$(CC) $(PARASITE_CFLAGS) -c $< -o $@

parasite.elf: parasite.o parasite.lds
	$(LD) -nostdlib -static --no-dynamic-linker --build-id=none \
	      -T parasite.lds -o $@ $<

parasite.bin: parasite.elf
	$(OBJCOPY) -O binary $< $@

parasite_blob.h: parasite.bin parasite.elf gen_blob_header.sh
	./gen_blob_header.sh parasite.bin parasite.elf > $@

test_hello_static: test_hello.c
	$(CC) $(CFLAGS) -no-pie -static -o $@ $<

.PHONY: demo clean

demo: injector test_hello test_hello_static
	@cp test_hello test_hello.infected
	@./injector test_hello.infected
	@echo "--- PIE (ET_DYN) ---"
	@./test_hello.infected || true
	@cp test_hello_static test_hello_static.infected
	@./injector test_hello_static.infected
	@echo "--- non-PIE (ET_EXEC) ---"
	@./test_hello_static.infected || true

clean:
	rm -f injector test_hello test_hello_static \
	      test_hello.infected test_hello_static.infected