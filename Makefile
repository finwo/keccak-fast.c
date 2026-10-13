CC ?= cc
OPT ?= -O2
CFLAGS ?= -Wall -Wextra -Wpedantic $(OPT)
CFLAGS += -std=c11 -I src

LIB := src/keccak-fast.c $(wildcard src/backend/*.c)
OUT := build
BINS := $(OUT)/kat $(OUT)/batch $(OUT)/chain

.PHONY: default test bench clean
default: test

test: $(BINS)
	@$(OUT)/kat
	@$(OUT)/batch
	@$(OUT)/chain

bench:
	@$(MAKE) --no-print-directory --directory bench run

$(OUT)/%: test/%.c $(LIB) | $(OUT)
	@$(CC) $(CFLAGS) $< $(LIB) -o $@

$(OUT):
	@mkdir -p $(OUT)

clean:
	rm -rf $(OUT)
	@$(MAKE) --no-print-directory --directory bench clean
