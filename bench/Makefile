CC ?= cc
OPT ?= -O2

ARCHFLAGS := $(filter -march=% -mcpu=% -mavx% -mavx2% -mavx512% -msse% \
                        -mssse3% -msse4% -mfma%,$(OPT))
ifneq ($(ARCHFLAGS),)
$(error bench: OPT has arch flags ($(ARCHFLAGS)); the library ships without \
	them and the baseline is not comparable. Use OPT=-O2 or OPT=-O3)
endif

CFLAGS ?= -Wall -Wextra -Wpedantic $(OPT)
CFLAGS += -std=c11 -I../src
BENCH_DESC := $(CC) -std=c11 $(OPT)
CFLAGS += -DBENCH_FLAGS='"$(BENCH_DESC)"'

OUT := build
BIN := $(OUT)/bench

SRC := ../src/keccak-fast.c $(wildcard ../src/backend/*.c)

DONOR := lib/coruus/keccak-tiny/keccak-tiny.c
DONOR_OBJ := $(OUT)/kct.o
DONOR_DEFS := -Dshake128=kct_shake128 -Dshake256=kct_shake256 \
              -Dsha3_224=kct_sha3_224 -Dsha3_256=kct_sha3_256 \
              -Dsha3_384=kct_sha3_384 -Dsha3_512=kct_sha3_512

.PHONY: all run clean
all: $(BIN)

$(OUT):
	@mkdir -p $(OUT)

$(DONOR):
	@dep install

$(DONOR_OBJ): $(DONOR) | $(OUT)
	@$(CC) $(CFLAGS) $(DONOR_DEFS) -c $< -o $@

$(BIN): bench.c $(SRC) $(DONOR_OBJ) | $(OUT)
	@$(CC) $(CFLAGS) bench.c $(SRC) $(DONOR_OBJ) -o $@

run: $(BIN)
	@$(BIN)

clean:
	rm -rf $(OUT)
