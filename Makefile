# Builds build/libtinymtproto.a with the host compiler and runs the offline tests.
#   make              library
#   make test         offline tests (Python 3 with cryptography + pycryptodome)
#   make arm          freestanding ARM build check (needs: pip install ziglang pyelftools)
#   make schema       regenerate src/tg_schema.[ch] from schema/telegram_api.tl
CC ?= cc
AR ?= ar
PYTHON ?= python3
CFLAGS ?= -O2 -Wall -Wextra

SRCS = tg_sha.c tg_aes.c tg_bn.c tg_pq.c tg_tl.c tg_mtp.c tg_auth.c tg_net.c \
       tg_session.c tg_inflate.c tg_tlwalk.c tg_schema.c tg_client.c
OBJS = $(SRCS:%.c=build/%.o)

all: build/libtinymtproto.a

build:
	mkdir -p build

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -Isrc -c $< -o $@

build/libtinymtproto.a: $(OBJS)
	$(AR) rcs $@ $^

test:
	CC="$(CC)" $(PYTHON) tests/run_all.py --no-arm

arm:
	$(PYTHON) tests/arm_check.py

schema:
	$(PYTHON) tools/gen_tl.py

clean:
	rm -rf build

.PHONY: all test arm schema clean
