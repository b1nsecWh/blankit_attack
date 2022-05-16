CC         := clang
CFLAGS     := -Wall -fpic -O0 -m32  #-fpermissive
LIB = libblankit.so

SRC    :=   $(shell find -type f -name \*.c -print)
OBJ    :=   $(patsubst %.c,%.o,$(SRC))

all: $(LIB)
.PHONY: all

debug: CFLAGS := $(CFLAGS_DBG)
debug: all

clean:
	@rm -f *.o *.so
.PHONY: clean

$(LIB): $(OBJ)
	$(CC) -m32  -shared -o $@ $^

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $< -o $@
