CC=gcc
CFLAGS = -Wno-unused-variable -Wall -Werror -Wextra -Wpedantic -Wwrite-strings -Wvla -Wfloat-equal
LDLIBS = -lpthread

SRC := src
DEST := bin
BUILD := build

SOURCES := $(wildcard $(SRC)/*.c)
HEADERS := $(wildcard &(SRC)/*.h)

TARGET = $(DEST)/capstone

.PHONY: all
all: $(DEST) $(TARGET)

.PHONY: debug
debug: CFLAGS += -g
debug: all

$(DEST):
	mkdir -p $@

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(SOURCES) -o $@ $(LDLIBS)


.PHONY: clean
clean:
	$(RM) $(TARGET) $(BUILD)/*.o