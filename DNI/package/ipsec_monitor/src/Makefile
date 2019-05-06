
TARGET  := ipsec_monitor

SOURCES := main.c
OBJS    := $(SOURCES:.c=.o)

LDFLAGS +=
IFLAGS += -I. 
CFLAGS += -Os -Wall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $(IFLAGS) $<

clean:
	rm -rf $(TARGET) $(OBJS)

.PHONY: clean
