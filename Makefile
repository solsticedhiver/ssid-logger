.PHONY: all

NL_FLAGS = $(shell pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0)

all: ssid-logger

clean:
	rm -f *.o
	rm -f ssid-logger

%.o: %.c
	gcc -O2 $(NL_FLAGS) -c $<

ssid-logger: ssid-logger.o radiotap.o queue.o hopper.o parsers.o worker.o gps.o
	gcc $(NL_FLAGS) -lgps -lpthread -lpcap -o ssid-logger ssid-logger.o radiotap.o queue.o hopper.o parsers.o worker.o gps.o
