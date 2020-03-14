.PHONY: all

NL_FLAGS = $(shell pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0)

all: ssid_logger

clean:
	rm -f *.o
	rm -f ssid_logger

%.o: %.c
	gcc -O2 $(NL_FLAGS) -c $<

ssid_logger: ssid_logger.o radiotap.o queue.o hopper.o parsers.o worker.o
	gcc $(NL_FLAGS) -lpthread -lpcap -o ssid_logger ssid_logger.o radiotap.o queue.o hopper.o parsers.o worker.o
