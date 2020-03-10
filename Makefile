.PHONY: all

NL_FLAGS = $(shell pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0)

all: ssid_logger

ssid_logger: ssid_logger.c radiotap.c
	gcc -O2 $(NL_FLAGS) -lpthread -lpcap -o ssid_logger ssid_logger.c radiotap.c
