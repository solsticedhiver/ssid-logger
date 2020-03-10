.PHONY: all

all: ssid_logger

ssid_logger: ssid_logger.c radiotap.c
	gcc $(shell pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0) -lpthread -lpcap -o ssid_logger ssid_logger.c radiotap.c
