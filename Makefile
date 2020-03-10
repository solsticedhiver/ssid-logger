.PHONY: all

all: ssid_logger

ssid_logger: ssid_logger.c radiotap.c
	gcc -lpcap -o ssid_logger ssid_logger.c radiotap.c
