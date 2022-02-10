# A simple SSID logger
If you are looking for a low cpu usage SSID logger written in C for the *GNU/Linux* platform, you just found one named **ssid-logger**.

*ssid-logger* was mainly created to log SSIDs and export the collected data to [Wigle.net](https://wigle.net). It is able to run on a *rpi0* for example, without requiring 100% cpu usage.

You will need a **wifi card** that is able to run in **monitor mode** and a GPS device recognized by **gpsd**.

*ssid-logger* uses the *pcap* library to listen passively for *beacon* management frames broadcasted by wifi access points, using a wifi card in monitor mode. It parses each beacon to extract the minimum data required to export to wigle.net. It logs each beacon AP alongside its GPS coordinates, acquired via the *gpsd* daemon. It automatically hops between 802.11n channels, at the default rate of 3 per second.

It can log to a **sqlite3** database (by default) or to a **csv** file.

This is an **all-in-one** solution to log SSIDs. Even though *kismet* is a great software; it's wardrive mode might not be light enough for a rpi0 (may be a rpi0 v2 ?)

Note: ssid-logger does not automatically export the collected data to wigle.net. You will have to do it manually, if you want to.

## Running
You run *ssid-logger* with:

    $ sudo ssid-logger -i wlan0mon

where *wlan0mon* is a wifi interface already put in monitor mode.

The default output format is a **sqlite3** database, named *beacon.db*. You can choose another name by using the `-o` switch.
You can select to choose the *csv* format by using `-f csv`.

The complete usage:

    Usage: ssid-logger -i IFACE [-f csv|sqlite3] [-o FILENAME] [-V] [-z] [-z]
      -i IFACE        interface to use
      -f csv|sqlite3  output format to use (default sqlite3)
      -o FILENAME     explicitly set the output filename
      -V              print version and exit
      -z              log ssid even if no gps coordinates are available
      -zz or -z -z    don't use gpsd and log all ssids

## Dependencies
*ssid-logger* depends on the following libraries:

  - libpcap
  - libpthread
  - libnl and libnl-genl
  - libgps
  - libsqlite3

You also need *gpsd* up and running.

### Examples
On Ubuntu 21.10 or Raspberry Pi OS, one needs to run the following command to install libraries and headers:

    $ sudo apt install pkg-config libpcap0.8 libpcap0.8-dev libnl-3-200 libnl-3-dev libnl-genl-3-200 libnl-genl-3-dev gpsd libgps28 libgps-dev libsqlite3-dev libsqlite3-0 meson ninja-build

On archlinux-arm, this is (libnl is already installed):

    $ sudo pacman -S libpcap gpsd sqlite3 meson ninja

## Building
To build the executable, you need *meson* and *ninja*.

    $ cd ssid-logger
    $ meson build
    $ ninja -C build

## Helper scripts

  - `sqlite3_to_csv.py` will allow to convert a sqlite3 `.db` file to a `.csv` one, if you change your mind afterwards and wants a csv file instead of a sqlite3 db.
  - `convert.py` will allow you to get a GPS trace in *GPX* or *KML* format to visualize on a map your path, and the SSIDs encoutered. This will allow you to check your GPS device and see if it works OK.
  - `upload_to_wiglenet.sh` helps you to upload the collected data to wigle.net via cli
