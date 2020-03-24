# A simple SSID logger
If you are looking for a low cpu usage SSID logger written in C for the *GNU/Linux* platform, you just found one named **ssid-logger**.

*ssid-logger* was mainly created to log SSIDs and export the collected data to [Wigle.net](https://wigle.net). It is able to run on a *rpi0* for example, without requiring 100% cpu usage.

You will need a **wifi card** that is able to run in **monitor mode** and a GPS device recognized by **gpsd**.

*ssid-logger* uses the *pcap* library to listen passively for *beacon* management frames broadcasted by wifi access points, using a wifi card in monitor mode. It parses each beacon to extract the minimum data required to export to wigle.net. It logs each beacon AP alongside its GPS coordinates, acquired via the *gpsd* daemon. It automatically hops between 802.11n channels, at the default rate of 3 per second.

It can log to a **sqlite3** database (by default) or to a **csv** file.

Note: ssid-logger does not automatically export the collected data to wigle.net. You will have to do it manually, if you want to.

## Running
You run *ssid-logger* with:

    $ sudo ssid-logger -i wlan0mon

where *wlan0mon* is a wifi interface already put in monitor mode. If not, ssid-logger will do its best to try to put the interface in **monitor mode**, and exits if it fails to do so.

The default output format is a **sqlite3** database, named *beacon.db*. You can choose another name by using the `-o` switch.
You can select to choose the *csv* format by using `-f csv`.

The complete usage:

    Usage: ssid-logger -i IFACE [-f csv|sqlite3] [-o FILENAME]
      -i IFACE        interface to use
      -f csv|sqlite3  output format to use (default sqlite3)
      -o FILENAME     explicitly set the output filename

## Dependencies
*ssid-logger* depends on the following libraries:

  - libpcap
  - libpthread
  - libnl and libnl-genl
  - libgps
  - libsqlite3

You also need *gpsd* up and running.

### Examples
On Ubuntu 18.04 or Raspbian, one needs to run the following command to install libraries and headers:

    sudo apt install pkg-config libpcap0.8 libpcap0.8-dev libnl-3-200 libnl-3-dev libnl-genl-3-200 libnl-genl-3-dev gpsd libgps23 libgps-dev libsqlite3-dev libsqlite3-0 meson ninja-build

On archlinux-arm, this is (libnl is already installed):

    sudo pacman -S libpcap gpsd sqlite3 meson ninja

## Building
To build the executable, you need *meson* and *ninja*.

    $ cd ssid-logger
    $ meson build
    $ ninja -C build

If you don't want to or can't use meson+ninja, you can use a *Makefile* that is present in the git history.
You can view it with:

    $ git show a2fee3cbd3ae6f9cde291c419b5db6136f0c4c1f:Makefile

You can output that command to a file with a redirection to get a Makefile. The file might be a little old and you might need to update it.
