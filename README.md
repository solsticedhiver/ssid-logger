# Build

To build the executable, you need meson and ninja.

    # cd ssid-logger
    # meson build
    # ninja -C build

If you don't want or can't use meson+ninja, you can use a Makefile that is present in the git history.
You can view it with:

    git show a2fee3cbd3ae6f9cde291c419b5db6136f0c4c1f:Makefile

You can output that command to a file with a redirection to get a Makefile. The file might be a little old and you might need to update it.
