lssecrets
=========

This is a program to list the content of the [secret
keyring](https://specifications.freedesktop.org/secret-service/latest/) using
[libsecret](https://gnome.pages.gitlab.gnome.org/libsecret/).


Usage
-----

With no arguments, all unlocked collections and items are shown, without attributes or
secrets:

    lssecrets

To show item attributes, use the argument `--detail=3`:

    lssecrets --detail=3

To show item attributes and secrets, use the argument `--detail=4`:

    lssecrets --detail=4

If there are collections or items locked, use the option `--unlock` to unlock everything:

    lssecrets --unlock

Both options can be combined, to unlock and show the secrets:

    lssecrets --detail=4 --unlock


Dependencies
------------

- A C++ compiler that supports `-std=c++20`.
- [libsecret](https://gnome.pages.gitlab.gnome.org/libsecret/)
- [glibmm](https://gitlab.gnome.org/GNOME/glibmm)


Build and Installation
----------------------

If you're building from a tarball, you can skip step 0.

  0. Run `./bootstrap`
  1. Run `./configure`
  2. Run `make`
  3. Optional: run `sudo make install`

This software is a standard Automake package. Check the [INSTALL](INSTALL) file or run
`./configure --help` for more detailed instructions.
