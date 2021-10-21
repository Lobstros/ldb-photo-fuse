# LDB photo FUSE

> Everything is a file. Even files!

Written to propagate a user's LDAP profile picture to the Ubuntu login screen, `ldb-photo-fuse` can:

* Allow access to user photos in an LDB database (e.g. SSSD cache) through the filesystem as a FUSE mount.
* Automatically set users' profile pictures thus available via DBus.

## Caching photots in SSS and integrating with Ubuntu login icons

1. Install requirements: `apt install python3-ldb python3-fusepy python3-pydbus python3-apscheduler`
2. Instruct SSSD to cache user photos: in `/etc/sssd/sssd.conf`, add `ldap_user_extra_attrs = jpegPhoto` under your LDAP domain heading
3. Install application: `cp ldb-photo-fuse.py /usr/local/sbin/ldb-photo-fuse`
4. Install systemd service:
    1. Edit arguments in `sss-photo-fuse.service` to point to the LDB file where SSSD caches your domain info (usually `/var/lib/sss/db/cache_YOURDOMAIN.ldb`)
    2. `cp sss-photo-fuse.service /etc/systemd/system/`
    3. `systemctl enable sss-photo-fuse; systemctl start sss-photo-fuse`
