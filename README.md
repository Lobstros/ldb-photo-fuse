# LDB photo FUSE

> Everything is a file. Even files!

Originally written to show a user's LDAP profile picture on the Ubuntu login screen, `ldb-photo-fuse` allows access to certain user attributes in an LDB database (used by SSSD as cache format) through the filesystem as a FUSE mount.

## Caching photots in SSS and integrating with Ubuntu

1. Install requirements: `apt install python3-ldb python3-fusepy`
2. Make SSSD cache user photos: in `/etc/sssd/sssd.conf`, add `ldap_user_extra_attrs = jpegPhoto` under your LDAP domain heading
3. Create mountpoint: `mkdir /mnt/sssd-photo`
4. Install application: `cp ldb-photo-fuse.py /usr/local/bin/ldb-photo-fuse`
5. Install systemd service:
    1. Edit arguments in `sss-photo-fuse.service` to point to the LDB file where SSSD caches your domain info (usually `/var/lib/sss/db/cache_YOURDOMAIN.ldb`)
    2. `cp sssd-photo-fuse.service /etc/systemd/system/`
    3. `systemctl enable sss-photo-fuse; systemctl start sss-photo-fuse`
6. Point accounts service at photo files: for users with photos, edit `/var/lib/AccountsService/users/<user>`, to have `Icon=/mnt/sss-photo/<user>@<domain>/jpegPhoto.jpeg`
