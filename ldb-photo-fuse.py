#!/usr/bin/env python3

"""
ldb-photo-fuse v0.2.
FUSE mount for user attributes (e.g. jpegPhoto) in LDB files (e.g. SSSD cache).
Exported file/directory structure:
  /                               (root)
  └── user@ldapserver.domain/     (user subfolder)
      ├── jpegPhoto.jpeg          (profile picture, if exists)
      └── thumbnailPhoto.jpeg     (thumbnail picture, if exists)
"""


from argparse import ArgumentParser, RawTextHelpFormatter
from os.path import isdir
from collections import namedtuple
from datetime import datetime
from filecmp import cmp
from errno import ENOENT
from ldb import Ldb, FLG_RDONLY
from fusepy import FUSE, Operations, FuseOSError
from apscheduler.schedulers.background import BackgroundScheduler
from pydbus import SystemBus

DEFAULT_MOUNTPOINT = "/mnt/ldb-photo"
PHOTO_FILENAME = "jpegPhoto.jpeg"
THUMBNAIL_FILENAME = "thumbnailPhoto.jpeg"
LOGIN_ICON_CHECK_FREQ_MINS = 30

User = namedtuple("User", ("name", "uidNumber", "originalModifyTimestamp", "jpegPhoto", "thumbnailPhoto"))


class UserDataProvider:
    """
    Fetches user data from an LDB file, and returns it in a useable format.
    """

    fetch_attrs = ["Dn", "name", "uidNumber", "originalModifyTimestamp", "jpegPhoto", "thumbnailPhoto"]

    def __init__(self, dbpath):
        self.dbpath = dbpath
        self.ldb = Ldb()
        # Read-only flag highly advised—for security, and because LDB
        # will clobber the contents of any non-LDB file it's pointed at!
        self.ldb.connect(self.dbpath, FLG_RDONLY)

    @staticmethod
    def _ldb_results_to_user_tuples(results):
        return tuple(User(name=str(res["name"].get(0)),
                          uidNumber=str(res["uidNumber"].get(0)),
                          originalModifyTimestamp=str(res["originalModifyTimestamp"].get(0)),
                          jpegPhoto=(res["jpegPhoto"].get(0) if res.get("jpegPhoto") else None),
                          thumbnailPhoto=(res["thumbnailPhoto"].get(0) if res.get("thumbnailPhoto") else None)
                          ) for res in results)

    def get_all_users(self):
        """
        Fetches all user records.
        :return: Tuple of User namedtuples containing user details.
        """
        results = self.ldb.search(expression="objectCategory=user", attrs=self.fetch_attrs)
        return self._ldb_results_to_user_tuples(results)

    def get_user(self, full_username):
        """
        Searches for a user given their full username "user@ldapserver.domain".
        :return: User namedtuple containing user details if a match found; None otherwise.
        """
        results = self.ldb.search(expression=f"name={full_username}", attrs=self.fetch_attrs)
        if results:
            return self._ldb_results_to_user_tuples(results)[0]
        else:
            return None


class LDBFuse(Operations):
    """
    Implements necessary methods to expose to FUSE.
    """
    def __init__(self, user_data_provider):
        self.provider = user_data_provider

    @staticmethod
    def _parse_path(path):
        """Returns user, filename tuple."""
        splitpath = path.split("/")
        if splitpath[1] == "":
            return None, None
        elif len(splitpath) == 2:
            return splitpath[1], None
        else:
            return splitpath[1], splitpath[2]

    @staticmethod
    def _generate_dir_stat(atime=0, ctime=0, mtime=0, gid=0, uid=0, mode=0o40555, nlink=0, size=0):
        # File mode for a directory r/x by all and w by no-one: 040555
        return {"st_atime": atime, "st_ctime": ctime, "st_mtime": mtime,
                "st_gid": gid, "st_uid": uid,
                "st_mode": mode, "st_nlink": nlink, "st_size": size
                }

    @staticmethod
    def _generate_file_stat(atime=0, ctime=0, mtime=0, gid=0, uid=0, mode=0o100444, nlink=0, size=0):
        # File mode for a file r by all and w/x by no-one: 0100444
        return {"st_atime": atime, "st_ctime": ctime, "st_mtime": mtime,
                "st_gid": gid, "st_uid": uid,
                "st_mode": mode, "st_nlink": nlink, "st_size": size
                }

    def getattr(self, path, fh=None):
        """Returns filesystem attributes (type of file object, permissions, etc)"""
        username, filename = self._parse_path(path)
        if not username:
            # Root
            return self._generate_dir_stat()

        user = self.provider.get_user(username)
        if not user:
            raise FuseOSError(ENOENT)

        if not filename:
            # Individual user's subfolder
            epoch_modified = int(datetime.strptime(user.originalModifyTimestamp, "%Y%m%d%H%M%SZ").timestamp())
            return self._generate_dir_stat(mtime=epoch_modified)

        if filename == PHOTO_FILENAME:
            # Photo file
            if not user.jpegPhoto:
                raise FuseOSError(ENOENT)
            epoch_modified = int(datetime.strptime(user.originalModifyTimestamp, "%Y%m%d%H%M%SZ").timestamp())
            return self._generate_file_stat(mtime=epoch_modified, size=len(user.jpegPhoto))

        if filename == THUMBNAIL_FILENAME:
            # Photo file
            if not user.thumbnailPhoto:
                raise FuseOSError(ENOENT)
            epoch_modified = int(datetime.strptime(user.originalModifyTimestamp, "%Y%m%d%H%M%SZ").timestamp())
            return self._generate_file_stat(mtime=epoch_modified, size=len(user.thumbnailPhoto))

        raise FuseOSError(ENOENT)

    def readdir(self, path, fh):
        """Yields directory contents."""
        entries = [".", ".."]
        username, filename = self._parse_path(path)
        allusers = self.provider.get_all_users()
        if username is None:
            # Root
            entries.extend(user.name for user in allusers)
        elif username in (user.name for user in allusers):
            # Individual user's subfolder
            user = self.provider.get_user(username)
            if user.jpegPhoto:
                entries.append(PHOTO_FILENAME)
            if user.thumbnailPhoto:
                entries.append(THUMBNAIL_FILENAME)
        for entry in entries:
            yield entry

    def read(self, path, length, offset, fh):
        """Returns file byte data."""
        username, filename = self._parse_path(path)
        user = self.provider.get_user(username)
        # Does Linux read if it can't stat? Maybe the second check isn't necessary.
        if filename == PHOTO_FILENAME and user.jpegPhoto:
            return user.jpegPhoto[offset:offset+length]
        if filename == THUMBNAIL_FILENAME and user.thumbnailPhoto:
            return user.thumbnailPhoto[offset:offset+length]


def dbus_set_icon_path(uid, icon_path):
    return SystemBus().get("org.freedesktop.Accounts", f"/org/freedesktop/Accounts/User{uid}").SetIconFile(icon_path)


def dbus_get_icon_path(uid):
    return SystemBus().get("org.freedesktop.Accounts", f"/org/freedesktop/Accounts/User{uid}").Get('org.freedesktop.Accounts.User', 'IconFile')


def sync_user_icons(user_data_provider, cache_mountpoint):
    for user in user_data_provider.get_all_users():
        if user.jpegPhoto:
            fuse_photo_path = f"{cache_mountpoint}/{user.name}/{PHOTO_FILENAME}"
            try:
                if not cmp(dbus_get_icon_path(user.uidNumber), fuse_photo_path):
                    dbus_set_icon_path(user.uidNumber, fuse_photo_path)
            except FileNotFoundError:
                dbus_set_icon_path(user.uidNumber, fuse_photo_path)


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("dbpath", help="SSS database location")
    parser.add_argument("--mountpoint", help="Path that pictures will be mounted under.", default=DEFAULT_MOUNTPOINT)
    parser.add_argument("--allow-other", help="Allow users other than root to access mount", action="store_true")
    parser.add_argument("--sync-user-icons", help=f"Every {LOGIN_ICON_CHECK_FREQ_MINS} mins, set login icon via D-Bus for users that have a new jpegPhoto. Will overwrite previous picture.", action="store_true")
    args = parser.parse_args()
    if not isdir(args.mountpoint):
        raise NotADirectoryError(f"Mountpoint {args.mountpoint} does not exist.")
    provider = UserDataProvider(args.dbpath)
    if args.sync_user_icons:
        scheduler = BackgroundScheduler()
        scheduler.add_job(func=sync_user_icons,
                          args=(provider, args.mountpoint),
                          trigger="interval",
                          minutes=LOGIN_ICON_CHECK_FREQ_MINS
                          )
        scheduler.start()
    FUSE(LDBFuse(provider), args.mountpoint, nothreads=True, foreground=True, allow_other=args.allow_other)
