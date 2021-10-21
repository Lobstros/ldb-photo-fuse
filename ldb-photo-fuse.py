#!/usr/bin/env python3

"""
ldb-photo-fuse v0.2.
FUSE mount for user attributes (e.g. jpegPhoto) in LDB files (e.g. SSSD cache).
Exported file/directory structure:
  /                               (root)
  └── user@ldapserver.domain/     (user subfolder)
      ├── photo.<extension>       (profile picture, if exists)
      └── thumbnail.<extension>   (thumbnail picture, if exists)
"""


from argparse import ArgumentParser, RawTextHelpFormatter
from os.path import isdir
from datetime import datetime
from imghdr import what as imghdr_what
from filecmp import cmp
from errno import ENOENT
from ldb import Ldb, FLG_RDONLY
from fusepy import FUSE, Operations, FuseOSError
from apscheduler.schedulers.background import BackgroundScheduler
from pydbus import SystemBus

DEFAULT_MOUNTPOINT = "/mnt/ldb-photo"
LOGIN_ICON_CHECK_FREQ_MINS = 30


class User:
    __slots__ = "name", "uidNumber", "originalModifyTimestamp", "jpegPhoto", "thumbnailPhoto"

    def __init__(self, ldb_res):
        """Initialises a User object from an LDB search result record."""
        self.name = str(ldb_res["name"].get(0))
        self.uidNumber = str(ldb_res["uidNumber"].get(0))
        self.originalModifyTimestamp = str(ldb_res["originalModifyTimestamp"].get(0))
        self.jpegPhoto = (ldb_res["jpegPhoto"].get(0) if ldb_res.get("jpegPhoto") else None)
        self.thumbnailPhoto = (ldb_res["thumbnailPhoto"].get(0) if ldb_res.get("thumbnailPhoto") else None)

    def photo_file_extension(self):
        """
        Returns a string that dictates the file extension for this user's photo.
        The LDAP attribute that stores the photo is (somewhat naïvely) called jpegPhoto, even though the picture data
        can be in any image format. Sticking the extension `.jpeg` on to such files willy-nilly can make certain
        userspace applications like `eog` angry.
        Thus, we need to detect the format to generate an apporpriate extension.
        """
        return imghdr_what(None, h=self.jpegPhoto)

    def thumbnail_file_extension(self):
        """
        Returns a string that dictates the file extension for this user's thumbnail image.
        """
        return imghdr_what(None, h=self.thumbnailPhoto)

    def photo_filename(self):
        return "photo." + self.photo_file_extension()

    def thumbnail_filename(self):
        return "thumbnail." + self.thumbnail_file_extension()


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
        return tuple(User(res) for res in results)

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

        if filename == user.photo_filename():
            # Photo file
            if not user.jpegPhoto:
                raise FuseOSError(ENOENT)
            epoch_modified = int(datetime.strptime(user.originalModifyTimestamp, "%Y%m%d%H%M%SZ").timestamp())
            return self._generate_file_stat(mtime=epoch_modified, size=len(user.jpegPhoto))

        if filename == user.thumbnail_filename():
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
                entries.append(user.photo_filename())
            if user.thumbnailPhoto:
                entries.append(user.thumbnail_filename())
        for entry in entries:
            yield entry

    def read(self, path, length, offset, fh):
        """Returns file byte data."""
        username, filename = self._parse_path(path)
        user = self.provider.get_user(username)
        # Does Linux read if it can't stat? Maybe the second check isn't necessary.
        if user.jpegPhoto and filename == user.photo_filename():
            return user.jpegPhoto[offset:offset+length]
        if user.thumbnailPhoto and filename == user.thumbnail_filename():
            return user.thumbnailPhoto[offset:offset+length]


def dbus_set_icon_path(uid, icon_path):
    return SystemBus().get("org.freedesktop.Accounts", f"/org/freedesktop/Accounts/User{uid}").SetIconFile(icon_path)


def dbus_get_icon_path(uid):
    return SystemBus().get("org.freedesktop.Accounts", f"/org/freedesktop/Accounts/User{uid}").Get('org.freedesktop.Accounts.User', 'IconFile')


def sync_user_icons(user_data_provider, cache_mountpoint):
    for user in user_data_provider.get_all_users():
        if user.jpegPhoto:
            fuse_photo_path = f"{cache_mountpoint}/{user.name}/{user.photo_filename()}"
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
