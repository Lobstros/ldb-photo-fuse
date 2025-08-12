#!/usr/bin/env python3

"""
ldb-fuse v0.4.
FUSE mount for LDAP information (e.g. user jpegPhoto, sudoers, etc.) in LDB files (e.g. SSSD cache).
Exported file/directory structure for photos:
  /                               (root)
  ├── users/
  │   └── user@ldapserver.domain/     (user subfolder)
  │       ├── photo.<extension>       (profile picture, if exists)
  │       └── thumbnail.<extension>   (thumbnail picture, if exists)
  └── sudoers.txt   (text file of newline-separated usernames that are authorised
                     for ALL sudo commands on this machine)
"""


from argparse import ArgumentParser, RawTextHelpFormatter
from os.path import isdir
from os import makedirs, removedirs
from socket import gethostname
from datetime import datetime
from imghdr import what as imghdr_what
from filecmp import cmp
from errno import ENOENT
from ldb import Ldb, FLG_RDONLY
from fusepy import FUSE, Operations, FuseOSError
from apscheduler.schedulers.background import BackgroundScheduler
from pydbus import SystemBus

DEFAULT_MOUNTPOINT = "/run/ldb-fuse/"
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
        Thus, we need to detect the format to generate an appropriate extension.
        """
        return imghdr_what(None, h=self.jpegPhoto)

    def thumbnail_file_extension(self):
        """
        Returns a string that dictates the file extension for this user's thumbnail image.
        """
        return imghdr_what(None, h=self.thumbnailPhoto)

    def photo_filename(self):
        if not self.jpegPhoto:
            raise FuseOSError(ENOENT)
        return "photo." + self.photo_file_extension()

    def thumbnail_filename(self):
        if not self.thumbnailPhoto:
            raise FuseOSError(ENOENT)
        return "thumbnail." + self.thumbnail_file_extension()


class UserDataProvider:
    """
    Fetches user data from an LDB file, and returns it in a useable format.
    """

    fetch_user_attrs = ["Dn", "name", "uidNumber", "originalModifyTimestamp", "jpegPhoto", "thumbnailPhoto"]
    fetch_sudoer_attrs = ["sudoUser"]

    def __init__(self, dbpath):
        self.dbpath = dbpath
        self.ldb = Ldb()
        # Read-only flag highly advised—for security, and because LDB
        # will clobber the contents of any non-LDB file it's pointed at!
        self.ldb.connect(self.dbpath, FLG_RDONLY)

    def get_all_users(self):
        """
        Fetches all user records.
        :return: Tuple of User objects containing user details.
        """
        results = self.ldb.search(expression="objectCategory=user", attrs=self.fetch_user_attrs)
        return tuple(User(res) for res in results)

    def get_user(self, full_username):
        """
        Searches for a user given their full username "user@ldapserver.domain".
        :return: User object containing user details if a match found; None otherwise.
        """
        results = self.ldb.search(expression=f"name={full_username}", attrs=self.fetch_user_attrs)
        if results:
            return User(results[0])
        return None

    def get_sudoers(self, hostname=None):
        """
        Searches for all users that are allowed to sudo execute "ALL" on this (or another given) hostname.
        :return: Tuple of usernames with sudo permissions.
        """
        if hostname is None:
            hostname = gethostname()
        results = self.ldb.search(expression=f"(&(sudoHost={hostname})(sudoCommand=ALL))", attrs=self.fetch_sudoer_attrs)
        return tuple(str(res["sudoUser"].get(0)).removesuffix('@ldap.luffy.ai') for res in results)

    def get_sudoers_as_bytes(self, hostname=None):
        """
        Transforms the list of sudoers returned from get_sudoers() into a newline-delimited byte string.
        :return: Sudoers list as bytes object.
        """
        return ("\n".join(self.get_sudoers(hostname))+"\n").encode()


class LDBFuse(Operations):
    """
    Implements necessary methods to expose to FUSE.
    """
    def __init__(self, user_data_provider):
        self.provider = user_data_provider

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
        match path.strip("/").split("/"):

            case [""] | ["users"]:
                # Main root or all users subfolder
                return self._generate_dir_stat()

            case ["users", username] if user := self.provider.get_user(username):
                # Individual user's subfolder
                epoch_modified = int(datetime.strptime(user.originalModifyTimestamp, "%Y%m%d%H%M%SZ").timestamp())
                return self._generate_dir_stat(mtime=epoch_modified)

            case ["users", username, filename] if user := self.provider.get_user(username):
                # Individual file under user's subfolder
                if filename == user.photo_filename():
                    # Photo file
                    epoch_modified = int(datetime.strptime(user.originalModifyTimestamp, "%Y%m%d%H%M%SZ").timestamp())
                    return self._generate_file_stat(mtime=epoch_modified, size=len(user.jpegPhoto))

                if filename == user.thumbnail_filename():
                    # Thumbnail file
                    epoch_modified = int(datetime.strptime(user.originalModifyTimestamp, "%Y%m%d%H%M%SZ").timestamp())
                    return self._generate_file_stat(mtime=epoch_modified, size=len(user.thumbnailPhoto))

                raise FuseOSError(ENOENT)

            case ["sudoers.txt"]:
                # Sudoers file
                return self._generate_file_stat(size=len(self.provider.get_sudoers_as_bytes()))

        raise FuseOSError(ENOENT)

    def readdir(self, path, fh):
        """Yields directory contents."""
        entries = [".", ".."]

        match path.strip("/").split("/"):

            case [""]:
                # Root
                entries.extend(["users", "sudoers.txt"])

            case ["users"]:
                # All users subfolder
                allusers = self.provider.get_all_users()
                entries.extend(user.name for user in allusers)

            case ["users", username] if user := self.provider.get_user(username):
                # Individual user's subfolder
                if user.jpegPhoto:
                    entries.append(user.photo_filename())
                if user.thumbnailPhoto:
                    entries.append(user.thumbnail_filename())

            case _:
                raise FuseOSError(ENOENT)

        yield from entries

    def read(self, path, length, offset, fh):
        """Returns file byte data."""

        match path.strip("/").split("/"):

            case ["users", username, filename] if user := self.provider.get_user(username):
                # Individual file under user's subfolder
                if user.jpegPhoto and filename == user.photo_filename():
                    return user.jpegPhoto[offset:offset+length]
                if user.thumbnailPhoto and filename == user.thumbnail_filename():
                    return user.thumbnailPhoto[offset:offset+length]
                raise FuseOSError(ENOENT)

            case ["sudoers.txt"]:
                # Sudoers file
                return self.provider.get_sudoers_as_bytes()[offset:offset+length]

        raise FuseOSError(ENOENT)


def dbus_set_icon_path(uid, icon_path):
    """Set a user's login icon to the contents of an existing file via DBus"""
    return SystemBus().get("org.freedesktop.Accounts", f"/org/freedesktop/Accounts/User{uid}")\
                      .SetIconFile(icon_path)


def dbus_get_icon_path(uid):
    """Get the path of a user's current login icon via DBus"""
    return SystemBus().get("org.freedesktop.Accounts", f"/org/freedesktop/Accounts/User{uid}")\
                      .Get('org.freedesktop.Accounts.User', 'IconFile')


def sync_user_icons(user_data_provider, user_data_path):
    """
    For all users in a provider, checks for the existence of a jpegPhoto.
    If available, and it is different to the user's current profile icon, set it as their new icon.
    """
    for user in user_data_provider.get_all_users():
        if user.jpegPhoto:
            fuse_photo_path = f"{user_data_path}/{user.name}/{user.photo_filename()}"
            try:
                # NB: Sometimes SSSD caches users that haven't yet logged on locally.
                # In this case, dbus raises a KeyError in get_icon_path(), and we simply move to the next iteration.
                if not cmp(dbus_get_icon_path(user.uidNumber), fuse_photo_path):
                    dbus_set_icon_path(user.uidNumber, fuse_photo_path)
            except KeyError:
                continue
            except FileNotFoundError:
                # No existing icon, so use the one from the provided path.
                dbus_set_icon_path(user.uidNumber, fuse_photo_path)


class Mountpoint:
    """Context handler for FUSE mounts that creates mount point beforehand, and removes afterward."""
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        if not isdir(self.path):
            makedirs(self.path)
            if not isdir(self.path):
                raise NotADirectoryError(f"Can't create mount point {self.path}.")

    def __exit__(self, exception_type, exception_value, exception_traceback):
        removedirs(self.path)


def main():

    parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("dbpath", help="SSS database location")
    parser.add_argument("--mountpoint", help="Path that LDB data will be mounted under.", default=DEFAULT_MOUNTPOINT)
    parser.add_argument("--allow-other", help="Allow users other than root to access mounts", action="store_true")
    parser.add_argument("--sync-user-icons", help=f"Every {LOGIN_ICON_CHECK_FREQ_MINS} mins, set login icon via D-Bus for users that have a new jpegPhoto. Will overwrite previous picture.", action="store_true")
    args = parser.parse_args()
    provider = UserDataProvider(args.dbpath)

    if args.sync_user_icons:
        scheduler = BackgroundScheduler()
        scheduler.add_job(func=sync_user_icons,
                          args=(provider, f"{args.mountpoint}/users"),
                          trigger="interval",
                          minutes=LOGIN_ICON_CHECK_FREQ_MINS
                          )
        scheduler.start()

    with Mountpoint(args.mountpoint):
        FUSE(LDBFuse(provider), args.mountpoint, nothreads=True, foreground=True, allow_other=args.allow_other)


if __name__ == "__main__":
    main()
