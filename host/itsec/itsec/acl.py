"""Root's safe access to files that belong to a less trusted account: read access for the watchdog account, and reading them.

install-watchdog.sh runs as root; the files live in the home of the account the agents run as, which can replace a
directory by a symlink at any moment. `setfacl -P` only refuses a symlink in the LAST path component, so a swap
between the check and the call would let root grant access to someone else's files. This module does what setfacl
cannot: it walks the path from "/" one component at a time with O_NOFOLLOW (relative to the directory it already
holds), looks at every component through the descriptor it opened (type and owner), and then runs setfacl on
/proc/self/fd/N of that very descriptor. A component swapped afterwards changes nothing: the descriptor still names
the original object. Recursive grants walk the tree the same way, so nothing below the top is followed either, and
they stay on the file system of the tree's top (a mount the account made inside it is not entered).

The same walk is the one way to read such a file, for root (read_checked, used by itsec-make-manifest) and for the
collector that runs as the itsec account (read_checked, open_file): the last component is opened
O_RDONLY|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW, so a FIFO cannot hang the reader, and the descriptor must be a regular file of
at most READ_CAP bytes (read_checked) or STREAM_CAP bytes (open_file, for hashing and line-by-line reads), so not /dev/zero
and not a huge file. Anything the walk cannot look at, including a stat or open that fails (for example on a FUSE mount
root may not enter), is a refusal, never a crash. Refused.kind says why (see KINDS); "denied" means the account simply may
not look or read (the ACL step was not run), which is not tampering: open_file reports it as PermissionError.

  itsec-acl --uid UID [--user itsec] grant  x|r|R PATH     x: a directory (traversal), r: a file (read),
  itsec-acl --uid UID [--user itsec] remove x|r|R PATH     R: a directory tree (read; directories also traversable)

UID is the watched account: every component, and everything in a tree, must belong to it or to root, else the
path is refused. Exit codes (install-watchdog.sh relies on them):
  0  done; a path that no longer exists counts as done. Objects below a tree that are symlinks, foreign-owned, on another
     file system or unreadable are left out and reported on stderr: that is still 0.
  2  refused: the path itself is not safe or cannot be looked at (symlink, foreign owner, wrong type, stat/open error), or a
     tree has more than MAX_OBJECTS entries (counted before anything is changed: the account could otherwise keep root
     walking). Reported; the installer goes on with the next path.
  1  setfacl failed or an unexpected error: the installer stops (re-running is safe)."""
import argparse
import errno
import itertools
import os
import stat
import struct
import subprocess
import sys

BATCH = 100                                     # objects per setfacl call
READ_CAP = 64 << 20                             # largest file read_checked returns
STREAM_CAP = 1 << 30                            # largest file open_file lets a caller stream (hash, verify line by line)
MAX_OBJECTS = 20000                             # most entries a recursive grant or removal looks at (the watch reads far fewer)
_GRANT = {"x": "u:{u}:x", "r": "u:{u}:r", "R": "u:{u}:rX"}
_WANT = {"x": stat.S_ISDIR, "r": stat.S_ISREG, "R": stat.S_ISDIR}

# system.posix_acl_access: version 2 header, then 8-byte entries (tag u16, perm u16, id u32), little endian
_TAG_USER, _TAG_GROUP_OBJ, _TAG_GROUP, _TAG_MASK = 0x02, 0x04, 0x08, 0x10


# Refused.kind
KINDS = ("symlink-in-path",     # a symlink, or a plain file where a directory belongs, in the path
         "foreign-owner",       # a component owned by neither the watched account nor root
         "not-regular",         # the last component is a FIFO, device, socket or directory
         "oversize",            # a regular file over the cap
         "denied",              # the account may not look at or read it (no ACL / traversal): not tampering
         "unsafe")              # anything else the walk cannot look at


class Refused(Exception):
    """The path (or something below it) is not safe to touch. `kind` is one of KINDS."""

    def __init__(self, message, kind="unsafe"):
        super().__init__(message)
        self.kind = kind

    @property
    def denied(self):
        return self.kind == "denied"


def _kind_of(e):
    if e.errno in (errno.ELOOP, errno.ENOTDIR):
        return "symlink-in-path"
    if e.errno in (errno.EACCES, errno.EPERM):
        return "denied"
    if e.errno in (errno.ENXIO, errno.ENODEV):
        return "not-regular"
    return "unsafe"


def _open_path(name, dir_fd, directory):
    flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if directory else 0)
    return os.open(name, flags, dir_fd=dir_fd)


def _open_data(name, dir_fd):
    """The last component of a read: never blocks (FIFO), never becomes the controlling terminal, never a symlink."""
    return os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)


def _owned(st, uid):
    return uid is None or st.st_uid in (uid, 0)


def _stat(fd, path):
    try:
        return os.fstat(fd)
    except OSError as e:                        # e.g. EACCES: a FUSE mount the account made and root may not look into
        raise Refused(f"{path}: cannot look at it ({e.strerror})", _kind_of(e))


def open_checked(path, uid, read=False):
    """O_PATH descriptor of `path` (read=True: a read-only one of a regular file), reached from "/" without a symlink and
    through components owned by `uid` or root (uid None: no owner check). Raises FileNotFoundError, or Refused."""
    parts = path[1:].split("/")
    if not path.startswith("/") or any(c in ("", ".", "..") for c in parts):
        raise Refused(f"{path}: not a plain absolute path", "unsafe")
    fd = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        if not _owned(_stat(fd, "/"), uid):
            raise Refused("/: owned by neither the watched account nor root", "foreign-owner")
        for i, name in enumerate(parts):
            last = i == len(parts) - 1
            try:
                nfd = _open_data(name, fd) if last and read else _open_path(name, fd, directory=not last)
            except FileNotFoundError:
                raise
            except OSError as e:                # ELOOP / ENOTDIR: a symlink or a plain file where a directory belongs; EACCES ...
                raise Refused(f"{path}: {name} is a symlink, not a directory or cannot be opened ({e.strerror})", _kind_of(e))
            os.close(fd)
            fd = nfd
            st = _stat(fd, path)
            if stat.S_ISLNK(st.st_mode):        # the last component, opened as the link itself
                raise Refused(f"{path}: {name} is a symlink", "symlink-in-path")
            if not _owned(st, uid):
                raise Refused(f"{path}: {name} belongs to uid {st.st_uid}, neither the watched account nor root", "foreign-owner")
        if read:
            if not stat.S_ISREG(st.st_mode):
                raise Refused(f"{path}: not a regular file", "not-regular")
            os.set_blocking(fd, True)           # a regular file: the flag only mattered for the open
        result, fd = fd, -1
        return result
    finally:
        if fd >= 0:
            os.close(fd)


def _fileobj(path, uid, cap):
    """Binary file object of the regular file `path` (reached as open_checked does); `cap` None = any size."""
    fd = open_checked(path, uid, read=True)
    f = os.fdopen(fd, "rb")
    try:
        size = os.fstat(fd).st_size
    except OSError as e:
        f.close()
        raise Refused(f"{path}: cannot look at it ({e.strerror})", _kind_of(e))
    if cap is not None and size > cap:
        f.close()
        raise Refused(f"{path}: {size} bytes, over the {cap} byte limit; not read", "oversize")
    return f


def open_file(path, uid=None, cap=STREAM_CAP):
    """For a caller that streams: the regular file `path` as a binary file object (reached as open_checked does), of at most
    `cap` bytes when opened (None: any size, for a tail read of a log that only grows; the caller bounds what it reads). The
    caller stops after `cap` bytes it reads itself, because the file may grow. Raises FileNotFoundError, PermissionError
    (the account may not look or read: not tampering), or Refused."""
    try:
        return _fileobj(path, uid, cap)
    except Refused as e:
        if e.denied:
            raise PermissionError(errno.EACCES, str(e)) from None
        raise


def read_checked(path, uid=None, cap=READ_CAP):
    """The content of the regular file `path` (reached as open_checked does), at most `cap` bytes. Raises FileNotFoundError,
    or Refused (also for a file over the cap: it is not read; every refusal, "denied" too)."""
    with _fileobj(path, uid, cap) as f:
        try:
            data = f.read(cap + 1)              # the file may grow while it is read
        except OSError as e:
            raise Refused(f"{path}: cannot read it ({e.strerror})", _kind_of(e))
    if len(data) > cap:
        raise Refused(f"{path}: over the {cap} byte limit; not read", "oversize")
    return data


def _mask_is_leftover(fd):
    """True when the access ACL of `fd` has no user or group entry left and its mask equals the group entry: the mask then
    only keeps the `+` in `ls -l`, and removing it leaves the mode bits as they are."""
    try:
        raw = os.getxattr(f"/proc/self/fd/{fd}", "system.posix_acl_access")
    except OSError:
        return False                            # no ACL left at all (or no ACL support): nothing to clean
    if len(raw) < 4 or struct.unpack_from("<I", raw)[0] != 2:
        return False
    perms = {}
    for off in range(4, len(raw) - 7, 8):
        tag, perm, _ = struct.unpack_from("<HHI", raw, off)
        if tag in (_TAG_USER, _TAG_GROUP):
            return False
        perms[tag] = perm
    return _TAG_MASK in perms and perms[_TAG_MASK] == perms.get(_TAG_GROUP_OBJ)


class Applier:
    """Collects descriptors and runs setfacl on up to BATCH of them at once; owns (closes) what it is given."""

    def __init__(self, op, kind, user, setfacl):
        self.op, self.kind, self.user, self.setfacl = op, kind, user, setfacl
        self.fds, self.failed = [], False
        self.env = dict(os.environ, LC_ALL="C")

    def add(self, fd):
        self.fds.append(fd)
        if len(self.fds) >= BATCH:
            self.flush()

    def _setfacl(self, args, fds):
        paths = [f"/proc/self/fd/{fd}" for fd in fds]
        r = subprocess.run([self.setfacl, *args, "--", *paths], pass_fds=fds, env=self.env, capture_output=True, text=True)
        if r.returncode != 0:
            self.failed = True
            sys.stderr.write(r.stderr.replace("/proc/self/fd/", "fd "))
        return r.returncode == 0

    def flush(self):
        fds, self.fds = self.fds, []
        if not fds:
            return
        try:
            if self.op == "grant":
                self._setfacl(["-m", _GRANT[self.kind].format(u=self.user)], fds)
            elif self._setfacl(["-x", f"u:{self.user}"], fds):
                plain = [fd for fd in fds if _mask_is_leftover(fd)]
                if plain:
                    self._setfacl(["-x", "m::"], plain)
        finally:
            for fd in fds:
                os.close(fd)


class _Counter:
    """Stands in for the Applier in the counting pass: closes what it is given, changes nothing."""

    def add(self, fd):
        os.close(fd)


def _walk(dfd, uid, applier, skipped, dev, seen, depth=0):
    """Add every directory and regular file below the O_PATH directory `dfd` that lives on file system `dev`. Symlinks,
    foreign owners, other file systems (a mount inside the tree) and objects that cannot be looked at are left out.
    `seen` counts every entry looked at (a one-item list); past MAX_OBJECTS the tree is refused."""
    if depth > 200:
        raise Refused("tree too deep", "oversize")
    try:
        rfd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=dfd)
        try:
            with os.scandir(rfd) as it:
                names = sorted(e.name for e in itertools.islice(it, MAX_OBJECTS - seen[0] + 1))
        finally:
            os.close(rfd)
    except OSError:
        skipped.append("(unreadable directory)")
        return
    seen[0] += len(names)
    if seen[0] > MAX_OBJECTS:
        raise Refused(f"tree has more than {MAX_OBJECTS} entries", "oversize")
    for name in names:
        try:
            fd = _open_path(name, dfd, directory=False)
        except FileNotFoundError:
            continue                            # vanished meanwhile
        except OSError:
            skipped.append(name)
            continue
        try:
            st = os.fstat(fd)
        except OSError:                         # e.g. EACCES on a FUSE mount
            skipped.append(name)
            os.close(fd)
            continue
        if (stat.S_ISLNK(st.st_mode) or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)) or not _owned(st, uid)
                or st.st_dev != dev):
            skipped.append(name)
            os.close(fd)
            continue
        if stat.S_ISDIR(st.st_mode):
            sub = os.dup(fd)
            try:
                applier.add(fd)
                _walk(sub, uid, applier, skipped, dev, seen, depth + 1)
            finally:
                os.close(sub)
        else:
            applier.add(fd)


def apply(op, kind, path, uid, user="itsec", setfacl="setfacl"):
    """grant or remove the read access of `user` on `path`. Returns 0 (done or gone), 1 (setfacl failed); raises Refused
    (also when the path cannot be looked at: stat and open errors are refusals)."""
    if op not in ("grant", "remove") or kind not in _WANT:
        raise ValueError("op is grant or remove, kind is x, r or R")
    try:
        fd = open_checked(path, uid)
    except FileNotFoundError:
        return 0
    applier = Applier(op, kind, user, setfacl)
    skipped = []
    try:
        st = _stat(fd, path)
        if not _WANT[kind](st.st_mode):
            raise Refused(f"{path}: not a {'file' if kind == 'r' else 'directory'}")
        top = os.dup(fd) if kind == "R" else -1
        try:
            if kind == "R":                     # first look only (a tree past MAX_OBJECTS is refused untouched), then change
                _walk(top, uid, _Counter(), [], st.st_dev, [0])
            own, fd = fd, -1                    # the applier owns it from here on
            applier.add(own)
            if kind == "R":
                _walk(top, uid, applier, skipped, st.st_dev, [0])
            applier.flush()
        finally:
            if top >= 0:
                os.close(top)
    finally:
        if fd >= 0:
            os.close(fd)
        for left in applier.fds:
            os.close(left)
    if skipped:
        sys.stderr.write(f"itsec-acl: {path}: left out {len(skipped)} symlink(s), foreign-owned, other-file-system or unreadable object(s) below it\n")
    return 1 if applier.failed else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--uid", type=int, required=True, help="the watched account's uid")
    ap.add_argument("--user", default="itsec", help="the account that gets the read access (default itsec)")
    ap.add_argument("--setfacl", default="setfacl", help=argparse.SUPPRESS)
    ap.add_argument("op", choices=["grant", "remove"])
    ap.add_argument("kind", choices=sorted(_WANT))
    ap.add_argument("path")
    a = ap.parse_args(argv)
    try:
        return apply(a.op, a.kind, a.path, a.uid, a.user, a.setfacl)
    except Refused as e:
        print(f"itsec-acl: refused: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"itsec-acl: {a.path}: {e.strerror}", file=sys.stderr)
        return 1
