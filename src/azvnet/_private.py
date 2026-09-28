"""Windows equivalents of azvnet's POSIX private-file invariants.

POSIX azvnet refuses symlinks (O_NOFOLLOW), requires the current user's uid, and
requires mode 0600/0700. Windows mode bits do not describe access, so the same
invariants are read from the object itself: no reparse point, the owner SID is
the current token user, and the DACL is protected and grants access only to that
user. Everything here is stdlib ctypes; azvnet keeps zero runtime dependencies.
"""

from __future__ import annotations

import sys

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes
    import errno
    import msvcrt
    import os
    from pathlib import Path

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _READ_CONTROL = 0x00020000
    _FILE_SHARE_READ = 0x1
    _FILE_SHARE_WRITE = 0x2
    _OPEN_EXISTING = 3
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_ATTRIBUTE_DIRECTORY = 0x10
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    _FILE_TYPE_DISK = 1
    _INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    _SE_FILE_OBJECT = 1
    _OWNER_SECURITY_INFORMATION = 0x1
    _DACL_SECURITY_INFORMATION = 0x4
    _SE_DACL_PROTECTED = 0x1000
    _ACCESS_ALLOWED_ACE_TYPE = 0
    _TOKEN_QUERY = 0x8
    _TOKEN_USER = 1
    _ACL_SIZE_INFORMATION = 2
    _SDDL_REVISION_1 = 1
    _ERROR_ALREADY_EXISTS = 183
    _REPARSE = "must not be a symlink, junction or other reparse point"

    class _FileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation", wintypes.FILETIME),
            ("access", wintypes.FILETIME),
            ("write", wintypes.FILETIME),
            ("volume", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

    class _AceHeader(ctypes.Structure):
        _fields_ = [
            ("type", ctypes.c_ubyte),
            ("flags", ctypes.c_ubyte),
            ("size", wintypes.WORD),
        ]

    class _AclSize(ctypes.Structure):
        _fields_ = [
            ("count", wintypes.DWORD),
            ("used", wintypes.DWORD),
            ("free", wintypes.DWORD),
        ]

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.DWORD),
            ("descriptor", ctypes.c_void_p),
            ("inherit", wintypes.BOOL),
        ]

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.GetFileType.argtypes = [wintypes.HANDLE]
    _kernel32.GetFileType.restype = wintypes.DWORD
    _kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_FileInformation),
    ]
    _kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _kernel32.CreateDirectoryW.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes),
    ]
    _advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.GetSecurityInfo.restype = wintypes.DWORD
    _advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int,
    ]
    _advapi32.GetAce.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    _advapi32.IsValidSid.argtypes = [ctypes.c_void_p]
    _advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR),
    ]
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]

    def _check(success: object) -> None:
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())

    def _user_sid() -> bytes:
        """The current token user's SID bytes."""
        token = wintypes.HANDLE()
        _check(_advapi32.OpenProcessToken(
            _kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token),
        ))
        try:
            size = wintypes.DWORD()
            _advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            _check(_advapi32.GetTokenInformation(
                token, _TOKEN_USER, buffer, size, ctypes.byref(size),
            ))
            # TOKEN_USER begins with SID_AND_ATTRIBUTES, whose first field is the SID pointer.
            sid = ctypes.c_void_p.from_buffer(buffer).value
            if not sid:
                raise OSError("the process token has no user SID")
            return ctypes.string_at(sid, _sid_length(sid))
        finally:
            _kernel32.CloseHandle(token)

    def _sid_length(sid: int) -> int:
        if not _advapi32.IsValidSid(sid):
            raise OSError("invalid SID")
        # SID: revision, sub-authority count, 6-byte authority, then 4 bytes each.
        return 8 + 4 * ctypes.c_ubyte.from_address(sid + 1).value

    def _user_sid_text() -> str:
        sid = ctypes.create_string_buffer(_user_sid())
        text = wintypes.LPWSTR()
        _check(_advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)))
        try:
            return str(text.value)
        finally:
            _kernel32.LocalFree(text)

    def _open(path: Path, access: int, *, directory: bool) -> int:
        flags = _FILE_FLAG_OPEN_REPARSE_POINT
        if directory:
            flags |= _FILE_FLAG_BACKUP_SEMANTICS
        handle = _kernel32.CreateFileW(
            str(path), access, _FILE_SHARE_READ | _FILE_SHARE_WRITE, None,
            _OPEN_EXISTING, flags, None,
        )
        if handle == _INVALID_HANDLE_VALUE or handle is None:
            raise ctypes.WinError(ctypes.get_last_error())
        return int(handle)

    def _violation(handle: int, *, directory: bool, protected: bool = True) -> str | None:
        """Why an open object is not a current-user-owned, current-user-only non-link.

        `protected` also requires a DACL that no parent can change by inheritance.
        """
        information = _FileInformation()
        _check(_kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)))
        if information.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            return _REPARSE
        if bool(information.attributes & _FILE_ATTRIBUTE_DIRECTORY) != directory:
            return "must be a directory" if directory else "must be a regular file"
        if not directory and _kernel32.GetFileType(handle) != _FILE_TYPE_DISK:
            return "must be a regular file"
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        code = _advapi32.GetSecurityInfo(
            handle, _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor),
        )
        if code:
            raise ctypes.WinError(code)
        private = "must have a DACL granting access only to the current user"
        if protected:
            private = "must have a protected DACL granting access only to the current user"
        try:
            user = ctypes.create_string_buffer(_user_sid())
            if not _advapi32.EqualSid(owner, user):
                return "must be owned by the current user"
            if not dacl.value:
                return private  # A NULL DACL grants everyone full access.
            control, revision = wintypes.WORD(), wintypes.DWORD()
            _check(_advapi32.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision),
            ))
            if protected and not control.value & _SE_DACL_PROTECTED:
                return private
            size = _AclSize()
            _check(_advapi32.GetAclInformation(
                dacl, ctypes.byref(size), ctypes.sizeof(size), _ACL_SIZE_INFORMATION,
            ))
            if not size.count:
                return private
            for index in range(size.count):
                entry = ctypes.c_void_p()
                _check(_advapi32.GetAce(dacl, index, ctypes.byref(entry)))
                address = entry.value or 0
                if _AceHeader.from_address(address).type != _ACCESS_ALLOWED_ACE_TYPE:
                    return private
                # ACCESS_ALLOWED_ACE: header, 4-byte mask, then the SID.
                if not _advapi32.EqualSid(address + 8, user):
                    return private
            return None
        finally:
            _kernel32.LocalFree(descriptor)

    def private_text(path: Path) -> tuple[str | None, str | None]:
        """A private regular file's text, or the reason it is not private.

        A reparse point raises OSError(ELOOP), as O_NOFOLLOW does on POSIX.
        """
        handle = _open(path, _GENERIC_READ | _READ_CONTROL, directory=False)
        try:
            reason = _violation(handle, directory=False)
            if reason == _REPARSE:
                raise OSError(errno.ELOOP, reason, str(path))
            if reason is None:
                descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY)
                handle = 0  # The descriptor now owns the handle.
                with os.fdopen(descriptor, encoding="utf-8") as stream:
                    return stream.read(), None
            return None, reason
        finally:
            if handle:
                _kernel32.CloseHandle(handle)

    def file_violation(path: Path, *, protected: bool = True) -> str | None:
        """Why a regular file is not current-user-owned and current-user-only, if it is not."""
        handle = _open(path, _READ_CONTROL, directory=False)
        try:
            return _violation(handle, directory=False, protected=protected)
        finally:
            _kernel32.CloseHandle(handle)

    def directory_violation(path: Path) -> str | None:
        """Why a directory is not current-user-owned and current-user-only, if it is not."""
        handle = _open(path, _READ_CONTROL, directory=True)
        try:
            return _violation(handle, directory=True)
        finally:
            _kernel32.CloseHandle(handle)

    def make_private_directory(path: Path) -> None:
        """Create a directory with a protected current-user-only DACL (like mode 0700).

        Its files inherit that DACL. An existing directory is left for the
        caller's verification, as `mkdir(exist_ok=True)` does on POSIX.
        """
        user = _user_sid_text()
        descriptor = ctypes.c_void_p()
        _check(_advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"O:{user}D:P(A;OICI;FA;;;{user})", _SDDL_REVISION_1,
            ctypes.byref(descriptor), None,
        ))
        try:
            attributes = _SecurityAttributes(
                ctypes.sizeof(_SecurityAttributes), descriptor.value, False,
            )
            if not _kernel32.CreateDirectoryW(str(path), ctypes.byref(attributes)):
                error = ctypes.get_last_error()
                if error != _ERROR_ALREADY_EXISTS:
                    raise ctypes.WinError(error)
        finally:
            _kernel32.LocalFree(descriptor)

    def sync_directory(path: Path) -> None:
        """Flush a directory's metadata, as fsync on an O_DIRECTORY descriptor does."""
        handle = _open(path, _GENERIC_READ | _GENERIC_WRITE, directory=True)
        try:
            _check(_kernel32.FlushFileBuffers(handle))
        finally:
            _kernel32.CloseHandle(handle)
