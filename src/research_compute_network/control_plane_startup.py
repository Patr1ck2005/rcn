"""Fixed Windows startup and crash-recovery contract for the Control Plane."""

from __future__ import annotations

import subprocess
import sys
import csv
import io
import json
import tempfile
from pathlib import Path
from xml.sax.saxutils import escape

from .runtime_policy import PACKAGE_VERSION, STABLE_RUNTIME_VERSION


CONTROL_PLANE_TASK = "ResearchComputeNetwork-ControlPlane"
CONTROL_PLANE_MANAGER = "Research Compute Network Control.exe"


def build_control_plane_manager_source() -> str:
    """Return the Windows GUI-subsystem manager used for service control."""

    return r'''using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Management;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

internal static class RcnControlProgram
{
    private const string DefaultTaskName = "ResearchComputeNetwork-ControlPlane";
    private const string DefaultPointer = @"D:\ResearchComputeNetwork\control-plane\runtime\current.json";
    private const string ConsoleUrl = "http://127.0.0.1:8765/app/fleet";

    [STAThread]
    private static int Main(string[] args)
    {
        bool unattended = Array.IndexOf(args, "--run") >= 0 || Array.IndexOf(args, "--stop") >= 0;
        try
        {
            Dictionary<string, string> options = ParseOptions(args);
            if (options.ContainsKey("run"))
                return RunControlPlane(GetOption(options, "runtime-pointer", DefaultPointer));
            if (options.ContainsKey("stop"))
                return StopControlPlane(GetOption(options, "runtime-pointer", DefaultPointer));

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new ControlForm(
                GetOption(options, "task-name", DefaultTaskName),
                GetOption(options, "runtime-pointer", DefaultPointer)));
            return 0;
        }
        catch (Exception error)
        {
            if (unattended)
            {
                // A SYSTEM/session-0 task must never wait for a hidden dialog.
                // Record types/codes only; exception text may contain secrets.
                Dictionary<string, string> failedOptions = ParseOptions(args);
                RecordManagerEvent(GetOption(failedOptions, "runtime-pointer", DefaultPointer),
                    "manager_error", error.GetType().FullName, error.HResult, null);
                return 1;
            }
            MessageBox.Show(error.Message, "Research Compute Network", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    private static Dictionary<string, string> ParseOptions(string[] args)
    {
        Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int index = 0; index < args.Length; index++)
        {
            string value = args[index];
            if (!value.StartsWith("--", StringComparison.Ordinal))
                continue;
            string key = value.Substring(2);
            string optionValue = "true";
            if (index + 1 < args.Length && !args[index + 1].StartsWith("--", StringComparison.Ordinal))
                optionValue = args[++index];
            result[key] = optionValue;
        }
        return result;
    }

    private static string GetOption(Dictionary<string, string> options, string name, string fallback)
    {
        string value;
        return options.TryGetValue(name, out value) ? value : fallback;
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }

    private static string ReadString(Dictionary<string, object> pointer, string key)
    {
        object value;
        if (!pointer.TryGetValue(key, out value) || value == null)
            throw new InvalidDataException("Runtime pointer is missing " + key + ".");
        return Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static void RecordManagerEvent(string pointerValue, string kind, string errorType, int code, int? childPid)
    {
        // The administrator-provisioned pointer and sibling startup directory
        // share the protected RCN_HOME ACL; no environment/command/token dump.
        try
        {
            string root = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetFullPath(pointerValue)));
            string directory = Path.Combine(root, "startup");
            Directory.CreateDirectory(directory);
            Dictionary<string, object> record = new Dictionary<string, object>();
            record["at"] = DateTime.UtcNow.ToString("o");
            record["event"] = kind;
            record["manager_pid"] = Process.GetCurrentProcess().Id;
            record["child_pid"] = childPid;
            record["code"] = code;
            record["error_type"] = errorType;
            string line = new JavaScriptSerializer().Serialize(record) + Environment.NewLine;
            File.AppendAllText(Path.Combine(directory, "manager.events.jsonl"), line);
        }
        catch (Exception loggingError)
        {
            // Preserve a failing task result even if the disk/ACL also blocks
            // durable diagnostics. Never replace failure with a GUI dialog.
            Console.Error.WriteLine("RCN manager diagnostic write failed: " + loggingError.GetType().FullName);
        }
    }

    private static int RunControlPlane(string pointerValue)
    {
        string pointerPath = Path.GetFullPath(pointerValue);
        if (!File.Exists(pointerPath))
            throw new FileNotFoundException("Control Plane runtime pointer was not found.", pointerPath);
        JavaScriptSerializer serializer = new JavaScriptSerializer();
        Dictionary<string, object> pointer = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(pointerPath));
        string runtimeRoot = Path.GetFullPath(ReadString(pointer, "runtime_root"));
        string python = Path.GetFullPath(ReadString(pointer, "python_executable"));
        string rootPrefix = runtimeRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!python.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Control Plane Python must remain inside the selected runtime root.");
        if (!File.Exists(python))
            throw new FileNotFoundException("Control Plane Python was not found.", python);

        string arguments = "-m research_compute_network.cli --database-url " + Quote(ReadString(pointer, "database_url"))
            + " serve --host " + Quote(ReadString(pointer, "host"))
            + " --port " + Quote(ReadString(pointer, "port"));
        object requireAuth;
        if (pointer.TryGetValue("require_auth", out requireAuth) && Convert.ToBoolean(requireAuth))
            arguments += " --require-auth";
        object candidates;
        IEnumerable candidateValues = null;
        if (pointer.TryGetValue("candidate_runtime_versions", out candidates) && !(candidates is string))
            candidateValues = candidates as IEnumerable;
        if (candidateValues != null)
        {
            foreach (object candidate in candidateValues)
                arguments += " --canary-runtime-version " + Quote(Convert.ToString(candidate));
        }

        ProcessStartInfo start = new ProcessStartInfo();
        start.FileName = python;
        start.Arguments = arguments;
        start.WorkingDirectory = runtimeRoot;
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.WindowStyle = ProcessWindowStyle.Hidden;
        start.EnvironmentVariables["RCN_CONTROL_PLANE_DEPLOYMENT_ID"] = ReadString(pointer, "deployment_id");
        start.EnvironmentVariables["RCN_CONTROL_PLANE_RUNTIME_ROOT"] = runtimeRoot;
        start.EnvironmentVariables["RCN_CONTROL_PLANE_PYTHON_EXECUTABLE"] = python;
        RecordManagerEvent(pointerPath, "launch_requested", null, 0, null);
        using (Process child = Process.Start(start))
        {
            RecordManagerEvent(pointerPath, "child_started", null, 0, child.Id);
            child.WaitForExit();
            RecordManagerEvent(pointerPath, "child_exited", null, child.ExitCode, child.Id);
            return child.ExitCode;
        }
    }

    private static int StopControlPlane(string pointerValue)
    {
        string pointerPath = Path.GetFullPath(pointerValue);
        if (!File.Exists(pointerPath))
            return 0;
        JavaScriptSerializer serializer = new JavaScriptSerializer();
        Dictionary<string, object> pointer = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(pointerPath));
        string database = ReadString(pointer, "database_url");
        string managerName = Path.GetFileNameWithoutExtension(Process.GetCurrentProcess().MainModule.FileName);
        List<int> roots = new List<int>();
        using (ManagementObjectSearcher search = new ManagementObjectSearcher(
            "SELECT ProcessId, ParentProcessId, Name, CommandLine FROM Win32_Process"))
        {
            foreach (ManagementObject item in search.Get())
            {
                string command = Convert.ToString(item["CommandLine"], System.Globalization.CultureInfo.InvariantCulture) ?? "";
                string name = Convert.ToString(item["Name"], System.Globalization.CultureInfo.InvariantCulture) ?? "";
                if (name.Equals("python.exe", StringComparison.OrdinalIgnoreCase)
                    && command.IndexOf("research_compute_network.cli", StringComparison.OrdinalIgnoreCase) >= 0
                    && command.IndexOf(database, StringComparison.OrdinalIgnoreCase) >= 0
                    && command.IndexOf("--port", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    roots.Add(Convert.ToInt32(item["ProcessId"], System.Globalization.CultureInfo.InvariantCulture));
                }
            }
        }
        foreach (int processId in roots)
            KillProcessTree(processId);
        ProcessStartInfo endTask = new ProcessStartInfo();
        endTask.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe");
        endTask.Arguments = "/End /TN " + Quote(DefaultTaskName);
        endTask.UseShellExecute = false;
        endTask.CreateNoWindow = true;
        endTask.WindowStyle = ProcessWindowStyle.Hidden;
        using (Process process = Process.Start(endTask))
            process.WaitForExit(15000);
        return 0;
    }

    private static void KillProcessTree(int processId)
    {
        using (ManagementObjectSearcher search = new ManagementObjectSearcher(
            "SELECT ProcessId, ParentProcessId FROM Win32_Process"))
        {
            foreach (ManagementObject item in search.Get())
            {
                int parent = Convert.ToInt32(item["ParentProcessId"], System.Globalization.CultureInfo.InvariantCulture);
                if (parent == processId)
                    KillProcessTree(Convert.ToInt32(item["ProcessId"], System.Globalization.CultureInfo.InvariantCulture));
            }
        }
        try { Process.GetProcessById(processId).Kill(); } catch { }
    }

    private sealed class ControlForm : Form
    {
        private readonly string taskName;
        private readonly string pointerPath;
        private readonly Label status;
        private readonly Button startButton;
        private readonly Button stopButton;
        private readonly Timer timer;

        internal ControlForm(string taskNameValue, string pointerPathValue)
        {
            taskName = taskNameValue;
            pointerPath = pointerPathValue;
            Text = "Research Compute Network";
            ClientSize = new Size(520, 250);
            MinimumSize = new Size(536, 289);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(20, 23, 31);
            ForeColor = Color.FromArgb(238, 241, 247);
            Font = new Font("Segoe UI", 10F);

            Label title = new Label();
            title.Text = "Research Compute Network";
            title.Font = new Font("Segoe UI Semibold", 18F);
            title.Location = new Point(28, 25);
            title.AutoSize = true;
            Controls.Add(title);

            status = new Label();
            status.Location = new Point(31, 76);
            status.Size = new Size(455, 48);
            status.ForeColor = Color.FromArgb(174, 184, 201);
            Controls.Add(status);

            startButton = MakeButton("Start", 31, Color.FromArgb(32, 122, 78));
            startButton.Click += delegate { RunTask("/Run"); RefreshStatus(); };
            Controls.Add(startButton);

            stopButton = MakeButton("Stop", 151, Color.FromArgb(164, 65, 65));
            stopButton.Click += delegate
            {
                if (MessageBox.Show("Stop the Control Plane and Dispatcher? Running remote calculations are not terminated.",
                    "Research Compute Network", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
                {
                    RunManager("--stop --runtime-pointer " + Quote(pointerPath));
                    RefreshStatus();
                }
            };
            Controls.Add(stopButton);

            Button openButton = MakeButton("Open console", 271, Color.FromArgb(48, 92, 160));
            openButton.Width = 130;
            openButton.Click += delegate { Process.Start(new ProcessStartInfo(ConsoleUrl) { UseShellExecute = true }); };
            Controls.Add(openButton);

            Button refreshButton = MakeButton("Refresh", 411, Color.FromArgb(67, 73, 87));
            refreshButton.Width = 78;
            refreshButton.Click += delegate { RefreshStatus(); };
            Controls.Add(refreshButton);

            Label detail = new Label();
            detail.Text = "Task: " + taskName + "\r\nPointer: " + pointerPath;
            detail.Location = new Point(31, 190);
            detail.Size = new Size(458, 42);
            detail.ForeColor = Color.FromArgb(120, 130, 148);
            detail.Font = new Font("Segoe UI", 8.5F);
            Controls.Add(detail);

            timer = new Timer();
            timer.Interval = 3000;
            timer.Tick += delegate { RefreshStatus(); };
            timer.Start();
            Shown += delegate { RefreshStatus(); };
        }

        private Button MakeButton(string text, int x, Color color)
        {
            Button button = new Button();
            button.Text = text;
            button.Location = new Point(x, 132);
            button.Size = new Size(108, 38);
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderSize = 0;
            button.BackColor = color;
            button.ForeColor = Color.White;
            button.Cursor = Cursors.Hand;
            return button;
        }

        private void RunTask(string operation)
        {
            ProcessStartInfo info = new ProcessStartInfo();
            info.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe");
            info.Arguments = operation + " /TN " + Quote(taskName);
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.WindowStyle = ProcessWindowStyle.Hidden;
            using (Process process = Process.Start(info))
            {
                process.WaitForExit(15000);
                if (process.ExitCode != 0)
                    MessageBox.Show("Windows Task Scheduler rejected the operation.", Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void RunManager(string arguments)
        {
            string executable = Process.GetCurrentProcess().MainModule.FileName;
            ProcessStartInfo info = new ProcessStartInfo();
            info.FileName = executable;
            info.Arguments = arguments;
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.WindowStyle = ProcessWindowStyle.Hidden;
            using (Process process = Process.Start(info))
                process.WaitForExit(20000);
        }

        private async void RefreshStatus()
        {
            bool listening = await IsListening();
            status.Text = listening
                ? "Running - http://127.0.0.1:8765"
                : "Stopped - the local console is unavailable";
            status.ForeColor = listening ? Color.FromArgb(95, 210, 145) : Color.FromArgb(235, 152, 107);
            startButton.Enabled = !listening;
            stopButton.Enabled = listening;
        }

        private static async Task<bool> IsListening()
        {
            using (TcpClient client = new TcpClient())
            {
                try
                {
                    Task connect = client.ConnectAsync("127.0.0.1", 8765);
                    Task completed = await Task.WhenAny(connect, Task.Delay(800));
                    return completed == connect && client.Connected;
                }
                catch { return false; }
            }
        }
    }
}
'''


def build_control_plane_manager(path: str | Path) -> Path:
    """Compile the no-console Windows manager used by operators and Task Scheduler."""

    output = Path(path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rcn-control-manager-") as temporary:
        source = Path(temporary) / "RcnControl.cs"
        source.write_text(build_control_plane_manager_source(), encoding="ascii")
        source_text = str(source).replace("'", "''")
        output_text = str(output).replace("'", "''")
        command = (
            "$ErrorActionPreference='Stop'; "
            f"Add-Type -Path '{source_text}' -OutputAssembly '{output_text}' "
            "-OutputType WindowsApplication "
            "-ReferencedAssemblies System,System.Windows.Forms,System.Drawing,System.Web.Extensions,System.Management"
        )
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if completed.returncode != 0 or not output.is_file():
            raise RuntimeError((completed.stderr or completed.stdout).strip() or "manager build failed")
    return output


def build_control_plane_launcher_script() -> str:
    """Return the stable script used by the scheduled task across releases."""

    return r'''param(
  [Parameter(Mandatory=$true)][string]$RuntimePointer
)
$ErrorActionPreference = "Stop"
$pointerPath = [IO.Path]::GetFullPath($RuntimePointer)
if (-not (Test-Path -LiteralPath $pointerPath -PathType Leaf)) {
  throw "Control Plane runtime pointer not found: $pointerPath"
}
$pointer = Get-Content -LiteralPath $pointerPath -Raw -Encoding UTF8 | ConvertFrom-Json
$runtimeRoot = [IO.Path]::GetFullPath([string]$pointer.runtime_root)
$python = [IO.Path]::GetFullPath([string]$pointer.python_executable)
if (-not $python.StartsWith($runtimeRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Control Plane Python must remain inside the selected runtime root"
}
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
  throw "Control Plane Python not found: $python"
}
$arguments = @(
  '-m', 'research_compute_network.cli',
  '--database-url', [string]$pointer.database_url,
  'serve', '--host', [string]$pointer.host, '--port', [string]$pointer.port
)
if ([bool]$pointer.require_auth) { $arguments += '--require-auth' }
foreach ($version in @($pointer.candidate_runtime_versions)) {
  $arguments += @('--canary-runtime-version', [string]$version)
}
$env:RCN_CONTROL_PLANE_DEPLOYMENT_ID = [string]$pointer.deployment_id
$env:RCN_CONTROL_PLANE_RUNTIME_ROOT = $runtimeRoot
$env:RCN_CONTROL_PLANE_PYTHON_EXECUTABLE = $python
$child = Start-Process -FilePath $python -ArgumentList $arguments -WindowStyle Hidden -PassThru -Wait
exit $child.ExitCode
'''


def write_control_plane_runtime_pointer(
    path: str | Path,
    *,
    database_url: str,
    python_executable: str | Path,
    host: str,
    port: int,
    allow_local_trusted: bool,
    canary_runtime_versions: list[str] | tuple[str, ...] = (),
    deployment_id: str | None = None,
) -> Path:
    pointer = Path(path).resolve()
    executable = Path(python_executable).resolve()
    runtime_root = executable.parent.parent
    payload = {
        "schema_version": 1,
        "deployment_id": deployment_id or runtime_root.name,
        "package_version": PACKAGE_VERSION,
        "worker_runtime_version": STABLE_RUNTIME_VERSION,
        "runtime_root": str(runtime_root),
        "python_executable": str(executable),
        "database_url": database_url,
        "host": host,
        "port": port,
        "require_auth": not allow_local_trusted,
        "candidate_runtime_versions": list(canary_runtime_versions),
    }
    pointer.parent.mkdir(parents=True, exist_ok=True)
    temporary = pointer.with_suffix(pointer.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(pointer)
    return pointer


def build_control_plane_task_xml(
    *,
    database_url: str,
    python_executable: str | Path | None = None,
    principal_id: str = "S-1-5-18",
    startup: str = "boot",
    host: str = "127.0.0.1",
    port: int = 8765,
    allow_local_trusted: bool = False,
    canary_runtime_versions: list[str] | tuple[str, ...] = (),
    launcher_script: str | Path | None = None,
    manager_executable: str | Path | None = None,
    runtime_pointer: str | Path | None = None,
) -> str:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("automatic Control Plane startup currently supports loopback only")
    if not 1 <= port <= 65535:
        raise ValueError("Control Plane port must be between 1 and 65535")
    if startup not in {"boot", "logon"}:
        raise ValueError("Control Plane startup must be boot or logon")
    if runtime_pointer is None and (launcher_script is not None or manager_executable is not None):
        raise ValueError("a launcher requires a runtime pointer")
    if manager_executable is not None and launcher_script is not None:
        raise ValueError("select either the executable manager or the legacy script launcher")
    if manager_executable is not None and runtime_pointer is not None:
        executable = str(Path(manager_executable).resolve())
        arguments = f'--run --runtime-pointer "{Path(runtime_pointer).resolve()}"'
    elif launcher_script is not None and runtime_pointer is not None:
        executable = "powershell.exe"
        arguments = (
            '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass '
            f'-File "{Path(launcher_script).resolve()}" '
            f'-RuntimePointer "{Path(runtime_pointer).resolve()}"'
        )
    else:
        canary_args = "".join(
            f' --canary-runtime-version {escape(str(version))}'
            for version in canary_runtime_versions
        )
        arguments = (
            f'-m research_compute_network.cli --database-url "{database_url}" '
            f'serve --host {host} --port {port}'
            f'{"" if allow_local_trusted else " --require-auth"}{canary_args}'
        )
        executable = str(Path(python_executable).resolve()) if python_executable else sys.executable
    trigger = (
        "<BootTrigger><Enabled>true</Enabled><Delay>PT15S</Delay></BootTrigger>"
        if startup == "boot"
        else f"<LogonTrigger><Enabled>true</Enabled><UserId>{escape(principal_id)}</UserId></LogonTrigger>"
    )
    principal = (
        f'<Principal id="Author"><UserId>{escape(principal_id)}</UserId><RunLevel>HighestAvailable</RunLevel></Principal>'
        if startup == "boot"
        else (
            f'<Principal id="Author"><UserId>{escape(principal_id)}</UserId>'
            "<LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal>"
        )
    )
    return f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Research Compute Network Control Plane with Dispatcher desired-state recovery</Description></RegistrationInfo>
  <Triggers>{trigger}</Triggers>
  <Principals>{principal}</Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>{escape(executable)}</Command><Arguments>{escape(arguments)}</Arguments></Exec></Actions>
</Task>
'''


def install_control_plane_startup(
    *,
    database_url: str,
    state_root: str | Path,
    python_executable: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    allow_local_trusted: bool = False,
    canary_runtime_versions: list[str] | tuple[str, ...] = (),
) -> dict:
    root = Path(state_root).resolve()
    executable = Path(python_executable).resolve() if python_executable else Path(sys.executable).resolve()
    if not executable.is_file():
        raise FileNotFoundError(f"Control Plane Python executable not found: {executable}")
    root.mkdir(parents=True, exist_ok=True)
    launcher_path = root / "control-plane-launch.ps1"
    launcher_path.write_text(build_control_plane_launcher_script(), encoding="utf-8")
    manager_path = root / CONTROL_PLANE_MANAGER
    build_control_plane_manager(manager_path)
    runtime_pointer = root.parent / "runtime" / "current.json"
    write_control_plane_runtime_pointer(
        runtime_pointer,
        database_url=database_url,
        python_executable=executable,
        host=host,
        port=port,
        allow_local_trusted=allow_local_trusted,
        canary_runtime_versions=canary_runtime_versions,
    )
    xml_path = root / "control-plane-startup.xml"
    xml_path.write_text(
        build_control_plane_task_xml(
            database_url=database_url,
            python_executable=executable,
            host=host,
            port=port,
            allow_local_trusted=allow_local_trusted,
            canary_runtime_versions=canary_runtime_versions,
            manager_executable=manager_path,
            runtime_pointer=runtime_pointer,
        ),
        encoding="utf-16",
    )
    completed = subprocess.run(
        ["schtasks.exe", "/Create", "/TN", CONTROL_PLANE_TASK, "/XML", str(xml_path), "/F"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    startup = "boot"
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        if "access is denied" not in detail.lower():
            raise RuntimeError(detail)
        identity = subprocess.run(
            ["whoami.exe", "/user", "/fo", "csv", "/nh"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if identity.returncode != 0:
            raise RuntimeError(detail)
        rows = list(csv.reader(io.StringIO(identity.stdout)))
        if not rows or len(rows[0]) < 2:
            raise RuntimeError("unable to resolve the current Windows identity for logon startup")
        principal_id = rows[0][1].strip()
        startup = "logon"
        xml_path.write_text(
            build_control_plane_task_xml(
                database_url=database_url,
                python_executable=executable,
                principal_id=principal_id,
                startup=startup,
                host=host,
                port=port,
                allow_local_trusted=allow_local_trusted,
                canary_runtime_versions=canary_runtime_versions,
                launcher_script=launcher_path,
                runtime_pointer=runtime_pointer,
            ),
            encoding="utf-16",
        )
        completed = subprocess.run(
            ["schtasks.exe", "/Create", "/TN", CONTROL_PLANE_TASK, "/XML", str(xml_path), "/F"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if completed.returncode != 0:
            raise RuntimeError((completed.stderr or completed.stdout).strip())
    return {
        "task_name": CONTROL_PLANE_TASK,
        "xml_path": str(xml_path),
        "startup": startup,
        "crash_recovery": "restart_after_1m",
        "dispatcher_recovery": "desired_state",
        "python_executable": str(executable),
        "launcher_script": str(launcher_path),
        "manager_executable": str(manager_path),
        "runtime_pointer": str(runtime_pointer),
        "startup_contract": "no_console_manager_with_atomic_runtime_pointer",
        "authentication": "local_trusted" if allow_local_trusted else "personal_token_required",
    }


def remove_control_plane_startup() -> dict:
    completed = subprocess.run(
        ["schtasks.exe", "/Delete", "/TN", CONTROL_PLANE_TASK, "/F"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode not in {0, 1}:
        raise RuntimeError((completed.stderr or completed.stdout).strip())
    return {"task_name": CONTROL_PLANE_TASK, "removed": completed.returncode == 0}
