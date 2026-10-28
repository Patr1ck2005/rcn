// Stable, per-user entry. Compiled at release time with the inbox .NET compiler.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Web.Script.Serialization;

internal static class RcnAgentLauncher {
    static void Unlinked(string path) {
        for (var current = new FileInfo(Path.GetFullPath(path)); current != null;) {
            if ((File.Exists(current.FullName) || Directory.Exists(current.FullName)) &&
                (File.GetAttributes(current.FullName) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException();
            var parent = Path.GetDirectoryName(current.FullName);
            current = String.IsNullOrEmpty(parent) ? null : new FileInfo(parent);
        }
    }
    static void PrivateFile(string path) {
        Unlinked(path);
        var acl = File.GetAccessControl(path);
        var owner = (SecurityIdentifier)acl.GetOwner(typeof(SecurityIdentifier));
        var own = WindowsIdentity.GetCurrent().User.Value;
        if (owner.Value != own) throw new InvalidDataException();
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier))) {
            var id = rule.IdentityReference.Value;
            if (rule.AccessControlType == AccessControlType.Allow && id != own &&
                id != "S-1-5-18" && id != "S-1-5-32-544" &&
                (rule.FileSystemRights & (FileSystemRights.Write | FileSystemRights.Delete |
                    FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership)) != 0)
                throw new InvalidDataException();
        }
    }
    static string Hash(string path) {
        using (var stream = File.OpenRead(path)) using (var hash = SHA256.Create())
            return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }
    static string Quote(string value) {
        var b = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value) {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { b.Append('\\', slashes * 2 + 1); b.Append(c); }
            else { b.Append('\\', slashes); b.Append(c); }
            slashes = 0;
        }
        b.Append('\\', slashes * 2); return b.Append('"').ToString();
    }
    static int Main(string[] args) {
        Console.OutputEncoding = new UTF8Encoding(false);
        try {
            var root = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName;
            var marker = Path.Combine(root, "active-version.json"); PrivateFile(marker);
            if (new FileInfo(marker).Length > 16384) throw new InvalidDataException();
            var state = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(marker));
            var python = Path.GetFullPath((string)state["python_path"]);
            var release = Path.GetFullPath((string)state["release_root"]);
            if (!String.Equals(python, Path.Combine(release, "runtime", "python", "python.exe"), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException();
            Unlinked(python);
            var manifestPath = Path.Combine(release, "member-software-release.json"); Unlinked(manifestPath);
            if (Hash(manifestPath) != (string)state["manifest_sha256"]) throw new InvalidDataException();
            if (Hash(python) != (string)state["python_sha256"]) throw new InvalidDataException();
            var manifest = new JavaScriptSerializer { MaxJsonLength = 8 * 1024 * 1024 }
                .Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(release, "member-software-release.json")));
            var files = (Dictionary<string, object>)manifest["runtime_files"];
            if ((string)files["python/python.exe"] != (string)state["python_sha256"] ||
                (string)state["launcher_sha256"] != Hash(System.Reflection.Assembly.GetExecutingAssembly().Location))
                throw new InvalidDataException();
            var command = new StringBuilder("-B -m research_compute_network.agent_access");
            foreach (var arg in args) command.Append(' ').Append(Quote(arg));
            var start = new ProcessStartInfo(python, command.ToString()) {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
            };
            start.EnvironmentVariables["PYTHONNOUSERSITE"] = "1";
            start.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8";
            using (var process = new Process { StartInfo = start }) {
                process.OutputDataReceived += (sender, e) => { if (e.Data != null) Console.Out.WriteLine(e.Data); };
                process.ErrorDataReceived += (sender, e) => { if (e.Data != null) Console.Error.WriteLine(e.Data); };
                process.Start(); process.BeginOutputReadLine(); process.BeginErrorReadLine();
                process.WaitForExit(); return process.ExitCode;
            }
        } catch {
            Console.Error.WriteLine("{\"reason_code\":\"member_agent_launcher_unavailable\",\"message\":\"Open the member client and run connection diagnostics, or reinstall the same Setup.\"}");
            return 2;
        }
    }
}
