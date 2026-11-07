using System.Buffers;

namespace UploadGuard.Detection;

/// <summary>
/// Rejects file names that only an attacker sends. Stored files never use the client's name, so this is about
/// spotting tricks (paths, NUL bytes, bidi overrides, "shell.php.jpg") and keeping the name safe to display.
/// </summary>
internal static class FileNameValidator
{
    private static readonly SearchValues<char> Forbidden = SearchValues.Create(
        "/\\:*?\"<>|" +
        "​‌‍‎‏‪‫‬‭‮⁠⁦⁧⁨⁩﻿");

    private static readonly HashSet<string> DeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    // Extensions a misconfigured server executes even when they are not last ("shell.php.jpg" on Apache).
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "php", "php3", "php4", "php5", "php7", "phtml", "phar", "asp", "aspx", "ashx", "asmx", "axd", "cer", "config",
        "jsp", "jspx", "cgi", "pl", "py", "rb", "sh", "bat", "cmd", "com", "exe", "dll", "scr", "msi", "ps1", "vbs",
        "js", "mjs", "jar", "hta", "htm", "html", "shtml", "svg", "lnk", "htaccess",
    };

    /// <summary>Returns why the name is rejected, or null when it is fine.</summary>
    public static string? Check(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return "The file name is empty.";
        }

        if (name.Length > 255)
        {
            return "The file name is longer than 255 characters.";
        }

        if (name.Any(char.IsControl))
        {
            return "The file name contains control characters.";
        }

        if (name.AsSpan().ContainsAny(Forbidden))
        {
            return "The file name contains a path, a reserved character or an invisible formatting character.";
        }

        if (name[0] is '.' or ' ' || name[^1] is '.' or ' ')
        {
            return "The file name starts or ends with a dot or a space.";
        }

        var parts = name.Split('.');
        if (DeviceNames.Contains(parts[0].TrimEnd()))
        {
            return "The file name is a reserved device name.";
        }

        for (var i = 1; i < parts.Length - 1; i++)
        {
            if (ExecutableExtensions.Contains(parts[i]))
            {
                return $"The file name hides an executable extension (.{parts[i].ToLowerInvariant()}).";
            }
        }

        return null;
    }
}
