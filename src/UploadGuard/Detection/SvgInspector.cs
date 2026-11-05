using System.Xml;

namespace UploadGuard.Detection;

/// <summary>Rejects SVG that can run script: script-like elements, event handlers, script URLs and stylesheets.</summary>
internal static class SvgInspector
{
    private static readonly HashSet<string> ScriptElements = new(StringComparer.OrdinalIgnoreCase)
    {
        "script", "foreignObject", "iframe", "embed", "object", "handler", "listener",
    };

    private static readonly string[] ScriptUrls = ["javascript:", "vbscript:", "data:text/html", "data:image/svg+xml"];

    public static async Task<UploadError?> CheckAsync(Stream stream, CancellationToken cancellationToken)
    {
        var settings = new XmlReaderSettings
        {
            Async = true,
            DtdProcessing = DtdProcessing.Ignore, // many exporters write a DOCTYPE; never expand or fetch it
            XmlResolver = null,
            IgnoreComments = true,
            IgnoreWhitespace = true,
        };

        stream.Position = 0;
        try
        {
            using var reader = XmlReader.Create(stream, settings);
            while (await reader.ReadAsync())
            {
                cancellationToken.ThrowIfCancellationRequested();
                switch (reader.NodeType)
                {
                    case XmlNodeType.ProcessingInstruction when reader.Name.Equals("xml-stylesheet", StringComparison.OrdinalIgnoreCase):
                        return Active("The SVG links a stylesheet, which can run script.");
                    case XmlNodeType.Element when ScriptElements.Contains(reader.LocalName):
                        return Active($"The SVG contains a <{reader.LocalName}> element.");
                    case XmlNodeType.Element:
                        while (reader.MoveToNextAttribute())
                        {
                            if (reader.LocalName.StartsWith("on", StringComparison.OrdinalIgnoreCase))
                            {
                                return Active("The SVG contains an event handler attribute.");
                            }

                            if (HasScriptUrl(reader.Value))
                            {
                                return Active("The SVG contains a script URL.");
                            }
                        }

                        break;
                    case XmlNodeType.Text or XmlNodeType.CDATA when HasScriptUrl(reader.Value):
                        return Active("The SVG contains a script URL.");
                }
            }

            return null;
        }
        catch (XmlException)
        {
            return new(UploadErrorCode.Corrupt, "The SVG is not well-formed XML.");
        }
    }

    // Browsers drop whitespace and control characters inside a URL scheme ("java\tscript:"), so compare without them.
    private static bool HasScriptUrl(string value)
    {
        var compact = string.Concat(value.Where(c => c > ' '));
        return ScriptUrls.Any(url => compact.Contains(url, StringComparison.OrdinalIgnoreCase));
    }

    private static UploadError Active(string message) => new(UploadErrorCode.ActiveContent, message);
}
