namespace UploadGuard;

/// <summary>The file types UploadGuard detects. Pass them to <see cref="UploadPolicy.Allow"/>.</summary>
public static class FileTypes
{
    /// <summary>JPEG image.</summary>
    public static FileType Jpeg { get; } = new("JPEG image", [".jpg", ".jpeg", ".jpe", ".jfif"], ["image/jpeg", "image/pjpeg", "image/jpg"]);

    /// <summary>PNG image.</summary>
    public static FileType Png { get; } = new("PNG image", [".png"], ["image/png", "image/x-png"]);

    /// <summary>GIF image.</summary>
    public static FileType Gif { get; } = new("GIF image", [".gif"], ["image/gif"]);

    /// <summary>WebP image.</summary>
    public static FileType Webp { get; } = new("WebP image", [".webp"], ["image/webp"]);

    /// <summary>BMP image.</summary>
    public static FileType Bmp { get; } = new("BMP image", [".bmp", ".dib"], ["image/bmp", "image/x-bmp", "image/x-ms-bmp"]);

    /// <summary>TIFF image.</summary>
    public static FileType Tiff { get; } = new("TIFF image", [".tif", ".tiff"], ["image/tiff"]);

    /// <summary>Windows icon.</summary>
    public static FileType Ico { get; } = new("ICO icon", [".ico"], ["image/x-icon", "image/vnd.microsoft.icon"]);

    /// <summary>HEIC or HEIF image.</summary>
    public static FileType Heic { get; } = new("HEIC image", [".heic", ".heif"], ["image/heic", "image/heif"]);

    /// <summary>AVIF image.</summary>
    public static FileType Avif { get; } = new("AVIF image", [".avif"], ["image/avif"]);

    /// <summary>SVG image. Rejected when it contains scripts, event handlers or <c>javascript:</c> URLs.</summary>
    public static FileType Svg { get; } = new("SVG image", [".svg"], ["image/svg+xml"]);

    /// <summary>PDF document. Rejected when it contains JavaScript, launch actions, embedded files, XFA or rich media.</summary>
    public static FileType Pdf { get; } = new("PDF document", [".pdf"], ["application/pdf"]);

    /// <summary>Word document without macros.</summary>
    public static FileType Docx { get; } = new("Word document", [".docx"], ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"]);

    /// <summary>Word document with macros.</summary>
    public static FileType Docm { get; } = new("Word macro-enabled document", [".docm"], ["application/vnd.ms-word.document.macroEnabled.12"]);

    /// <summary>Excel workbook without macros.</summary>
    public static FileType Xlsx { get; } = new("Excel workbook", [".xlsx"], ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]);

    /// <summary>Excel workbook with macros.</summary>
    public static FileType Xlsm { get; } = new("Excel macro-enabled workbook", [".xlsm"], ["application/vnd.ms-excel.sheet.macroEnabled.12"]);

    /// <summary>PowerPoint presentation without macros.</summary>
    public static FileType Pptx { get; } = new("PowerPoint presentation", [".pptx"], ["application/vnd.openxmlformats-officedocument.presentationml.presentation"]);

    /// <summary>PowerPoint presentation with macros.</summary>
    public static FileType Pptm { get; } = new("PowerPoint macro-enabled presentation", [".pptm"], ["application/vnd.ms-powerpoint.presentation.macroEnabled.12"]);

    /// <summary>Word 97-2003 document. Rejected when it contains a VBA project.</summary>
    public static FileType Doc { get; } = new("Word 97-2003 document", [".doc", ".dot"], ["application/msword"]);

    /// <summary>Excel 97-2003 workbook. Rejected when it contains a VBA project.</summary>
    public static FileType Xls { get; } = new("Excel 97-2003 workbook", [".xls"], ["application/vnd.ms-excel"]);

    /// <summary>PowerPoint 97-2003 presentation. Rejected when it contains a VBA project.</summary>
    public static FileType Ppt { get; } = new("PowerPoint 97-2003 presentation", [".ppt"], ["application/vnd.ms-powerpoint"]);

    /// <summary>OpenDocument text. Rejected when it contains macros.</summary>
    public static FileType Odt { get; } = new("OpenDocument text", [".odt"], ["application/vnd.oasis.opendocument.text"]);

    /// <summary>OpenDocument spreadsheet. Rejected when it contains macros.</summary>
    public static FileType Ods { get; } = new("OpenDocument spreadsheet", [".ods"], ["application/vnd.oasis.opendocument.spreadsheet"]);

    /// <summary>OpenDocument presentation. Rejected when it contains macros.</summary>
    public static FileType Odp { get; } = new("OpenDocument presentation", [".odp"], ["application/vnd.oasis.opendocument.presentation"]);

    /// <summary>Rich Text Format document.</summary>
    public static FileType Rtf { get; } = new("RTF document", [".rtf"], ["application/rtf", "text/rtf"]);

    /// <summary>Plain text: valid UTF-8 (or UTF-16 with a byte order mark) without control characters.</summary>
    public static FileType Text { get; } = new("Plain text", [".txt"], ["text/plain"]);

    /// <summary>CSV. Detected as plain text, so the extension decides between <see cref="Text"/> and CSV.</summary>
    public static FileType Csv { get; } = new("CSV", [".csv"], ["text/csv", "application/vnd.ms-excel", "text/plain"]);

    /// <summary>XML document (other than SVG).</summary>
    public static FileType Xml { get; } = new("XML document", [".xml"], ["application/xml", "text/xml"]);

    /// <summary>HTML document. Detected the way browsers sniff HTML, so it cannot hide behind another extension.</summary>
    public static FileType Html { get; } = new("HTML document", [".html", ".htm"], ["text/html"]);

    /// <summary>ZIP archive. Checked for zip bombs, unsafe paths and encryption.</summary>
    public static FileType Zip { get; } = new("ZIP archive", [".zip"], ["application/zip", "application/x-zip-compressed", "application/x-zip"]);

    /// <summary>GZIP archive. Checked for decompression bombs.</summary>
    public static FileType Gzip { get; } = new("GZIP archive", [".gz", ".tgz"], ["application/gzip", "application/x-gzip"]);

    /// <summary>7z archive. Detected only: its contents are not inspected.</summary>
    public static FileType SevenZip { get; } = new("7z archive", [".7z"], ["application/x-7z-compressed"]);

    /// <summary>RAR archive. Detected only: its contents are not inspected.</summary>
    public static FileType Rar { get; } = new("RAR archive", [".rar"], ["application/vnd.rar", "application/x-rar-compressed", "application/x-rar"]);

    /// <summary>TAR archive. Detected only: its contents are not inspected.</summary>
    public static FileType Tar { get; } = new("TAR archive", [".tar"], ["application/x-tar"]);

    /// <summary>MP3 audio.</summary>
    public static FileType Mp3 { get; } = new("MP3 audio", [".mp3"], ["audio/mpeg", "audio/mp3"]);

    /// <summary>WAV audio.</summary>
    public static FileType Wav { get; } = new("WAV audio", [".wav"], ["audio/wav", "audio/x-wav", "audio/wave", "audio/vnd.wave"]);

    /// <summary>Ogg audio or video.</summary>
    public static FileType Ogg { get; } = new("Ogg media", [".ogg", ".oga", ".ogv", ".opus"], ["audio/ogg", "video/ogg", "application/ogg", "audio/opus"]);

    /// <summary>FLAC audio.</summary>
    public static FileType Flac { get; } = new("FLAC audio", [".flac"], ["audio/flac", "audio/x-flac"]);

    /// <summary>M4A (MPEG-4) audio.</summary>
    public static FileType M4a { get; } = new("M4A audio", [".m4a"], ["audio/mp4", "audio/x-m4a", "audio/m4a"]);

    /// <summary>MP4 video.</summary>
    public static FileType Mp4 { get; } = new("MP4 video", [".mp4", ".m4v"], ["video/mp4", "video/x-m4v"]);

    /// <summary>QuickTime video.</summary>
    public static FileType Mov { get; } = new("QuickTime video", [".mov", ".qt"], ["video/quicktime"]);

    /// <summary>WebM video.</summary>
    public static FileType Webm { get; } = new("WebM video", [".webm"], ["video/webm", "audio/webm"]);

    /// <summary>Matroska video.</summary>
    public static FileType Mkv { get; } = new("Matroska video", [".mkv"], ["video/x-matroska"]);

    /// <summary>AVI video.</summary>
    public static FileType Avi { get; } = new("AVI video", [".avi"], ["video/x-msvideo", "video/avi", "video/msvideo"]);

    /// <summary>Windows executable or DLL. Detected so the error names it; never allow it.</summary>
    public static FileType Exe { get; } = new("Windows executable", [".exe", ".dll"], ["application/vnd.microsoft.portable-executable", "application/x-msdownload", "application/x-dosexec"]);

    /// <summary>Linux ELF executable or shared library.</summary>
    public static FileType Elf { get; } = new("ELF executable", [".elf", ".so"], ["application/x-elf", "application/x-executable"]);

    /// <summary>macOS Mach-O executable or library.</summary>
    public static FileType MachO { get; } = new("Mach-O executable", [".dylib"], ["application/x-mach-binary"]);

    /// <summary>Script that starts with <c>#!</c>.</summary>
    public static FileType ShellScript { get; } = new("Shell script", [".sh"], ["application/x-sh", "text/x-shellscript"]);

    /// <summary>Gets every type, in declaration order. Keep this last: static initializers run top to bottom.</summary>
    internal static IReadOnlyList<FileType> All { get; } =
    [
        Jpeg, Png, Gif, Webp, Bmp, Tiff, Ico, Heic, Avif, Svg,
        Pdf, Docx, Docm, Xlsx, Xlsm, Pptx, Pptm, Doc, Xls, Ppt, Odt, Ods, Odp, Rtf, Text, Csv, Xml, Html,
        Zip, Gzip, SevenZip, Rar, Tar,
        Mp3, Wav, Ogg, Flac, M4a, Mp4, Mov, Webm, Mkv, Avi,
        Exe, Elf, MachO, ShellScript,
    ];
}
