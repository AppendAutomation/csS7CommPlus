using System.Collections.Generic;

namespace CsS7CommPlus.Backend
{
    /// <summary>Symbol metadata returned by a V3 backend browse.</summary>
    public class V3TagInfo
    {
        /// <summary>Full symbolic name.</summary>
        public string Name { get; set; } = string.Empty;
        /// <summary>Data-type name (e.g. "REAL", "INT", "BOOL").</summary>
        public string DataType { get; set; } = string.Empty;
        /// <summary>Numeric access area / object relation id.</summary>
        public uint AccessArea { get; set; }
        /// <summary>Local ids (LIDs) addressing the symbol within its object.</summary>
        public IReadOnlyList<int> Lids { get; set; } = new int[0];
    }

    /// <summary>One result from a batched read.</summary>
    public class V3ReadResult
    {
        /// <summary>The requested tag name.</summary>
        public string Name { get; set; } = string.Empty;
        /// <summary>Decoded value, or null on error.</summary>
        public object? Value { get; set; }
        /// <summary>True when the read succeeded.</summary>
        public bool Ok { get; set; }
        /// <summary>Error message when not ok.</summary>
        public string? Error { get; set; }
    }

    /// <summary>
    /// The protocol-version-3 session seam (spec Appendix C).  This is the exact
    /// analog of the Python library's optional <c>s7commplus</c> backend
    /// (s7p_v3.py): the integrity-protected handshake, browse, read and write
    /// are supplied by an external MIT-licensed implementation.  For C# that is
    /// HarpoS7 / the S7CommPlusDriver; an adapter implementing this interface
    /// lets <see cref="CsS7CommPlus.PLC"/> perform live Explore/Read/Write.
    ///
    /// When no backend is configured, the PLC's V3 methods return a clear
    /// status, mirroring pyS7commplus without its backend installed.
    /// </summary>
    public interface IV3Backend
    {
        /// <summary>Whether the session is open.</summary>
        bool Connected { get; }

        /// <summary>Open the integrity-protected V3 session (TLS handshake etc.).</summary>
        void Connect();

        /// <summary>Browse the symbol tree; returns one entry per symbol.</summary>
        IList<V3TagInfo> Tags(bool refresh = false);

        /// <summary>Read one symbol; returns the decoded value and its data-type name.</summary>
        V3ReadResult Read(string name);

        /// <summary>Write one symbol; <paramref name="datatypeOverride"/> may force a type.</summary>
        V3ReadResult Write(string name, object value, string? datatypeOverride = null);

        /// <summary>Read many symbols in batches of <paramref name="chunk"/> per request.</summary>
        IList<V3ReadResult> ReadMany(IEnumerable<string> names, int chunk = 40);

        /// <summary>CPU operating state ("RUN"/"STOP"/"UNKNOWN").</summary>
        string CpuState();

        /// <summary>Close the session.</summary>
        void Close();
    }
}
