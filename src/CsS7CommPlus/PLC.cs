using System;
using System.Collections.Generic;
using System.Linq;
using CsS7CommPlus.Backend;
using CsS7CommPlus.Codec;
using CsS7CommPlus.Constants;
using CsS7CommPlus.Helpers;
using CsS7CommPlus.Models;

namespace CsS7CommPlus
{
    /// <summary>
    /// Main class for communicating with Siemens S7-1200/1500 PLCs over
    /// S7comm-plus.  Interface modelled on pylogix / pyS7commplus.
    ///
    /// The clear-text protocol-version-1 path (connect, CreateObject identity)
    /// works directly.  The integrity-protected protocol-version-3 path
    /// (Explore / Read / Write) is delegated to a pluggable
    /// <see cref="IV3Backend"/> — the C# analog of pyS7commplus's optional
    /// <c>s7commplus</c> dependency.  Per spec Appendix C, wire HarpoS7 /
    /// the S7CommPlusDriver as that backend to enable live V3 operations.
    /// </summary>
    public class PLC : IDisposable
    {
        /// <summary>Target PLC IP address.</summary>
        public string IPAddress { get; set; } = string.Empty;
        /// <summary>ISO-on-TCP port (default 102).</summary>
        public int Port { get; set; } = S7PlusConstants.IsoTcpPort;
        /// <summary>Socket timeout in seconds (default 5.0).</summary>
        public double SocketTimeout { get; set; } = 5.0;
        /// <summary>Client access-point TSAP (spec §5; configurable).</summary>
        public string SourceTsap { get; set; } = S7PlusConstants.DefaultSrcTsap;
        /// <summary>Destination TSAP (SIMATIC-ROOT-HMI).</summary>
        public string DestTsap { get; set; } = S7PlusConstants.DestTsap;
        /// <summary>Use the TLS V3 variant (S7-1200 FW4+); default true.</summary>
        public bool UseTLS { get; set; } = true;
        /// <summary>Optional PLC legitimation password.</summary>
        public string? Password { get; set; }

        /// <summary>Integrity provider for direct v3 framing (default: none).</summary>
        public IIntegrityProvider Integrity { get; set; } = new NullIntegrityProvider();

        /// <summary>A live V3 backend, if already created/connected.</summary>
        public IV3Backend? V3Backend { get; set; }

        /// <summary>
        /// Factory that creates a V3 backend for this PLC on demand (the analog
        /// of pyS7commplus auto-instantiating its s7commplus session).  Set this
        /// to an adapter over HarpoS7 / the S7CommPlusDriver to enable live V3.
        /// </summary>
        public Func<PLC, IV3Backend>? V3BackendFactory { get; set; }

        /// <summary>CPU identity from the last GetDeviceProperties call.</summary>
        public Device? Device { get; private set; }
        /// <summary>The last browsed tag list.</summary>
        public List<Tag> TagList { get; private set; } = new List<Tag>();

        private readonly Connection _conn;
        private bool _disposed;

        /// <summary>Create an empty PLC; set IPAddress before use.</summary>
        public PLC() { _conn = new Connection(this); }

        /// <summary>Create a PLC for the given IP.</summary>
        public PLC(string ipAddress) : this() { IPAddress = ipAddress; }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed) return;
            Close();
            _disposed = true;
        }

        /// <summary>Open TCP + COTP to the PLC.</summary>
        public Response Connect()
        {
            try { _conn.Open(); return new Response(null, true, 0x00); }
            catch (Exception e) { return new Response(null, false, e.Message); }
        }

        /// <summary>Close the connection and any V3 session.</summary>
        public void Close()
        {
            _conn.Close();
            if (V3Backend != null) { try { V3Backend.Close(); } catch { /* ignore */ } V3Backend = null; }
        }

        // --- V3 session seam ----------------------------------------------
        private IV3Backend? EnsureV3(out string? error)
        {
            if (V3Backend != null && V3Backend.Connected) { error = null; return V3Backend; }
            if (V3BackendFactory == null)
            {
                error = "no V3 backend configured; Explore/Read/Write require the "
                      + "integrity-protected session. Set V3BackendFactory to an "
                      + "adapter over HarpoS7 / S7CommPlusDriver (spec Appendix C).";
                return null;
            }
            try
            {
                V3Backend = V3BackendFactory(this);
                V3Backend.Connect();
                error = null;
                return V3Backend;
            }
            catch (Exception e) { V3Backend = null; error = e.Message; return null; }
        }

        // --- CreateObject session (spec §7, protocol v1, clear text) -------
        private byte[] BuildCreateObject()
        {
            // Minimal well-formed request; the reply is parsed for identity
            // regardless of request detail (the spec documents the fields but
            // not the exact request TLV).
            var body = new byte[10];
            body[4] = (byte)((S7PlusConstants.FuncCreateObject >> 8) & 0xFF);
            body[5] = (byte)(S7PlusConstants.FuncCreateObject & 0xFF);
            return body;
        }

        private ParsedPdu CreateObject()
        {
            int seq = _conn.NextSeq();
            var pdu = _conn.BuildPdu(S7PlusConstants.Version1, S7PlusConstants.OpRequest,
                                     S7PlusConstants.FuncCreateObject, seq, BuildCreateObject());
            _conn.SendPdu(pdu);
            return Connection.ParsePdu(_conn.RecvPdu());
        }

        /// <summary>
        /// Negotiate a session and return the CPU identity (spec §7/§8), using
        /// only the clear-text protocol-version-1 CreateObject exchange.
        /// </summary>
        public Response GetDeviceProperties()
        {
            ParsedPdu resp;
            try { _conn.Open(); resp = CreateObject(); }
            catch (Exception e) { return new Response(null, null, e.Message); }

            var dev = new Device();
            var strings = ExploreParser.ScanStrings(resp.Body);
            dev.RawStrings = strings;
            foreach (var s in strings)
            {
                if (s.Contains("OMSP")) dev.Firmware = s;
                else if (s.Contains("6ES7"))
                {
                    dev.OrderNumber = s;
                    int idx = s.IndexOf(";V", StringComparison.Ordinal);
                    if (idx >= 0) dev.Version = "V" + s.Substring(idx + 2).Trim();
                }
                else if (s.Count(c => c == ':') == 1 && s.All(c => Uri.IsHexDigit(c) || c == ':'))
                    dev.Serial = s;
            }
            Device = dev;
            object status = strings.Count > 0
                ? (object)0x00
                : "session reply received; no clear-text identity in this response";
            return new Response(null, dev, status);
        }

        /// <summary>Connectivity / liveness probe (spec §8): negotiate, then close.</summary>
        public Response ConnectionTest()
        {
            var r = GetDeviceProperties();
            Close();
            return r;
        }

        // --- Explore / tag list (spec §9) ----------------------------------
        /// <summary>Browse the symbol tree (Explore) and return it as Tags.</summary>
        public Response GetTagList()
        {
            var sess = EnsureV3(out var err);
            if (err != null) return new Response(null, new List<Tag>(), err);
            try
            {
                var tags = new List<Tag>();
                foreach (var ti in sess!.Tags())
                {
                    tags.Add(new Tag(ti.Name)
                    {
                        DataType = ti.DataType,
                        RelationId = ti.AccessArea,
                        LID = ti.Lids.Count > 0 ? ti.Lids[ti.Lids.Count - 1] : (int?)null,
                    });
                }
                TagList = tags;
                return new Response(null, tags, 0x00);
            }
            catch (Exception e) { return new Response(null, new List<Tag>(), e.Message); }
        }

        // --- read / write PDU builders (spec §11, §12) ---------------------
        /// <summary>
        /// Build a SetMultiVariables (0x0542) single-item write request body
        /// (spec §12/§12.1): access-base + object relation-id + LID + value block.
        /// </summary>
        public static byte[] BuildWriteRequest(uint relationId, int lid, S7Type type, object value,
            byte[]? accessBase = null)
        {
            accessBase ??= new byte[] { 0x70, 0x40, 0x00, 0x03, 0x34, 0x00, 0x00, 0x00, 0x00 };
            var rid = new byte[] { (byte)(relationId >> 24), (byte)(relationId >> 16),
                                   (byte)(relationId >> 8), (byte)relationId };
            var block = S7PlusTypes.EncodeWriteBlock(type, value);
            var outBytes = new byte[accessBase.Length + rid.Length + 1 + block.Length];
            int o = 0;
            Array.Copy(accessBase, 0, outBytes, o, accessBase.Length); o += accessBase.Length;
            Array.Copy(rid, 0, outBytes, o, rid.Length); o += rid.Length;
            outBytes[o++] = (byte)lid;
            Array.Copy(block, 0, outBytes, o, block.Length);
            return outBytes;
        }

        /// <summary>Build a single-variable read (0x04FC) request body (spec §11.1).</summary>
        public static byte[] BuildReadSingleRequest(byte[] itemAddress)
        {
            var outBytes = new byte[3 + itemAddress.Length];
            outBytes[0] = 0x70; outBytes[1] = 0x40; outBytes[2] = 0x00;
            Array.Copy(itemAddress, 0, outBytes, 3, itemAddress.Length);
            return outBytes;
        }

        /// <summary>Read one symbolic tag by name (optimized or standard DB).</summary>
        public Response Read(string tag)
        {
            var sess = EnsureV3(out var err);
            if (err != null) return new Response(tag, null, err);
            try
            {
                var r = sess!.Read(tag);
                return new Response(tag, r.Value, r.Ok ? (object)0x00 : (r.Error ?? "read failed"));
            }
            catch (Exception e) { return new Response(tag, null, e.Message); }
        }

        /// <summary>Read many symbolic tags in batched requests (default 40 per round-trip).</summary>
        public IList<Response> ReadList(IEnumerable<string> tags, int chunk = 40)
        {
            var list = tags.ToList();
            var sess = EnsureV3(out var err);
            if (err != null) return list.Select(t => new Response(t, null, err)).ToList();
            try
            {
                return sess!.ReadMany(list, chunk)
                    .Select(r => new Response(r.Name, r.Value, r.Ok ? (object)0x00 : (r.Error ?? "read failed")))
                    .ToList();
            }
            catch (Exception e) { return list.Select(t => new Response(t, null, e.Message)).ToList(); }
        }

        /// <summary>Write one symbolic tag by name; datatype override is optional.</summary>
        public Response Write(string tag, object value, string? datatype = null)
        {
            var sess = EnsureV3(out var err);
            if (err != null) return new Response(tag, null, err);
            try
            {
                var r = sess!.Write(tag, value, datatype);
                return new Response(tag, r.Value, r.Ok ? (object)0x00 : (r.Error ?? "write failed"));
            }
            catch (Exception e) { return new Response(tag, null, e.Message); }
        }
    }
}
