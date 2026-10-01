using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using CsS7CommPlus.Constants;

namespace CsS7CommPlus
{
    /// <summary>Raised on a transport/framing error.</summary>
    public class S7PlusCommException : Exception
    {
        /// <summary>Create with a message.</summary>
        public S7PlusCommException(string message) : base(message) { }
    }

    /// <summary>A parsed S7comm-plus PDU (port of the Python parse_pdu dict).</summary>
    public class ParsedPdu
    {
        /// <summary>Protocol version byte.</summary>
        public byte Version { get; set; }
        /// <summary>v3 integrity digest, or null.</summary>
        public byte[]? Digest { get; set; }
        /// <summary>Opcode (0x31/0x32/0x33), or null if the PDU was too short.</summary>
        public byte? Opcode { get; set; }
        /// <summary>Function code, or null.</summary>
        public ushort? Function { get; set; }
        /// <summary>Sequence number, or null.</summary>
        public ushort? Seq { get; set; }
        /// <summary>Operation payload (after the 9-byte opcode header).</summary>
        public byte[] Body { get; set; } = new byte[0];
        /// <summary>The raw PDU bytes.</summary>
        public byte[] Raw { get; set; } = new byte[0];
    }

    /// <summary>
    /// Transport and framing for S7comm-plus: TCP / TPKT / COTP and the
    /// S7comm-plus PDU envelope (spec §4–6).  Direct port of s7p_comm.py.
    /// </summary>
    public class Connection
    {
        private readonly PLC _parent;
        private TcpClient? _sock;
        private NetworkStream? _stream;
        private int _seq;

        /// <summary>True once TCP is established.</summary>
        public bool Connected { get; private set; }
        /// <summary>True once the COTP Connect Confirm has been received.</summary>
        public bool CotpConnected { get; private set; }

        /// <summary>Create a connection bound to its owning PLC.</summary>
        public Connection(PLC parent) { _parent = parent; }

        // --- low-level TPKT I/O --------------------------------------------
        private void Send(byte[] payload)
        {
            int total = payload.Length + 4;
            var frame = new byte[total];
            frame[0] = 0x03; frame[1] = 0x00;
            frame[2] = (byte)((total >> 8) & 0xFF);
            frame[3] = (byte)(total & 0xFF);
            Array.Copy(payload, 0, frame, 4, payload.Length);
            _stream!.Write(frame, 0, frame.Length);
        }

        private byte[] RecvExact(int n)
        {
            var buf = new byte[n];
            int got = 0;
            while (got < n)
            {
                int r = _stream!.Read(buf, got, n - got);
                if (r <= 0) throw new S7PlusCommException("connection closed by peer");
                got += r;
            }
            return buf;
        }

        private byte[] RecvTpkt()
        {
            var hdr = RecvExact(4);
            if (hdr[0] != S7PlusConstants.TpktVersion)
                throw new S7PlusCommException(string.Format("bad TPKT version 0x{0:x2}", hdr[0]));
            int total = (hdr[2] << 8) | hdr[3];
            return RecvExact(total - 4);
        }

        // --- TCP + COTP ----------------------------------------------------
        /// <summary>Open TCP and perform the COTP connect handshake.</summary>
        public void Open()
        {
            if (Connected) return;
            _sock = new TcpClient();
            if (!_sock.ConnectAsync(_parent.IPAddress, _parent.Port)
                     .Wait((int)(_parent.SocketTimeout * 1000)))
                throw new S7PlusCommException("TCP connect timed out");
            _stream = _sock.GetStream();
            _stream.ReadTimeout = (int)(_parent.SocketTimeout * 1000);
            _stream.WriteTimeout = (int)(_parent.SocketTimeout * 1000);
            Connected = true;
            CotpConnect();
        }

        private void CotpConnect()
        {
            var src = Encoding.ASCII.GetBytes(_parent.SourceTsap);
            var dst = Encoding.ASCII.GetBytes(_parent.DestTsap);
            using var ms = new MemoryStream();
            // fixed CR header: PDU=E0, dst-ref 0000, src-ref 0023, class 0
            ms.Write(new byte[] { S7PlusConstants.CotpCr, 0x00, 0x00, 0x00, 0x23, 0x00 }, 0, 6);
            ms.WriteByte(S7PlusConstants.CotpParamSrcTsap); ms.WriteByte((byte)src.Length); ms.Write(src, 0, src.Length);
            ms.WriteByte(S7PlusConstants.CotpParamDstTsap); ms.WriteByte((byte)dst.Length); ms.Write(dst, 0, dst.Length);
            ms.Write(new byte[] { S7PlusConstants.CotpParamTpduSize, 0x01, S7PlusConstants.TpduSize1024 }, 0, 3);
            var body = ms.ToArray();
            var cotp = new byte[body.Length + 1];
            cotp[0] = (byte)body.Length;             // LI
            Array.Copy(body, 0, cotp, 1, body.Length);
            Send(cotp);
            var cc = RecvTpkt();
            if (cc.Length < 2 || cc[1] != S7PlusConstants.CotpCc)
                throw new S7PlusCommException("COTP Connect Confirm not received");
            CotpConnected = true;
        }

        // --- S7comm-plus PDU envelope --------------------------------------
        /// <summary>Increment and return the request/response sequence counter.</summary>
        public int NextSeq() { _seq = (_seq + 1) & 0xFFFF; return _seq; }

        /// <summary>
        /// Build a complete S7comm-plus PDU (header + data part + trailer).
        /// For version 3 the integrity part is prepended to the data part.
        /// </summary>
        public byte[] BuildPdu(byte version, byte opcode, ushort function, int seq, byte[] payload)
        {
            var header = new byte[9];
            header[0] = opcode;
            header[3] = (byte)((function >> 8) & 0xFF);
            header[4] = (byte)(function & 0xFF);
            header[7] = (byte)((seq >> 8) & 0xFF);
            header[8] = (byte)(seq & 0xFF);

            byte[] data = Concat(header, payload);
            if (version == S7PlusConstants.Version3)
            {
                var digest = _parent.Integrity.Digest(data, seq);
                var dpart = new byte[1 + digest.Length + data.Length];
                dpart[0] = S7PlusConstants.IntegrityDigestLen;
                Array.Copy(digest, 0, dpart, 1, digest.Length);
                Array.Copy(data, 0, dpart, 1 + digest.Length, data.Length);
                data = dpart;
            }
            using var ms = new MemoryStream();
            ms.WriteByte(S7PlusConstants.S7pProtocolId);
            ms.WriteByte(version);
            ms.WriteByte((byte)((data.Length >> 8) & 0xFF));
            ms.WriteByte((byte)(data.Length & 0xFF));
            ms.Write(data, 0, data.Length);
            ms.Write(new byte[] { S7PlusConstants.S7pProtocolId, version, 0x00, 0x00 }, 0, 4);
            return ms.ToArray();
        }

        /// <summary>Send a PDU inside a COTP DT (Data) unit with the EOT bit set.</summary>
        public void SendPdu(byte[] pdu) => Send(Concat(new byte[] { 0x02, 0xF0, 0x80 }, pdu));

        /// <summary>Receive one application PDU, stripping the COTP DT header.</summary>
        public byte[] RecvPdu()
        {
            var body = RecvTpkt();
            if (body.Length >= 3 && body[1] == S7PlusConstants.CotpDt)
            {
                var inner = new byte[body.Length - 3];
                Array.Copy(body, 3, inner, 0, inner.Length);
                return inner;
            }
            return body;
        }

        /// <summary>Send a request and return (seq, parsed response).</summary>
        public ParsedPdu Transaction(byte version, byte opcode, ushort function, byte[] payload, out int seq)
        {
            seq = NextSeq();
            SendPdu(BuildPdu(version, opcode, function, seq, payload));
            return ParsePdu(RecvPdu());
        }

        /// <summary>Close the socket.</summary>
        public void Close()
        {
            try { _stream?.Dispose(); } catch { /* ignore */ }
            try { _sock?.Close(); } catch { /* ignore */ }
            _stream = null; _sock = null;
            Connected = false; CotpConnected = false;
        }

        /// <summary>
        /// Parse a received S7comm-plus PDU.  Handles v1/v2 (no integrity) and
        /// v3 (33-byte integrity part before the opcode header).
        /// </summary>
        public static ParsedPdu ParsePdu(byte[] raw)
        {
            if (raw.Length < 4 || raw[0] != S7PlusConstants.S7pProtocolId)
                throw new S7PlusCommException("not an S7comm-plus PDU");
            var pdu = new ParsedPdu { Version = raw[1], Raw = raw };
            int dataLen = (raw[2] << 8) | raw[3];
            int dataStart = 4;
            int dataEnd = System.Math.Min(4 + dataLen, raw.Length);
            int off = dataStart;
            if (pdu.Version == S7PlusConstants.Version3 && dataEnd - off >= 1
                && raw[off] == S7PlusConstants.IntegrityDigestLen)
            {
                pdu.Digest = Slice(raw, off + 1, S7PlusConstants.IntegrityDigestLen);
                off += 1 + S7PlusConstants.IntegrityDigestLen;
            }
            int avail = dataEnd - off;
            if (avail >= 9)
            {
                pdu.Opcode = raw[off];
                pdu.Function = (ushort)((raw[off + 3] << 8) | raw[off + 4]);
                pdu.Seq = (ushort)((raw[off + 7] << 8) | raw[off + 8]);
                pdu.Body = Slice(raw, off + 9, dataEnd - (off + 9));
            }
            else
            {
                pdu.Body = Slice(raw, off, System.Math.Max(0, avail));
            }
            return pdu;
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Array.Copy(a, 0, r, 0, a.Length);
            Array.Copy(b, 0, r, a.Length, b.Length);
            return r;
        }

        private static byte[] Slice(byte[] a, int start, int len)
        {
            if (len <= 0) return new byte[0];
            var r = new byte[len];
            Array.Copy(a, start, r, 0, len);
            return r;
        }
    }
}
