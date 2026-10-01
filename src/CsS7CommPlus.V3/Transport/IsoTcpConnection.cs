using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using CsS7CommPlus.V3.Protocol;

namespace CsS7CommPlus.V3.Transport
{
    /// <summary>
    /// A byte source and sink for S7comm-plus PDUs.  The two session variants
    /// carry their PDUs differently — one inside COTP data frames, one inside TLS
    /// records that are themselves inside COTP data frames — so the framing code
    /// above reads and writes through this.
    /// </summary>
    public interface IPduTransport
    {
        /// <summary>Send one complete S7comm-plus frame.</summary>
        void Send(byte[] frame);

        /// <summary>
        /// Read up to <paramref name="count"/> bytes of the PDU stream.  Returns 0
        /// only when the peer has closed.
        /// </summary>
        int Read(byte[] buffer, int offset, int count);

        /// <summary>Set how long a read may block, in milliseconds.</summary>
        void SetReadTimeout(int milliseconds);
    }

    /// <summary>
    /// ISO-on-TCP (RFC 1006): a TCP connection to port 102 carrying TPKT frames,
    /// each holding a COTP class-0 TPDU.
    ///
    /// The S7comm-plus session opens with a COTP connection request naming the
    /// client's access point and the PLC's "SIMATIC-ROOT-HMI" TSAP, and every PDU
    /// after it travels as the payload of a COTP data frame.
    ///
    /// Ported from the MIT-licensed s7commplus Python backend (transport.py).
    /// </summary>
    public sealed class IsoTcpConnection : IPduTransport, IDisposable
    {
        private const byte CotpConnectionRequest = 0xE0;
        private const byte CotpConnectionConfirm = 0xD0;
        private const byte CotpDisconnectRequest = 0x80;
        private const byte CotpDataTransfer = 0xF0;

        private const byte ParamTpduSize = 0xC0;
        private const byte ParamCallingTsap = 0xC1;
        private const byte ParamCalledTsap = 0xC2;

        private readonly string _host;
        private readonly int _port;

        private TcpClient? _tcp;
        private NetworkStream? _stream;

        // The current COTP payload, served out by Read until it is exhausted.
        private byte[] _buffer = new byte[0];
        private int _offset;

        private ushort _srcRef = 0x0001;
        private ushort _dstRef;

        /// <summary>Negotiated TPDU size; the default until the confirm says otherwise.</summary>
        public int TpduSize { get; private set; } = 1024;

        /// <summary>Whether the socket and COTP connection are open.</summary>
        public bool Connected { get; private set; }

        /// <summary>Create a connection for the given PLC.</summary>
        public IsoTcpConnection(string host, int port = 102)
        {
            _host = host;
            _port = port;
        }

        /// <summary>The underlying network stream, for a TLS handshake that needs it.</summary>
        public Stream NetworkStream =>
            _stream ?? throw new S7ConnectionException("Not connected");

        /// <summary>Open the socket and complete the COTP handshake.</summary>
        public void Open(int timeoutMs)
        {
            _tcp = new TcpClient
            {
                // Request/response traffic in complete PDUs, so Nagle only adds latency.
                NoDelay = true,
            };

            if (!_tcp.ConnectAsync(_host, _port).Wait(timeoutMs))
            {
                Abort();
                throw new S7TimeoutException($"TCP connect to {_host}:{_port} timed out after {timeoutMs} ms");
            }

            _tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            _tcp.ReceiveTimeout = timeoutMs;
            _tcp.SendTimeout = timeoutMs;
            _stream = _tcp.GetStream();
            _stream.ReadTimeout = timeoutMs;
            _stream.WriteTimeout = timeoutMs;

            Connected = true;

            try
            {
                CotpConnect();
            }
            catch
            {
                Abort();
                throw;
            }
        }

        /// <summary>Open only the socket, leaving the COTP handshake to the caller.</summary>
        public void OpenSocketOnly(int timeoutMs)
        {
            _tcp = new TcpClient { NoDelay = true };
            if (!_tcp.ConnectAsync(_host, _port).Wait(timeoutMs))
            {
                Abort();
                throw new S7TimeoutException($"TCP connect to {_host}:{_port} timed out after {timeoutMs} ms");
            }
            _tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            _tcp.ReceiveTimeout = timeoutMs;
            _tcp.SendTimeout = timeoutMs;
            _stream = _tcp.GetStream();
            _stream.ReadTimeout = timeoutMs;
            _stream.WriteTimeout = timeoutMs;
            Connected = true;
        }

        private void CotpConnect()
        {
            WriteTpkt(BuildConnectionRequest());

            var confirm = ReadTpkt();
            if (confirm.Length < 7)
                throw new S7ConnectionException("COTP connection confirm is too short");
            if (confirm[1] != CotpConnectionConfirm)
                throw new S7ConnectionException($"Expected a COTP connection confirm, got 0x{confirm[1]:X2}");

            _dstRef = (ushort)((confirm[2] << 8) | confirm[3]);
            if (confirm.Length > 7) ParseConnectionParameters(confirm, 7);
        }

        private byte[] BuildConnectionRequest()
        {
            var tsap = S7Protocol.RemoteTsap;
            var cr = new List<byte>
            {
                0x00,                                   // header length, filled in below
                CotpConnectionRequest,
                0x00, 0x00,                             // destination reference
                (byte)(_srcRef >> 8), (byte)_srcRef,
                0x00,                                   // class 0, no extended formats
                ParamCallingTsap, 0x02,
                (byte)(S7Protocol.LocalTsap >> 8), unchecked((byte)S7Protocol.LocalTsap),
                ParamCalledTsap, (byte)tsap.Length,
            };
            cr.AddRange(tsap);
            cr.AddRange(new byte[] { ParamTpduSize, 0x01, 0x0A });   // 2^10 = 1024 bytes

            cr[0] = (byte)(cr.Count - 1);
            return cr.ToArray();
        }

        private void ParseConnectionParameters(byte[] data, int offset)
        {
            while (offset + 2 <= data.Length)
            {
                byte code = data[offset];
                int length = data[offset + 1];
                if (offset + 2 + length > data.Length) break;

                if (code == ParamTpduSize && length == 1)
                {
                    int exponent = data[offset + 2];
                    if (exponent >= 7 && exponent <= 13) TpduSize = 1 << exponent;
                }
                offset += 2 + length;
            }
        }

        /// <inheritdoc/>
        public void Send(byte[] frame)
        {
            // A frame longer than the negotiated TPDU still goes out in one data
            // frame: the PLC's limit is on its own reassembly, and every request
            // this client builds stays well inside it.
            var payload = new byte[3 + frame.Length];
            payload[0] = 0x02;
            payload[1] = CotpDataTransfer;
            payload[2] = 0x80;                          // end of TSDU, sequence 0
            Array.Copy(frame, 0, payload, 3, frame.Length);
            WriteTpkt(payload);
        }

        /// <inheritdoc/>
        public int Read(byte[] buffer, int offset, int count)
        {
            while (_offset >= _buffer.Length)
            {
                var payload = ReadTpkt();
                if (payload.Length < 3)
                    throw new S7ConnectionException("COTP data frame is too short");
                if (payload[1] != CotpDataTransfer)
                    throw new S7ConnectionException($"Expected a COTP data frame, got 0x{payload[1]:X2}");

                _buffer = Slice(payload, 3, payload.Length - 3);
                _offset = 0;
                if (_buffer.Length == 0) continue;       // an empty data frame carries nothing
            }

            int n = Math.Min(count, _buffer.Length - _offset);
            Array.Copy(_buffer, _offset, buffer, offset, n);
            _offset += n;
            return n;
        }

        /// <inheritdoc/>
        public void SetReadTimeout(int milliseconds)
        {
            if (_stream != null) _stream.ReadTimeout = milliseconds;
            if (_tcp != null) _tcp.ReceiveTimeout = milliseconds;
        }

        /// <summary>Whether a byte is already buffered or waiting on the socket.</summary>
        public bool DataAvailable =>
            _offset < _buffer.Length || (_stream != null && _stream.DataAvailable);

        private void WriteTpkt(byte[] payload)
        {
            if (_stream == null) throw new S7ConnectionException("Not connected");

            int length = payload.Length + 4;
            if (length > 65535) throw new S7ProtocolException($"TPKT frame of {length} bytes is too long");

            var frame = new byte[length];
            frame[0] = 0x03;
            frame[1] = 0x00;
            frame[2] = (byte)(length >> 8);
            frame[3] = (byte)length;
            Array.Copy(payload, 0, frame, 4, payload.Length);

            try
            {
                _stream.Write(frame, 0, frame.Length);
                _stream.Flush();
            }
            catch (IOException e)
            {
                Connected = false;
                throw Translate(e, "Send failed");
            }
        }

        private byte[] ReadTpkt()
        {
            var header = ReadExactFromSocket(4);
            if (header[0] != 0x03)
                throw new S7ProtocolException($"Invalid TPKT version {header[0]}");

            int length = (header[2] << 8) | header[3];
            if (length < 7) throw new S7ProtocolException($"Invalid TPKT length {length}");

            return ReadExactFromSocket(length - 4);
        }

        private byte[] ReadExactFromSocket(int count)
        {
            if (_stream == null) throw new S7ConnectionException("Not connected");

            var buffer = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n;
                try
                {
                    n = _stream.Read(buffer, read, count - read);
                }
                catch (IOException e)
                {
                    Connected = false;
                    throw Translate(e, "Receive failed");
                }

                if (n <= 0)
                {
                    Connected = false;
                    throw new S7ConnectionException("Connection closed by the PLC");
                }
                read += n;
            }
            return buffer;
        }

        private static Exception Translate(IOException e, string what)
        {
            if (e.InnerException is SocketException se &&
                (se.SocketErrorCode == SocketError.TimedOut || se.SocketErrorCode == SocketError.WouldBlock))
                return new S7TimeoutException($"{what}: the PLC did not answer in time");
            return new S7ConnectionException($"{what}: {e.Message}", e);
        }

        private static byte[] Slice(byte[] data, int offset, int length)
        {
            if (length <= 0) return new byte[0];
            var outBytes = new byte[length];
            Array.Copy(data, offset, outBytes, 0, length);
            return outBytes;
        }

        /// <summary>Send a COTP disconnect request and close the socket.</summary>
        public void Close()
        {
            if (Connected && _stream != null)
            {
                try
                {
                    WriteTpkt(new byte[]
                    {
                        0x06, CotpDisconnectRequest,
                        (byte)(_dstRef >> 8), (byte)_dstRef,
                        (byte)(_srcRef >> 8), (byte)_srcRef,
                        0x00, 0x00,
                    });
                }
                catch { /* best effort */ }
            }
            Abort();
        }

        /// <summary>Drop the socket without the disconnect request.</summary>
        public void Abort()
        {
            Connected = false;
            _buffer = new byte[0];
            _offset = 0;
            try { _stream?.Dispose(); } catch { /* ignore */ }
            try { _tcp?.Close(); } catch { /* ignore */ }
            _stream = null;
            _tcp = null;
        }

        /// <inheritdoc/>
        public void Dispose() => Abort();
    }

    /// <summary>A transport that reads and writes PDUs as plain bytes on a stream, for a TLS session.</summary>
    public sealed class StreamPduTransport : IPduTransport
    {
        private readonly Stream _stream;
        private readonly IsoTcpConnection? _underlying;

        /// <summary>
        /// Wrap an authenticated stream.  A managed TLS stream cannot carry a read
        /// timeout itself, so <paramref name="underlying"/> is where one is set.
        /// </summary>
        public StreamPduTransport(Stream stream, IsoTcpConnection? underlying = null)
        {
            _stream = stream;
            _underlying = underlying;
        }

        /// <inheritdoc/>
        public void Send(byte[] frame)
        {
            _stream.Write(frame, 0, frame.Length);
            _stream.Flush();
        }

        /// <inheritdoc/>
        public int Read(byte[] buffer, int offset, int count) => _stream.Read(buffer, offset, count);

        /// <inheritdoc/>
        public void SetReadTimeout(int milliseconds)
        {
            if (_underlying != null) { _underlying.SetReadTimeout(milliseconds); return; }
            try { _stream.ReadTimeout = milliseconds; } catch (InvalidOperationException) { /* not timeoutable */ }
        }
    }
}
