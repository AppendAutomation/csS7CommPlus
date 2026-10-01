using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using CsS7CommPlus.V3.Protocol;
using HarpoS7.Tls;

namespace CsS7CommPlus.V3.Session
{
    /// <summary>
    /// An S7comm-plus session to one S7-1200/1500 CPU, carried inside TLS.
    ///
    /// The connect sequence is COTP connection request/confirm, the InitSSL
    /// exchange, the TLS 1.2/1.3 handshake, a CreateObject that opens the
    /// NullServerSession, and a V2 SetMultiVariables that echoes
    /// ServerSessionVersion back.  From then on every request carries the V2
    /// IntegrityId counters.
    ///
    /// TLS records travel as the payload of COTP data frames — the TPKT and COTP
    /// headers stay in clear text, which is why the socket cannot simply be
    /// wrapped in TLS.  HarpoS7's CotpStream provides that framing and its
    /// <see cref="HarpoTlsAuth"/> drives the COTP and InitSSL handshake, so this
    /// class starts from the authenticated <see cref="SslStream"/> it returns.
    ///
    /// This covers PLCs configured with TIA Portal V17 or later (S7-1200 FW V4.3+,
    /// S7-1500 FW V2.9+), which is the band that supports secure communication.
    /// The pre-V17 challenge scheme — where frames carry a keyed digest instead of
    /// travelling inside TLS — is not implemented here.
    ///
    /// Ported from the MIT-licensed s7commplus Python backend (connection.py).
    /// A connection is driven by one caller at a time; requests are serialized
    /// internally but notifications must not be awaited concurrently with a
    /// request.
    /// </summary>
    public class S7CommPlusConnection : IDisposable
    {
        private const int MaxSystemEventsPerResponse = 16;
        private const int MaxStaleResponsesPerRequest = 16;
        private const int MaxReassembledBytes = 16 * 1024 * 1024;
        private const int MaxReassembledFragments = 4096;
        private const uint SystemEventReturnValueId = 40305;

        private readonly object _requestLock = new object();
        private readonly Queue<byte[]> _notificationFrames = new Queue<byte[]>();

        private TcpClient? _tcp;
        private SslStream? _ssl;
        private ushort _sequenceNumber;
        private bool _connected;
        private bool _sessionReady;

        /// <summary>PLC IP address or host name.</summary>
        public string Host { get; }

        /// <summary>ISO-on-TCP port, 102 unless overridden.</summary>
        public int Port { get; }

        /// <summary>Socket and request timeout in milliseconds.</summary>
        public int TimeoutMs { get; set; } = 5000;

        /// <summary>The protocol version the session settled on (V2 inside TLS).</summary>
        public ProtocolVersion ProtocolVersion { get; private set; }

        /// <summary>Session id allocated by the PLC; the first CreateObject object id.</summary>
        public uint SessionId { get; private set; }

        /// <summary>Object id of this session's subscription container.</summary>
        public uint SubscriptionContainerId { get; private set; }

        /// <summary>Whether the session is open and set up.</summary>
        public bool Connected => _connected;

        /// <summary>The PLC's effective protection level, when it reported one.</summary>
        public int? ProtectionLevel { get; private set; }

        /// <summary>Raised for each protocol-level diagnostic; wire to the host's logger.</summary>
        public event Action<string>? OnDiagnostic;

        /// <summary>Create a connection for the given PLC.</summary>
        public S7CommPlusConnection(string host, int port = 102)
        {
            Host = host;
            Port = port;
        }

        private void Log(string message) => OnDiagnostic?.Invoke(message);

        // --- connect / disconnect ------------------------------------------

        /// <summary>
        /// Open the socket, run the COTP, InitSSL and TLS handshakes, create the
        /// session and complete session setup.
        /// </summary>
        public void Connect()
        {
            try
            {
                _tcp = new TcpClient();
                _tcp.NoDelay = true;                    // request/response traffic; Nagle only adds latency
                if (!_tcp.ConnectAsync(Host, Port).Wait(TimeoutMs))
                    throw new S7TimeoutException($"TCP connect to {Host}:{Port} timed out after {TimeoutMs} ms");

                _tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                _tcp.ReceiveTimeout = TimeoutMs;
                _tcp.SendTimeout = TimeoutMs;

                var network = _tcp.GetStream();

                // COTP connection request/confirm, InitSSL, then the TLS handshake.
                // The PLC presents a self-signed per-device certificate, so the
                // chain cannot be validated against a public root.
                var authOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = Host,
                    RemoteCertificateValidationCallback = (_, _, _, _) => true,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                };

                var authTask = HarpoTlsAuth.AuthenticateUsingTlsAsync(network, authOptions, "SIMATIC-ROOT-HMI");
                if (!authTask.Wait(TimeoutMs))
                    throw new S7TimeoutException($"TLS handshake with {Host} timed out after {TimeoutMs} ms");
                _ssl = authTask.Result;
                _ssl.ReadTimeout = TimeoutMs;
                _ssl.WriteTimeout = TimeoutMs;
                Log($"TLS activated ({_ssl.SslProtocol}, {_ssl.NegotiatedCipherSuite})");

                CreateSession();

                // Inside TLS the data PDUs are V2, whatever version CreateObject used.
                ProtocolVersion = ProtocolVersion.V2;

                if (_serverSessionVersion == null)
                    throw new S7ConnectionException(
                        "PLC did not return a ServerSessionVersion attribute; session setup cannot continue");

                if (!SetupSession())
                    throw new S7ConnectionException("The PLC rejected S7comm-plus session setup");

                _sessionReady = true;

                // V2 tracks a read and a write IntegrityId counter per session.
                _withIntegrityId = true;
                _integrityIdRead = 0;
                _integrityIdWrite = 0;

                ProtectionLevel = ReadEffectiveProtectionLevel();
                if (ProtectionLevel != null) Log($"PLC reports protection level {ProtectionLevel}");

                _connected = true;
                Log($"Connected to {Host}:{Port}, version=V{(int)ProtocolVersion}, session=0x{SessionId:X8}");
            }
            catch
            {
                Disconnect();
                throw;
            }
        }

        /// <summary>Delete the session on the PLC and close the socket.</summary>
        public void Disconnect()
        {
            if (_sessionReady && SessionId != 0)
            {
                try { DeleteSession(); } catch { /* best effort */ }
            }

            _connected = false;
            _sessionReady = false;
            SessionId = 0;
            SubscriptionContainerId = 0;
            _sequenceNumber = 0;
            ProtocolVersion = 0;
            _serverSessionVersion = null;
            _withIntegrityId = false;
            _integrityIdRead = 0;
            _integrityIdWrite = 0;
            ProtectionLevel = null;
            _notificationFrames.Clear();

            try { _ssl?.Dispose(); } catch { /* ignore */ }
            try { _tcp?.Close(); } catch { /* ignore */ }
            _ssl = null;
            _tcp = null;
        }

        /// <summary>Close the socket immediately, without the clean-up requests.</summary>
        public void Abort()
        {
            _connected = false;
            _sessionReady = false;
            try { _tcp?.Client?.Close(0); } catch { /* ignore */ }
            try { _ssl?.Dispose(); } catch { /* ignore */ }
            try { _tcp?.Close(); } catch { /* ignore */ }
            _ssl = null;
            _tcp = null;
            _notificationFrames.Clear();
        }

        /// <inheritdoc/>
        public void Dispose() => Disconnect();

        // --- request / response --------------------------------------------

        private bool _withIntegrityId;
        private uint _integrityIdRead;
        private uint _integrityIdWrite;
        private byte[]? _serverSessionVersion;

        private ushort NextSequenceNumber()
        {
            ushort seq = _sequenceNumber;
            _sequenceNumber = (ushort)((_sequenceNumber + 1) & 0xFFFF);
            return seq;
        }

        /// <summary>
        /// Send one request and return its response payload, the part after the
        /// 10-byte response header.
        /// </summary>
        /// <param name="functionCode">The function to invoke.</param>
        /// <param name="payload">Request payload, after the 14-byte request header.</param>
        /// <param name="integrityTail">
        /// How many trailing payload bytes the V2 IntegrityId is spliced in *before*:
        /// 4 for GetMultiVariables and SetMultiVariables (a trailing UInt32), 5 for
        /// Explore (a trailing UInt32 plus a filler byte), 3 for SetVariable.
        /// </param>
        public byte[] SendRequest(FunctionCode functionCode, byte[]? payload = null, int integrityTail = 4)
        {
            lock (_requestLock)
            {
                return SendRequestLocked(functionCode, payload ?? new byte[0], integrityTail);
            }
        }

        private byte[] SendRequestLocked(FunctionCode functionCode, byte[] payload, int integrityTail)
        {
            if (!_connected && !_sessionReady) throw new S7ConnectionException("Not connected");

            ushort seq = NextSequenceNumber();
            ushort fc = (ushort)functionCode;

            byte transportFlags = S7Protocol.Flags34FunctionCodes.Contains(fc) ? (byte)0x34 : (byte)0x36;
            var requestHeader = S7Codec.EncodeRequestHeader(fc, seq, SessionId, transportFlags);

            byte[] integrityIdBytes = new byte[0];
            if (_withIntegrityId)
            {
                bool isRead = S7Protocol.ReadFunctionCodes.Contains(fc);
                uint integrityId = isRead ? _integrityIdRead : _integrityIdWrite;
                integrityIdBytes = Vlq.EncodeUInt32(integrityId);
            }

            // The IntegrityId sits just before the payload's trailing fill bytes,
            // not immediately after the header.
            var request = new List<byte>(requestHeader.Length + payload.Length + integrityIdBytes.Length);
            request.AddRange(requestHeader);
            if (integrityIdBytes.Length > 0 && payload.Length >= integrityTail)
            {
                request.AddRange(S7Codec.Slice(payload, 0, payload.Length - integrityTail));
                request.AddRange(integrityIdBytes);
                request.AddRange(S7Codec.Slice(payload, payload.Length - integrityTail, integrityTail));
            }
            else
            {
                request.AddRange(integrityIdBytes);
                request.AddRange(payload);
            }

            var requestBytes = request.ToArray();
            SendFrame(ProtocolVersion, requestBytes);

            if (_withIntegrityId)
            {
                if (S7Protocol.ReadFunctionCodes.Contains(fc))
                    _integrityIdRead = unchecked(_integrityIdRead + 1);
                else
                    _integrityIdWrite = unchecked(_integrityIdWrite + 1);
            }

            var response = ReceiveResponse(seq);
            ValidateResponseHeader(response, fc, seq);
            return S7Codec.Slice(response, S7Codec.ResponseHeaderLength,
                                 response.Length - S7Codec.ResponseHeaderLength);
        }

        /// <summary>
        /// Wrap a request in the frame header and trailer and write it to the
        /// TLS stream.  A frame is 0x72, version, length, data, then the
        /// 0x72 version 0x0000 end-of-frame trailer.
        /// </summary>
        private void SendFrame(ProtocolVersion version, byte[] data)
        {
            if (_ssl == null) throw new S7ConnectionException("Not connected");

            var frame = new List<byte>(data.Length + 8);
            frame.AddRange(S7Codec.EncodeHeader(version, data.Length));
            frame.AddRange(data);
            frame.AddRange(new byte[] { S7Protocol.ProtocolId, (byte)version, 0x00, 0x00 });

            var bytes = frame.ToArray();
            try
            {
                _ssl.Write(bytes, 0, bytes.Length);
                _ssl.Flush();
            }
            catch (IOException e)
            {
                _connected = false;
                throw new S7ConnectionException($"Send failed: {e.Message}", e);
            }
        }

        /// <summary>
        /// Receive the next response, consuming non-fatal system events and
        /// queueing notifications that arrive while a response is outstanding.
        /// </summary>
        private byte[] ReceiveResponse(ushort expectedSequence)
        {
            int systemEvents = 0;
            int staleResponses = 0;

            while (true)
            {
                var data = ReceiveFrameData(out var version);

                if (version == ProtocolVersion.SystemEvent)
                {
                    CheckSystemEvent(data);
                    if (++systemEvents > MaxSystemEventsPerResponse)
                        throw new S7ProtocolException("Too many system events while waiting for a response");
                    continue;
                }

                if (data.Length < S7Codec.ResponseHeaderLength)
                    throw new S7ProtocolException("S7comm-plus response is shorter than its header");

                byte opcode = data[0];
                if (opcode == (byte)Opcode.Notification)
                {
                    _notificationFrames.Enqueue(data);
                    continue;
                }
                if (opcode != (byte)Opcode.Response && opcode != (byte)Opcode.Response2)
                    throw new S7ProtocolException($"Unexpected S7comm-plus opcode 0x{opcode:X2} while waiting for a response");

                ushort sequence = S7Codec.ReadUInt16(data, 7);
                if (IsStaleResponseSequence(sequence, expectedSequence))
                {
                    Log($"Ignoring stale response sequence {sequence} while waiting for {expectedSequence}");
                    if (++staleResponses > MaxStaleResponsesPerRequest)
                        throw new S7ProtocolException(
                            $"Too many stale responses while waiting for sequence {expectedSequence}");
                    continue;
                }

                return data;
            }
        }

        /// <summary>
        /// Read one complete PDU and return its data section.  A large response —
        /// an Explore of a big program, typically — arrives as several fragments,
        /// each 0x72 version length data, and only the last is followed by the
        /// zero-length trailer; the fragments' data sections are concatenated.
        /// </summary>
        private byte[] ReceiveFrameData(out ProtocolVersion version)
        {
            var header = ReadExact(4);
            if (header[0] != S7Protocol.ProtocolId)
                throw new S7ProtocolException($"Expected an S7comm-plus fragment header, got 0x{header[0]:X2}");

            version = (ProtocolVersion)header[1];
            int fragmentLength = (header[2] << 8) | header[3];
            if (fragmentLength == 0) return new byte[0];        // standalone trailer

            var data = new List<byte>(fragmentLength);
            data.AddRange(ReadExact(fragmentLength));
            int fragments = 1;

            while (true)
            {
                var next = ReadExact(4);
                if (next[0] != S7Protocol.ProtocolId)
                    throw new S7ProtocolException($"Expected an S7comm-plus fragment header, got 0x{next[0]:X2}");

                var nextVersion = (ProtocolVersion)next[1];
                int nextLength = (next[2] << 8) | next[3];

                if (nextLength == 0) break;                     // trailer: that was the last fragment

                if (nextVersion != version)
                    throw new S7ProtocolException(
                        $"Response changed fragment version from V{(int)version} to V{(int)nextVersion}");

                data.AddRange(ReadExact(nextLength));

                if (++fragments > MaxReassembledFragments || data.Count > MaxReassembledBytes)
                    throw new S7ConnectionException(
                        $"Reassembled response exceeds its limits ({data.Count} bytes, {fragments} fragments)");
            }

            return data.ToArray();
        }

        private byte[] ReadExact(int count)
        {
            if (_ssl == null) throw new S7ConnectionException("Not connected");

            var buffer = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n;
                try
                {
                    n = _ssl.Read(buffer, read, count - read);
                }
                catch (IOException e)
                {
                    _connected = false;
                    if (e.InnerException is SocketException se &&
                        (se.SocketErrorCode == SocketError.TimedOut || se.SocketErrorCode == SocketError.WouldBlock))
                        throw new S7TimeoutException($"Receive timed out after {TimeoutMs} ms");
                    throw new S7ConnectionException($"Receive failed: {e.Message}", e);
                }

                if (n <= 0)
                {
                    _connected = false;
                    throw new S7ConnectionException("Connection closed by the PLC");
                }
                read += n;
            }
            return buffer;
        }

        /// <summary>Whether a 16-bit response sequence precedes the one being waited for.</summary>
        private static bool IsStaleResponseSequence(ushort sequence, ushort expected)
        {
            int distance = (expected - sequence) & 0xFFFF;
            return distance > 0 && distance < 0x8000;
        }

        private static void ValidateResponseHeader(byte[] response, ushort expectedFunction, ushort expectedSequence)
        {
            if (response.Length < S7Codec.ResponseHeaderLength)
                throw new S7ConnectionException("S7comm-plus response is shorter than its header");

            byte opcode = response[0];
            ushort function = S7Codec.ReadUInt16(response, 3);
            ushort sequence = S7Codec.ReadUInt16(response, 7);

            if (opcode != (byte)Opcode.Response && opcode != (byte)Opcode.Response2)
                throw new S7ProtocolException($"Unexpected response opcode 0x{opcode:X2}");

            // A failed request may be answered with the generic ERROR function while
            // keeping the request's sequence number.
            if (function != expectedFunction && function != (ushort)FunctionCode.Error)
                throw new S7ProtocolException(
                    $"Response function mismatch: expected 0x{expectedFunction:X4}, got 0x{function:X4}");

            if (sequence != expectedSequence)
                throw new S7ProtocolException(
                    $"Response sequence mismatch: expected {expectedSequence}, got {sequence} for function 0x{function:X4}");
        }

        // --- notifications --------------------------------------------------

        /// <summary>Whether a notification is already queued from earlier traffic.</summary>
        public bool HasQueuedNotification => _notificationFrames.Count > 0;

        /// <summary>
        /// Return the next subscription notification's data section, waiting for one
        /// if none is queued.  Must not run concurrently with
        /// <see cref="SendRequest"/>; both consume the same stream.
        /// </summary>
        public byte[] ReceiveNotification()
        {
            if (!_connected) throw new S7ConnectionException("Not connected");

            lock (_requestLock)
            {
                if (_notificationFrames.Count > 0) return _notificationFrames.Dequeue();

                while (true)
                {
                    var data = ReceiveFrameData(out var version);
                    if (version == ProtocolVersion.SystemEvent) { CheckSystemEvent(data); continue; }
                    if (data.Length > 0 && data[0] == (byte)Opcode.Notification) return data;
                    if (data.Length == 0) continue;
                    throw new S7ConnectionException(
                        $"Expected a notification, got opcode 0x{data[0]:X2}");
                }
            }
        }

        /// <summary>Set the receive timeout used while waiting for notifications.</summary>
        public void SetReceiveTimeout(int milliseconds)
        {
            if (_ssl != null) _ssl.ReadTimeout = milliseconds;
            if (_tcp != null) _tcp.ReceiveTimeout = milliseconds;
        }

        // --- system events ---------------------------------------------------

        /// <summary>
        /// Raise for a fatal or malformed system event and ignore the informational
        /// ones.  A system event carries a struct with a ReturnValue member when it
        /// reports a failure; a negative value is fatal.
        /// </summary>
        private void CheckSystemEvent(byte[] payload)
        {
            long? returnValue = SystemEventReturnValue(payload);
            if (returnValue != null && returnValue < 0)
                throw new S7ProtocolException(
                    $"Fatal S7comm-plus system event, return_value={returnValue}: {ToHex(payload)}");
            Log($"Ignoring a non-fatal S7comm-plus system event ({payload.Length} bytes)");
        }

        private static long? SystemEventReturnValue(byte[] payload)
        {
            if (payload.Length < 16)
                throw new S7ProtocolException($"Malformed S7comm-plus system event: {ToHex(payload)}");
            if (payload.Length == 16) return null;

            // Anything that is not a struct suffix is informational, LOGOUT for example.
            if (payload.Length < 20 || S7Codec.ReadUInt32(payload, 16) != (uint)DataType.Struct) return null;
            if (payload.Length < 24)
                throw new S7ProtocolException($"Malformed S7comm-plus system event struct: {ToHex(payload)}");

            int offset = 24;        // fixed-width PValue header plus the struct id
            while (offset + 4 <= payload.Length)
            {
                uint memberId = S7Codec.ReadUInt32(payload, offset);
                offset += 4;
                if (memberId == 0) break;

                if (offset + 4 > payload.Length)
                    throw new S7ProtocolException($"Malformed S7comm-plus system event member: {ToHex(payload)}");

                byte flags = payload[offset + 1];
                byte datatype = payload[offset + 3];
                offset += 4;

                if (flags != 0)
                    throw new S7ProtocolException(
                        $"Unsupported S7comm-plus system event member flags 0x{flags:X2}: {ToHex(payload)}");

                int size = ScalarSize(datatype);
                if (size == 0 || offset + size > payload.Length)
                    throw new S7ProtocolException(
                        $"Unsupported or truncated system event datatype 0x{datatype:X2}: {ToHex(payload)}");

                if (memberId == SystemEventReturnValueId)
                {
                    if (datatype != (byte)DataType.LInt)
                        throw new S7ProtocolException($"Malformed system event ReturnValue: {ToHex(payload)}");
                    long value = 0;
                    for (int i = 0; i < size; i++) value = (value << 8) | payload[offset + i];
                    if (size == 8) return value;
                    return value;
                }
                offset += size;
            }

            throw new S7ProtocolException($"S7comm-plus system event struct has no ReturnValue: {ToHex(payload)}");
        }

        private static int ScalarSize(byte datatype)
        {
            switch ((DataType)datatype)
            {
                case DataType.Bool:
                case DataType.USInt:
                case DataType.SInt:
                case DataType.Byte:
                    return 1;
                case DataType.UInt:
                case DataType.Int:
                case DataType.Word:
                    return 2;
                case DataType.UDInt:
                case DataType.DInt:
                case DataType.DWord:
                case DataType.Real:
                case DataType.Rid:
                case DataType.Aid:
                    return 4;
                case DataType.ULInt:
                case DataType.LInt:
                case DataType.LWord:
                case DataType.LReal:
                case DataType.Timestamp:
                case DataType.Timespan:
                    return 8;
                default:
                    return 0;
            }
        }

        private static string ToHex(byte[] data) => BitConverter.ToString(data).Replace("-", string.Empty);

        // --- session establishment ------------------------------------------

        /// <summary>
        /// Open the session with a CreateObject on the NullServerSession.  The
        /// attribute set introduces the client the way TIA Portal does: V1-initial
        /// S7-1200 firmware only returns ServerSessionVersion when the client
        /// identifies itself this fully, and a minimal request yields an
        /// incomplete session.
        /// </summary>
        private void CreateSession()
        {
            ushort seq = NextSequenceNumber();

            var r = new List<byte>();
            r.AddRange(S7Codec.EncodeRequestHeader((ushort)FunctionCode.CreateObject, seq,
                                                   (uint)ObjectId.ObjectNullServerSession, 0x36));

            // RequestId: the server-session container
            S7Codec.AppendUInt32(r, (uint)ObjectId.ObjectServerSessionContainer);
            // RequestValue: UDInt(0)
            r.Add(0x00); r.Add((byte)DataType.UDInt); Vlq.AppendUInt32(r, 0);
            // Protocol-defined padding
            S7Codec.AppendUInt32(r, 0);

            // RequestObject: the new server session
            r.Add((byte)ElementId.StartOfObject);
            S7Codec.AppendUInt32(r, (uint)ObjectId.GetNewRidOnServer);
            Vlq.AppendUInt32(r, (uint)ObjectId.ClassServerSession);
            Vlq.AppendUInt32(r, 0);                      // ClassFlags
            Vlq.AppendUInt32(r, 0);                      // AttributeId

            const string clientId = "CsS7CommPlus";
            AppendWStringAttribute(r, 233, clientId);                       // class name
            AppendWStringAttribute(r, 289, $"1:::6.0::{clientId}");         // network interface
            AppendWStringAttribute(r, 296, clientId);                       // project name
            AppendWStringAttribute(r, 297, string.Empty);
            AppendWStringAttribute(r, 298, clientId);                       // host name

            r.Add((byte)ElementId.Attribute); Vlq.AppendUInt32(r, 299);
            r.Add(0x00); r.Add((byte)DataType.UDInt); Vlq.AppendUInt32(r, 1);

            r.Add((byte)ElementId.Attribute);
            Vlq.AppendUInt32(r, (uint)ObjectId.ServerSessionClientRid);
            r.Add(0x00); r.Add((byte)DataType.Rid); S7Codec.AppendUInt32(r, 0x80C3C901);

            AppendWStringAttribute(r, 301, string.Empty);

            // Nested subscription container, with its required class-name attribute
            r.Add((byte)ElementId.StartOfObject);
            S7Codec.AppendUInt32(r, (uint)ObjectId.GetNewRidOnServer);
            Vlq.AppendUInt32(r, (uint)ObjectId.ClassSubscriptions);
            Vlq.AppendUInt32(r, 0);
            Vlq.AppendUInt32(r, 0);
            AppendWStringAttribute(r, 233, "SubscriptionContainer");
            r.Add((byte)ElementId.TerminatingObject);

            r.Add((byte)ElementId.TerminatingObject);
            S7Codec.AppendUInt32(r, 0);                  // trailing padding

            // CreateObject always goes out with V1 framing.
            SendFrame(Protocol.ProtocolVersion.V1, r.ToArray());

            var response = ReceiveFrameData(out var version);
            if (response.Length < S7Codec.ResponseHeaderLength)
                throw new S7ConnectionException("CreateObject response is shorter than its header");

            int offset;
            var objectIds = S7Codec.ParseCreateObjectSessionId(
                S7Codec.Slice(response, S7Codec.ResponseHeaderLength,
                              response.Length - S7Codec.ResponseHeaderLength),
                out offset, out ulong returnValue);

            if (objectIds.Count == 0)
                throw new S7ConnectionException("CreateObject response carries no session object id");

            // The first object id is the session; the second is its subscription container.
            SessionId = objectIds[0];
            SubscriptionContainerId = objectIds.Count > 1 ? objectIds[1] : 0;
            ProtocolVersion = version;

            // Some firmware returns a non-zero status on a session that works, so
            // this is informational and the returned session data is still parsed.
            if (returnValue != 0)
                Log($"CreateObject returned 0x{returnValue:X} on an active TLS session; continuing");

            int treeStart = S7Codec.ResponseHeaderLength + offset;
            var attrs = S7Codec.ParseCreateObjectAttributes(
                S7Codec.Slice(response, treeStart, response.Length - treeStart));

            _serverSessionVersion = attrs.ServerSessionVersion;
            Log(_serverSessionVersion != null
                ? $"Session 0x{SessionId:X8} created, V{(int)version}, ServerSessionVersion {_serverSessionVersion.Length} bytes"
                : $"Session 0x{SessionId:X8} created, V{(int)version}, no ServerSessionVersion in the response");
        }

        private static void AppendWStringAttribute(List<byte> buffer, uint attributeId, string value)
        {
            var data = Encoding.UTF8.GetBytes(value);
            buffer.Add((byte)ElementId.Attribute);
            Vlq.AppendUInt32(buffer, attributeId);
            buffer.Add(0x00);
            buffer.Add((byte)DataType.WString);
            Vlq.AppendUInt32(buffer, (uint)data.Length);
            buffer.AddRange(data);
        }

        /// <summary>
        /// Complete session setup by echoing ServerSessionVersion back in a V2
        /// SetMultiVariables, with transport flags 0x34 and no IntegrityId yet.
        /// The device PAOM string is blanked first, as TIA Portal does.
        /// </summary>
        private bool SetupSession()
        {
            if (_serverSessionVersion == null) return false;

            ushort seq = NextSequenceNumber();

            var r = new List<byte>();
            r.AddRange(S7Codec.EncodeRequestHeader((ushort)FunctionCode.SetMultiVariables, seq, SessionId, 0x34));

            S7Codec.AppendUInt32(r, SessionId);                 // InObjectId
            Vlq.AppendUInt32(r, 1);                             // ItemCount
            Vlq.AppendUInt32(r, 1);                             // AddressCount
            Vlq.AppendUInt32(r, (uint)ObjectId.ServerSessionVersion);
            Vlq.AppendUInt32(r, 1);                             // ItemNumber

            r.AddRange(S7Codec.StripPaomStringInSessionVersion(_serverSessionVersion));

            r.Add(0x00);                                        // fill byte
            r.AddRange(S7Codec.EncodeObjectQualifier(0, ProtocolVersion));
            S7Codec.AppendUInt32(r, 0);                         // trailing padding

            // The setup write always goes out as V2, whatever CreateObject negotiated.
            SendFrame(Protocol.ProtocolVersion.V2, r.ToArray());

            var response = ReceiveFrameData(out _);
            if (response.Length < S7Codec.ResponseHeaderLength)
                throw new S7ConnectionException("Session-setup response is shorter than its header");

            var payload = S7Codec.Slice(response, S7Codec.ResponseHeaderLength,
                                        response.Length - S7Codec.ResponseHeaderLength);
            if (payload.Length == 0) return false;

            ulong returnValue = Vlq.DecodeUInt64(payload, 0, out _);
            if (returnValue != 0)
            {
                Log($"Session setup rejected by the PLC: return_value=0x{returnValue:X}");
                return false;
            }

            Log("Session setup completed");
            return true;
        }

        /// <summary>Close the session on the PLC with a DeleteObject.</summary>
        private void DeleteSession()
        {
            ushort seq = NextSequenceNumber();

            var r = new List<byte>();
            r.AddRange(S7Codec.EncodeRequestHeader((ushort)FunctionCode.DeleteObject, seq, SessionId, 0x34));
            S7Codec.AppendUInt32(r, 0);

            SendFrame(ProtocolVersion, r.ToArray());
            try { ReceiveFrameData(out _); } catch { /* best effort */ }
        }

        /// <summary>
        /// Read the session's effective protection level, or null when the PLC does
        /// not report one.  Lower is more privileged; see <see cref="AccessLevel"/>.
        /// </summary>
        private int? ReadEffectiveProtectionLevel()
        {
            try
            {
                var payload = BuildGetVarSubStreamedPayload(SessionId, Ids.EffectiveProtectionLevel);
                var response = SendRequest(FunctionCode.GetVarSubStreamed, payload, 4);
                return ParseScalarUDIntResponse(response);
            }
            catch (S7Exception e)
            {
                Log($"PLC did not report a protection level: {e.Message}");
                return null;
            }
        }

        /// <summary>
        /// Build a GetVarSubStreamed request set.  The IntegrityId is spliced in
        /// before the final four-byte fill by <see cref="SendRequest"/>.
        /// </summary>
        internal static byte[] BuildGetVarSubStreamedPayload(uint inObjectId, uint address,
                                                             uint keyQualifier = 0, ushort sequenceField = 1)
        {
            var o = new List<byte>();
            S7Codec.AppendUInt32(o, inObjectId);
            o.Add(0x20); o.Add((byte)DataType.UDInt); o.Add(0x01);     // one-element address array
            Vlq.AppendUInt32(o, address);
            o.AddRange(S7Codec.EncodeObjectQualifier(keyQualifier));
            S7Codec.AppendUInt16(o, sequenceField);
            S7Codec.AppendUInt32(o, 0);                                // fill
            return o.ToArray();
        }

        private static int ParseScalarUDIntResponse(byte[] payload)
        {
            ulong returnValue = Vlq.DecodeUInt64(payload, 0, out int offset);
            if (returnValue != 0)
                throw new S7ConnectionException($"GetVarSubStreamed failed: return_value=0x{returnValue:X}");

            if (offset >= payload.Length) throw new S7ProtocolException("GetVarSubStreamed response has no marker");
            offset += 1;                                               // protocol-defined unknown byte

            if (offset + 2 > payload.Length) throw new S7ProtocolException("GetVarSubStreamed response has no PValue header");
            byte flags = payload[offset];
            byte datatype = payload[offset + 1];
            offset += 2;

            if (datatype != (byte)DataType.UDInt || (flags & 0x10) != 0)
                throw new S7ProtocolException(
                    $"Expected a scalar UDInt, got flags=0x{flags:X2} datatype=0x{datatype:X2}");

            return (int)Vlq.DecodeUInt32(payload, offset, out _);
        }
    }
}
