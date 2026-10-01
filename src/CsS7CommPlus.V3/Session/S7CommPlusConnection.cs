using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using CsS7CommPlus.V3.Protocol;
using CsS7CommPlus.V3.Transport;

namespace CsS7CommPlus.V3.Session
{
    /// <summary>Which session authentication the PLC expects.</summary>
    public enum SessionMode
    {
        /// <summary>Decide from the PLC's CreateObject reply; the default.</summary>
        Automatic = 0,
        /// <summary>Force the pre-TIA-V17 challenge scheme.</summary>
        SessionKey = 1,
        /// <summary>Force the TIA-V17+ TLS scheme.</summary>
        Tls = 2,
    }

    /// <summary>
    /// An S7comm-plus session to one S7-1200/1500 CPU.
    ///
    /// The protocol has two session variants and a CPU supports one of them,
    /// decided by the TIA Portal version the project was made with:
    ///
    /// * **SessionKey** (TIA Portal V16 and earlier).  CreateObject goes out in
    ///   clear text and the PLC answers with a 20-byte challenge and the
    ///   fingerprint of the public key it expects.  The client solves the
    ///   challenge, sends the result in the session-setup write, and every frame
    ///   afterwards carries a keyed digest over its own bytes.
    /// * **TLS** (TIA Portal V17 and later).  An InitSSL exchange is followed by a
    ///   TLS handshake whose records travel inside COTP data frames, and the V2
    ///   framing inside it needs no digest because TLS already protects it.
    ///
    /// <see cref="SessionMode.Automatic"/> reads the CreateObject reply and picks:
    /// a challenge and fingerprint mean SessionKey, their absence means the CPU
    /// wanted TLS.  Either way the symbol browse, reads, writes and subscriptions
    /// above this layer are identical.
    ///
    /// Ported from the MIT-licensed s7commplus Python backend (connection.py).
    /// A connection is driven by one caller at a time; requests are serialized
    /// internally, but a notification must not be awaited while a request is in
    /// flight.
    /// </summary>
    public class S7CommPlusConnection : IDisposable
    {
        private const int MaxSystemEventsPerResponse = 16;
        private const int MaxStaleResponsesPerRequest = 16;
        private const int MaxReassembledBytes = 16 * 1024 * 1024;
        private const int MaxReassembledFragments = 4096;
        private const uint SystemEventReturnValueId = 40305;

        /// <summary>The digest length a V3 frame declares ahead of its digest.</summary>
        private const byte IntegrityDigestLength = 0x20;

        /// <summary>Only the first 24 bytes of the session key key the digest.</summary>
        private const int DigestKeyLength = 24;

        private readonly object _requestLock = new object();
        private readonly Queue<byte[]> _notificationFrames = new Queue<byte[]>();

        private IsoTcpConnection? _iso;
        private Stream? _tls;
        private IPduTransport? _transport;

        private ushort _sequenceNumber;
        private bool _connected;
        private bool _sessionReady;

        private byte[]? _serverSessionVersion;
        private string? _publicKeyFingerprint;
        private byte[]? _sessionChallenge;
        private byte[]? _sessionKey;

        private bool _withIntegrityId;
        private uint _integrityIdRead;
        private uint _integrityIdWrite;

        /// <summary>PLC IP address or host name.</summary>
        public string Host { get; }

        /// <summary>ISO-on-TCP port, 102 unless overridden.</summary>
        public int Port { get; }

        /// <summary>Socket and request timeout in milliseconds.</summary>
        public int TimeoutMs { get; set; } = 5000;

        /// <summary>Which session authentication to use; automatic by default.</summary>
        public SessionMode Mode { get; set; } = SessionMode.Automatic;

        /// <summary>The protocol version the session settled on.</summary>
        public ProtocolVersion ProtocolVersion { get; private set; }

        /// <summary>Session id allocated by the PLC; the first CreateObject object id.</summary>
        public uint SessionId { get; private set; }

        /// <summary>Object id of this session's subscription container.</summary>
        public uint SubscriptionContainerId { get; private set; }

        /// <summary>Whether the session is open and set up.</summary>
        public bool Connected => _connected;

        /// <summary>Whether the session is protected by TLS rather than a keyed digest.</summary>
        public bool TlsActive => _tls != null;

        /// <summary>Whether frames carry a keyed digest, i.e. the SessionKey variant is in use.</summary>
        public bool SessionKeyActive => _sessionKey != null;

        /// <summary>The PLC's effective protection level, when it reported one.</summary>
        public int? ProtectionLevel { get; private set; }

        /// <summary>The fingerprint of the public key the PLC asked for, when it named one.</summary>
        public string? PublicKeyFingerprint => _publicKeyFingerprint;

        /// <summary>Raised for each protocol-level diagnostic; wire to the host's logger.</summary>
        public event Action<string>? OnDiagnostic;

        /// <summary>
        /// Log every frame sent and received as hex through <see cref="OnDiagnostic"/>.
        /// Siemens does not document this protocol, so when a CPU refuses a request
        /// the frame bytes are the only way to see why; leave it off in production.
        /// </summary>
        public bool TraceFrames { get; set; }

        /// <summary>Create a connection for the given PLC.</summary>
        public S7CommPlusConnection(string host, int port = 102)
        {
            Host = host;
            Port = port;
        }

        private void Log(string message) => OnDiagnostic?.Invoke(message);

        // --- connect / disconnect ------------------------------------------

        /// <summary>
        /// Open the socket, negotiate the session the PLC supports, and complete
        /// session setup.
        /// </summary>
        public void Connect()
        {
            // A CPU supports one session variant, so the only reliable way to find
            // out is to offer the TLS handshake and see whether it is taken. One
            // that wants the older scheme refuses it, and the socket is then no
            // longer usable, so the fallback reconnects.
            if (Mode == SessionMode.SessionKey)
            {
                ConnectOnce(useTls: false);
                return;
            }

            if (Mode == SessionMode.Tls)
            {
                ConnectOnce(useTls: true);
                return;
            }

            try
            {
                ConnectOnce(useTls: true);
                return;
            }
            catch (S7AuthenticationException e)
            {
                Log($"TLS was refused ({e.Message}); trying the session-key scheme");
            }
            catch (S7ConnectionException e)
            {
                Log($"TLS did not complete ({e.Message}); trying the session-key scheme");
            }

            Disconnect();
            ConnectOnce(useTls: false);
        }

        private void ConnectOnce(bool useTls)
        {
            try
            {
                _iso = new IsoTcpConnection(Host, Port);
                _iso.Open(TimeoutMs);
                _transport = _iso;

                InitSsl();

                if (useTls)
                {
                    _tls = SiemensTlsHandshake.Activate(_iso, Log);
                    _transport = new StreamPduTransport(_tls, _iso);
                    Log("TLS activated; its records travel inside COTP data frames");
                }

                CreateSession();

                bool wantsSessionKey = !useTls && _sessionChallenge != null && _publicKeyFingerprint != null;

                if (Mode == SessionMode.SessionKey && !wantsSessionKey)
                    throw new S7AuthenticationException(
                        "SessionKey authentication was requested but the PLC offered no challenge");

                if (useTls)
                {
                    // Inside TLS the data PDUs are V2, whatever CreateObject used.
                    ProtocolVersion = ProtocolVersion.V2;
                }

                if (_serverSessionVersion == null)
                    throw new S7ConnectionException(
                        "PLC did not return a ServerSessionVersion attribute; session setup cannot continue");

                SessionKeyMaterial? material = null;
                if (wantsSessionKey)
                {
                    material = SessionKeyAuth.Authenticate(_publicKeyFingerprint!, _sessionChallenge!);
                    if (material == null)
                        throw new S7AuthenticationException(
                            $"PLC asked for public key {_publicKeyFingerprint}, which is not in the bundled key set");
                    Log($"Session-key blob built for {_publicKeyFingerprint} ({material.Blob.Length} bytes)");
                }

                if (!SetupSession(material))
                    throw new S7ConnectionException("The PLC rejected S7comm-plus session setup");

                _sessionReady = true;
                _withIntegrityId = true;
                _integrityIdRead = 0;
                _integrityIdWrite = 0;
                _connected = true;

                if (material != null)
                {
                    // From here every frame carries a keyed digest.
                    _sessionKey = material.SessionKey;
                    Log("Session key accepted; frame digests enabled");
                    ActivateSession();
                }

                ProtectionLevel = ReadEffectiveProtectionLevel();
                if (ProtectionLevel != null) Log($"PLC reports protection level {ProtectionLevel}");

                Log($"Connected to {Host}:{Port}, V{(int)ProtocolVersion}, session=0x{SessionId:X8}, " +
                    (TlsActive ? "TLS" : "session key"));
            }
            catch
            {
                Disconnect();
                throw;
            }
        }

        /// <summary>Run the InitSSL exchange, which precedes CreateObject on every CPU.</summary>
        private void InitSsl()
        {
            ushort seq = NextSequenceNumber();

            var r = new List<byte>();
            r.AddRange(S7Codec.EncodeRequestHeader((ushort)FunctionCode.InitSsl, seq, 0, 0x30));
            S7Codec.AppendUInt32(r, 0);

            SendFrame(Protocol.ProtocolVersion.V1, r.ToArray());

            var response = ReceiveFrameData(out _);
            if (response.Length < S7Codec.ResponseHeaderLength)
                throw new S7ConnectionException("InitSSL response is shorter than its header");
            Log($"InitSSL acknowledged ({response.Length} bytes)");
        }

        /// <summary>Delete the session on the PLC and close the socket.</summary>
        public void Disconnect()
        {
            if (_sessionReady && SessionId != 0)
            {
                try { DeleteSession(); } catch { /* best effort */ }
            }

            try { _tls?.Dispose(); } catch { /* ignore */ }
            try { _iso?.Close(); } catch { /* ignore */ }
            ResetState();
        }

        /// <summary>Close the socket immediately, without the clean-up requests.</summary>
        public void Abort()
        {
            try { _iso?.Abort(); } catch { /* ignore */ }
            try { _tls?.Dispose(); } catch { /* ignore */ }
            ResetState();
        }

        private void ResetState()
        {
            _connected = false;
            _sessionReady = false;
            SessionId = 0;
            SubscriptionContainerId = 0;
            _sequenceNumber = 0;
            ProtocolVersion = 0;
            _serverSessionVersion = null;
            _publicKeyFingerprint = null;
            _sessionChallenge = null;
            _sessionKey = null;
            _withIntegrityId = false;
            _integrityIdRead = 0;
            _integrityIdWrite = 0;
            ProtectionLevel = null;
            _notificationFrames.Clear();
            _tls = null;
            _iso = null;
            _transport = null;
        }

        /// <inheritdoc/>
        public void Dispose() => Disconnect();

        // --- request / response --------------------------------------------

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
        /// How many trailing payload bytes the IntegrityId is spliced in *before*:
        /// 4 for GetMultiVariables and SetMultiVariables (a trailing 32-bit fill),
        /// 5 for Explore (a fill plus a filler byte), 3 for SetVariable, and for
        /// CreateObject whatever the request builder reports.
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

            // After session-key authentication every request uses 0x34, matching
            // TIA Portal; otherwise it depends on the request class.
            byte transportFlags = _sessionKey != null || S7Protocol.Flags34FunctionCodes.Contains(fc)
                ? (byte)0x34
                : (byte)0x36;

            var requestHeader = S7Codec.EncodeRequestHeader(fc, seq, SessionId, transportFlags);

            byte[] integrityIdBytes = new byte[0];
            if (_withIntegrityId)
            {
                bool isRead = S7Protocol.ReadFunctionCodes.Contains(fc);
                integrityIdBytes = Vlq.EncodeUInt32(isRead ? _integrityIdRead : _integrityIdWrite);
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

            SendFrame(_sessionKey != null ? Protocol.ProtocolVersion.V3 : ProtocolVersion, request.ToArray());

            if (_withIntegrityId)
            {
                if (S7Protocol.ReadFunctionCodes.Contains(fc))
                    _integrityIdRead = unchecked(_integrityIdRead + 1);
                else
                    _integrityIdWrite = unchecked(_integrityIdWrite + 1);
            }

            var response = ReceiveResponse(seq);
            ValidateResponseHeader(response, fc, seq);

            var responsePayload = S7Codec.Slice(response, S7Codec.ResponseHeaderLength,
                                                response.Length - S7Codec.ResponseHeaderLength);

            // An authenticated session prefixes its response payload with the
            // IntegrityId it answered under.
            if (_sessionKey != null && responsePayload.Length > 1)
            {
                Vlq.DecodeUInt32(responsePayload, 0, out int consumed);
                responsePayload = S7Codec.Slice(responsePayload, consumed, responsePayload.Length - consumed);
            }

            return responsePayload;
        }

        /// <summary>
        /// Wrap a request in the frame header and trailer and send it.  A V3 frame
        /// also carries the digest of its own data, length-prefixed, ahead of the
        /// request.
        /// </summary>
        private void SendFrame(ProtocolVersion version, byte[] data)
        {
            if (_transport == null) throw new S7ConnectionException("Not connected");

            byte[] framePayload;
            if (version == Protocol.ProtocolVersion.V3 && _sessionKey != null)
            {
                var digest = ComputeDigest(data);
                framePayload = new byte[1 + digest.Length + data.Length];
                framePayload[0] = IntegrityDigestLength;
                Array.Copy(digest, 0, framePayload, 1, digest.Length);
                Array.Copy(data, 0, framePayload, 1 + digest.Length, data.Length);
            }
            else
            {
                framePayload = data;
            }

            var frame = new List<byte>(framePayload.Length + 8);
            frame.AddRange(S7Codec.EncodeHeader(version, framePayload.Length));
            frame.AddRange(framePayload);
            frame.AddRange(new byte[] { S7Protocol.ProtocolId, (byte)version, 0x00, 0x00 });

            var bytes = frame.ToArray();
            if (TraceFrames) Log($"send V{(int)version} {bytes.Length} bytes: {ToHex(bytes)}");
            _transport.Send(bytes);
        }

        private byte[] ComputeDigest(byte[] data)
        {
            using var hmac = new HMACSHA256(S7Codec.Slice(_sessionKey!, 0, DigestKeyLength));
            return hmac.ComputeHash(data);
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

                if (version == Protocol.ProtocolVersion.SystemEvent)
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
        /// zero-length trailer.
        ///
        /// On an authenticated session each fragment carries a digest, and those
        /// digests are cumulative: the digest on fragment two covers fragment one's
        /// data as well, so one running digest spans the whole response.
        /// </summary>
        private byte[] ReceiveFrameData(out ProtocolVersion version)
        {
            var header = ReadExact(4);
            if (header[0] != S7Protocol.ProtocolId)
                throw new S7ProtocolException($"Expected an S7comm-plus fragment header, got 0x{header[0]:X2}");

            version = (ProtocolVersion)header[1];
            int fragmentLength = (header[2] << 8) | header[3];
            if (fragmentLength == 0) return new byte[0];        // standalone trailer

            IncrementalHash? running = null;
            try
            {
                if (_sessionKey != null && version == Protocol.ProtocolVersion.V3)
                    running = IncrementalHash.CreateHMAC(
                        HashAlgorithmName.SHA256, S7Codec.Slice(_sessionKey, 0, DigestKeyLength));

                var data = new List<byte>(fragmentLength);
                data.AddRange(VerifyFragment(ReadExact(fragmentLength), version, running));
                int fragments = 1;

                while (true)
                {
                    var next = ReadExact(4);
                    if (next[0] != S7Protocol.ProtocolId)
                        throw new S7ProtocolException($"Expected an S7comm-plus fragment header, got 0x{next[0]:X2}");

                    var nextVersion = (ProtocolVersion)next[1];
                    int nextLength = (next[2] << 8) | next[3];

                    if (nextLength == 0) break;                 // trailer: that was the last fragment

                    if (nextVersion != version)
                        throw new S7ProtocolException(
                            $"Response changed fragment version from V{(int)version} to V{(int)nextVersion}");

                    data.AddRange(VerifyFragment(ReadExact(nextLength), version, running));

                    if (++fragments > MaxReassembledFragments || data.Count > MaxReassembledBytes)
                        throw new S7ConnectionException(
                            $"Reassembled response exceeds its limits ({data.Count} bytes, {fragments} fragments)");
                }

                var result = data.ToArray();
                if (TraceFrames) Log($"recv V{(int)version} {result.Length} bytes: {ToHex(result)}");
                return result;
            }
            finally
            {
                running?.Dispose();
            }
        }

        /// <summary>
        /// Check and strip a fragment's digest.  An authenticated session must not
        /// accept an unauthenticated frame, and a failed check means the session is
        /// no longer trustworthy, so it is dropped rather than retried.
        /// </summary>
        private byte[] VerifyFragment(byte[] fragment, ProtocolVersion version, IncrementalHash? running)
        {
            if (_sessionKey == null)
            {
                if (version == Protocol.ProtocolVersion.V3)
                    throw new S7ProtocolException("Received a V3 frame without a session key");
                return fragment;
            }

            if (version != Protocol.ProtocolVersion.V3)
            {
                InvalidateOnIntegrityFailure();
                throw new S7IntegrityException(
                    $"Authenticated session received an unauthenticated V{(int)version} frame; reconnect");
            }

            if (fragment.Length == 0) throw new S7IntegrityException("Empty authenticated frame");

            int digestLength = fragment[0];
            if (digestLength != IntegrityDigestLength)
                throw new S7IntegrityException($"Invalid frame digest length {digestLength}");
            if (fragment.Length < 1 + digestLength)
                throw new S7IntegrityException("Truncated frame digest");

            var received = S7Codec.Slice(fragment, 1, digestLength);
            var applicationData = S7Codec.Slice(fragment, 1 + digestLength, fragment.Length - 1 - digestLength);

            byte[] expected;
            if (running != null)
            {
                running.AppendData(applicationData);
                expected = running.GetCurrentHash();
            }
            else
            {
                expected = ComputeDigest(applicationData);
            }

            if (!FixedTimeEquals(received, expected))
            {
                InvalidateOnIntegrityFailure();
                throw new S7IntegrityException("S7comm-plus response failed its integrity check");
            }

            return applicationData;
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        /// <summary>Discard the session without writing to a stream that can no longer be trusted.</summary>
        private void InvalidateOnIntegrityFailure()
        {
            _sessionReady = false;
            Abort();
        }

        private byte[] ReadExact(int count)
        {
            var transport = _transport ?? throw new S7ConnectionException("Not connected");

            var buffer = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = transport.Read(buffer, read, count - read);
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
                    if (version == Protocol.ProtocolVersion.SystemEvent) { CheckSystemEvent(data); continue; }
                    if (data.Length == 0) continue;
                    if (data[0] == (byte)Opcode.Notification) return data;
                    throw new S7ConnectionException($"Expected a notification, got opcode 0x{data[0]:X2}");
                }
            }
        }

        /// <summary>Set the receive timeout used while waiting for notifications.</summary>
        public void SetReceiveTimeout(int milliseconds) => _transport?.SetReadTimeout(milliseconds);

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
        /// attribute set introduces the client the way TIA Portal does: a
        /// V1-initial CPU only returns ServerSessionVersion, its public-key
        /// fingerprint and its challenge when the client identifies itself this
        /// fully, and a minimal request yields an incomplete session.
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

            var body = S7Codec.Slice(response, S7Codec.ResponseHeaderLength,
                                     response.Length - S7Codec.ResponseHeaderLength);
            var objectIds = S7Codec.ParseCreateObjectSessionId(body, out int offset, out ulong returnValue);

            if (objectIds.Count == 0)
                throw new S7ConnectionException("CreateObject response carries no session object id");

            // The first object id is the session; the second is its subscription container.
            SessionId = objectIds[0];
            SubscriptionContainerId = objectIds.Count > 1 ? objectIds[1] : 0;
            ProtocolVersion = version;

            // Some firmware returns a non-zero status on a session that works, so
            // this is informational and the returned session data is still parsed.
            if (returnValue != 0)
                Log($"CreateObject returned 0x{returnValue:X}; continuing to parse the returned session data");

            var attrs = S7Codec.ParseCreateObjectAttributes(
                S7Codec.Slice(body, offset, body.Length - offset));

            _serverSessionVersion = attrs.ServerSessionVersion;
            _publicKeyFingerprint = attrs.PublicKeyFingerprint;
            _sessionChallenge = attrs.SessionChallenge;

            Log($"Session 0x{SessionId:X8} created, V{(int)version}, " +
                $"ServerSessionVersion {(_serverSessionVersion?.Length ?? 0)} bytes, " +
                $"key {(_publicKeyFingerprint ?? "(none)")}, " +
                $"challenge {(_sessionChallenge == null ? "(none)" : _sessionChallenge.Length + " bytes")}");
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
        /// The device identity string is blanked first, as TIA Portal does.
        ///
        /// On the SessionKey variant the same write also carries the solved
        /// challenge, at element 1830.
        /// </summary>
        private bool SetupSession(SessionKeyMaterial? material)
        {
            if (_serverSessionVersion == null) return false;

            ushort seq = NextSequenceNumber();

            var r = new List<byte>();
            r.AddRange(S7Codec.EncodeRequestHeader((ushort)FunctionCode.SetMultiVariables, seq, SessionId, 0x34));

            S7Codec.AppendUInt32(r, SessionId);                 // InObjectId

            if (material != null)
            {
                Vlq.AppendUInt32(r, 2);                         // ItemCount
                Vlq.AppendUInt32(r, 2);                         // AddressCount
                Vlq.AppendUInt32(r, LegitimationIds.SessionSetupLegitimation);
                Vlq.AppendUInt32(r, (uint)ObjectId.ServerSessionVersion);
                Vlq.AppendUInt32(r, 1);                         // ItemNumber of the security key
                r.AddRange(SessionKeyAuth.EncodeSecurityKeyStruct(material));
                Vlq.AppendUInt32(r, 2);                         // ItemNumber of the session version
            }
            else
            {
                Vlq.AppendUInt32(r, 1);                         // ItemCount
                Vlq.AppendUInt32(r, 1);                         // AddressCount
                Vlq.AppendUInt32(r, (uint)ObjectId.ServerSessionVersion);
                Vlq.AppendUInt32(r, 1);                         // ItemNumber
            }

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

        /// <summary>
        /// Activate the session after the challenge was accepted.  TIA Portal
        /// writes 5 to element 323 of the session object immediately after the key
        /// exchange and before any data read, and the CPU expects the same.  The
        /// key qualifier carries the current sequence number as a fixed-width
        /// value, and the IntegrityId is spliced in before the three trailing zeros.
        /// </summary>
        private void ActivateSession()
        {
            var p = new List<byte>();
            S7Codec.AppendUInt32(p, SessionId);
            Vlq.AppendUInt32(p, 1);                             // AddressCount
            Vlq.AppendUInt32(p, 323);                           // element id
            p.Add(0x00); p.Add((byte)DataType.USInt); Vlq.AppendUInt32(p, 5);
            p.AddRange(S7Codec.EncodeObjectQualifier(_sequenceNumber, Protocol.ProtocolVersion.V1));
            p.AddRange(new byte[3]);

            SendRequest(FunctionCode.SetVariable, p.ToArray(), 3);
            Log("Session activated");
        }

        /// <summary>Close the session on the PLC with a DeleteObject.</summary>
        private void DeleteSession()
        {
            ushort seq = NextSequenceNumber();

            var r = new List<byte>();
            r.AddRange(S7Codec.EncodeRequestHeader((ushort)FunctionCode.DeleteObject, seq, SessionId, 0x34));
            S7Codec.AppendUInt32(r, 0);

            SendFrame(_sessionKey != null ? Protocol.ProtocolVersion.V3 : ProtocolVersion, r.ToArray());
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
            catch (S7IntegrityException) { throw; }
            catch (S7ConnectionException) { throw; }
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
                throw new S7ProtocolException($"GetVarSubStreamed failed: return_value=0x{returnValue:X}");

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
