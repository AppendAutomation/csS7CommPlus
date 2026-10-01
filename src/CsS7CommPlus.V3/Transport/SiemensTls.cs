using System;
using System.Collections.Generic;
using System.IO;
using CsS7CommPlus.V3.Protocol;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using TlsVersion = Org.BouncyCastle.Tls.ProtocolVersion;

namespace CsS7CommPlus.V3.Transport
{
    /// <summary>
    /// A stream whose bytes travel inside COTP data frames.
    ///
    /// S7comm-plus carries TLS records as the payload of COTP data frames, so the
    /// TPKT and COTP headers stay in clear text on the wire.  Wrapping the socket
    /// in TLS instead would encrypt those headers too, and the PLC drops the
    /// connection.
    /// </summary>
    public sealed class CotpTunnelStream : Stream
    {
        private readonly IsoTcpConnection _iso;

        /// <summary>Tunnel through an open COTP connection.</summary>
        public CotpTunnelStream(IsoTcpConnection iso) => _iso = iso;

        /// <inheritdoc/>
        public override int Read(byte[] buffer, int offset, int count) => _iso.Read(buffer, offset, count);

        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count)
        {
            var data = new byte[count];
            Array.Copy(buffer, offset, data, 0, count);
            _iso.Send(data);
        }

        /// <inheritdoc/>
        public override void Flush() { }
        /// <inheritdoc/>
        public override bool CanRead => true;
        /// <inheritdoc/>
        public override bool CanSeek => false;
        /// <inheritdoc/>
        public override bool CanWrite => true;
        /// <inheritdoc/>
        public override long Length => throw new NotSupportedException();
        /// <inheritdoc/>
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        /// <inheritdoc/>
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        /// <inheritdoc/>
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    /// <summary>
    /// The TLS client a SIMATIC CPU accepts.
    ///
    /// The CPU is particular about what it is offered, and .NET's own
    /// <c>SslStream</c> cannot be told what to send per connection: on Windows it
    /// is SChannel, which advertises the session-ticket and
    /// extended-master-secret extensions and, before Windows 11, cannot speak TLS
    /// 1.3 at all.  A CPU answers such a hello with a TCP reset rather than an
    /// alert, which is why the handshake is driven by BouncyCastle instead — a
    /// managed stack whose hello this class controls exactly.
    ///
    /// Verified against an S7-1212C FW V4.6, which negotiates TLS 1.3 with
    /// TLS_AES_128_GCM_SHA256 over x25519.
    /// </summary>
    internal sealed class SiemensTlsClient : DefaultTlsClient
    {
        private readonly Action<string>? _log;

        /// <summary>Create the client, optionally logging what gets negotiated.</summary>
        public SiemensTlsClient(Action<string>? log = null) : base(new BcTlsCrypto()) => _log = log;

        /// <summary>
        /// TLS 1.3 first, with 1.2 kept as a fallback for older firmware.
        /// </summary>
        protected override TlsVersion[] GetSupportedVersions() => new[]
        {
            TlsVersion.TLSv13,
            TlsVersion.TLSv12,
        };

        /// <summary>
        /// x25519 is the group a SIMATIC CPU negotiates; the NIST curve is offered
        /// behind it for firmware that does not take x25519.  Offering the wider
        /// default list, with x448 and the finite-field groups in it, is what a CPU
        /// resets on.
        /// </summary>
        protected override IList<int> GetSupportedGroups(IList<int> namedGroupRoles) => new List<int>
        {
            NamedGroup.x25519,
            NamedGroup.secp256r1,
        };

        /// <summary>
        /// The extended master secret is not offered: a CPU resets on it, and the
        /// session it protects is the PLC's own, not a browser's.
        /// </summary>
        public override bool ShouldUseExtendedMasterSecret() => false;

        /// <inheritdoc/>
        public override bool RequiresExtendedMasterSecret() => false;

        /// <inheritdoc/>
        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            var extensions = base.GetClientExtensions();
            if (extensions != null)
            {
                extensions.Remove(ExtensionType.session_ticket);
                extensions.Remove(ExtensionType.extended_master_secret);
                extensions.Remove(ExtensionType.encrypt_then_mac);
            }
            return extensions!;
        }

        /// <summary>
        /// Accept the CPU's certificate.  Every S7-1200/1500 presents a
        /// self-signed per-device certificate, so there is no chain to validate
        /// against a public root; the client is not authenticated either.
        /// </summary>
        public override TlsAuthentication GetAuthentication() => new AcceptDeviceCertificate();

        /// <inheritdoc/>
        public override void NotifyServerVersion(TlsVersion serverVersion)
        {
            base.NotifyServerVersion(serverVersion);
            _log?.Invoke($"TLS: the PLC chose {serverVersion}");
        }

        /// <inheritdoc/>
        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            base.NotifyAlertReceived(alertLevel, alertDescription);
            if (alertLevel == AlertLevel.fatal)
                _log?.Invoke($"TLS alert from the PLC: {AlertDescription.GetText(alertDescription)}");
        }

        private sealed class AcceptDeviceCertificate : TlsAuthentication
        {
            public void NotifyServerCertificate(TlsServerCertificate serverCertificate) { }

            public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest) => null;
        }
    }

    /// <summary>Runs the TLS handshake a SIMATIC CPU expects and hands back the stream.</summary>
    public static class SiemensTlsHandshake
    {
        /// <summary>
        /// Activate TLS over an already-open COTP connection that has had its
        /// InitSSL exchange.  Throws <see cref="S7AuthenticationException"/> when
        /// the CPU refuses, which is how a CPU that wants the older session-key
        /// scheme answers.
        /// </summary>
        public static Stream Activate(IsoTcpConnection iso, Action<string>? log = null)
        {
            try
            {
                var protocol = new TlsClientProtocol(new CotpTunnelStream(iso));
                protocol.Connect(new SiemensTlsClient(log));
                return protocol.Stream;
            }
            catch (Exception e)
            {
                throw new S7AuthenticationException($"The PLC refused the TLS handshake: {e.Message}", e);
            }
        }
    }
}
