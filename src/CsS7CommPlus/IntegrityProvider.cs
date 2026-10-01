using CsS7CommPlus.Constants;

namespace CsS7CommPlus
{
    /// <summary>
    /// Hook for the proprietary SIMATIC integrity protection (spec §6.2, §14).
    /// Direct port of the Python IntegrityProvider.
    ///
    /// Protocol-version-3 frames carry a 32-byte keyed digest derived from key
    /// material negotiated during the v2 SetMultiVariables exchange.  That key
    /// agreement and keyed hash are proprietary to Siemens; per spec Appendix C
    /// a C# client takes them from the MIT-licensed HarpoS7 rather than building
    /// them.  With the default provider below, v3 frames are still correctly
    /// built and parsed (digest zero-filled) — enough to round-trip framing and
    /// decode captured traffic — but a live PLC rejects the zero digest.
    /// </summary>
    public interface IIntegrityProvider
    {
        /// <summary>True when a real keyed digest can be produced.</summary>
        bool Available { get; }

        /// <summary>Compute the 32-byte digest over a PDU body for a sequence number.</summary>
        byte[] Digest(byte[] body, int seq);
    }

    /// <summary>Default provider: not available; returns 32 zero bytes.</summary>
    public class NullIntegrityProvider : IIntegrityProvider
    {
        /// <inheritdoc/>
        public bool Available => false;

        /// <inheritdoc/>
        public byte[] Digest(byte[] body, int seq) => new byte[S7PlusConstants.IntegrityDigestLen];
    }
}
