using System;
using System.Collections.Generic;
using CsS7CommPlus.V3.Protocol;
using HarpoS7.Auth;
using HarpoS7.PublicKeys.Impl;
using HarpoS7.Extensions;
using HarpoS7.Utilities.Auth;
using HarpoS7.Utilities.Extensions;

namespace CsS7CommPlus.V3.Session
{
    /// <summary>The material a successful session-key handshake produces.</summary>
    public class SessionKeyMaterial
    {
        /// <summary>The encrypted blob the PLC is sent to prove the client holds its key.</summary>
        public byte[] Blob { get; set; } = new byte[0];
        /// <summary>The 24-byte key every later frame's digest is computed with.</summary>
        public byte[] SessionKey { get; set; } = new byte[0];
        /// <summary>The PLC's public key the blob was built against.</summary>
        public byte[] PublicKey { get; set; } = new byte[0];
        /// <summary>The key family the fingerprint named.</summary>
        public EPublicKeyFamily Family { get; set; }
    }

    /// <summary>
    /// The pre-TIA-V17 session authentication, which Siemens calls SecurityTypeCSI.
    ///
    /// A V1-initial CPU answers CreateObject with a 20-byte challenge and the
    /// fingerprint of the public key it expects the client to use.  The client
    /// solves the challenge against that key, sends the result back inside the
    /// session-setup write, and both sides then hold a 24-byte session key that
    /// every later frame is digested with.
    ///
    /// The crypto is HarpoS7's (MIT): this only parses the fingerprint, looks the
    /// key up, and encodes the SecurityKey structure the PLC expects it in.
    /// </summary>
    public static class SessionKeyAuth
    {
        /// <summary>Length of the encrypted blob a real CPU expects, as against PLCSIM's.</summary>
        private const int EncryptedBlobLengthRealPlc = 180;

        /// <summary>
        /// Solve the PLC's challenge.  Returns null when the fingerprint names a
        /// key that is not in HarpoS7's bundled set, which means this CPU cannot be
        /// authenticated without its key being added.
        /// </summary>
        public static SessionKeyMaterial? Authenticate(string fingerprint, byte[] challenge)
        {
            if (string.IsNullOrEmpty(fingerprint) || challenge == null || challenge.Length == 0) return null;

            EPublicKeyFamily family;
            try
            {
                family = fingerprint.ToPublicKeyFamily();
            }
            catch (Exception)
            {
                return null;        // not a family this build understands
            }

            // PLCSIM uses a different blob layout; only real CPUs are handled here.
            if (family != EPublicKeyFamily.S71200 && family != EPublicKeyFamily.S71500) return null;

            byte[] publicKey;
            try
            {
                var store = new DefaultPublicKeyStore();
                publicKey = new byte[store.GetPublicKeyLength(fingerprint)];
                store.ReadPublicKey(publicKey.AsSpan(), fingerprint);
            }
            catch (Exception)
            {
                return null;        // no bundled key for this fingerprint
            }

            var blob = new byte[EncryptedBlobLengthRealPlc];
            var sessionKey = new byte[HarpoS7.Constants.SessionKeyLength];

            LegacyAuthenticationScheme.AuthenticateRealPlc(
                blob.AsSpan(), sessionKey.AsSpan(), challenge.AsSpan(), publicKey.AsSpan(), family);

            return new SessionKeyMaterial
            {
                Blob = blob,
                SessionKey = sessionKey,
                PublicKey = publicKey,
                Family = family,
            };
        }

        /// <summary>
        /// Encode the SecurityKey structure that carries the solved challenge.
        ///
        /// Inside a structure the members are a VLQ of the absolute element id
        /// followed by flags, type and value — there is no attribute tag, which
        /// only prefixes attributes in the object tree.  Structure 1800 holds the
        /// version, the security level, a descriptor for each of the two keys and
        /// the encrypted blob; each descriptor is structure 1825 with the key's
        /// derived id and its flags.
        /// </summary>
        public static byte[] EncodeSecurityKeyStruct(SessionKeyMaterial material)
        {
            if (material.PublicKey.Length == 0)
                throw new S7AuthenticationException("Session-key authentication needs the PLC's public key");
            if (material.SessionKey.Length == 0)
                throw new S7AuthenticationException("Session-key authentication needs the generated session key");

            var publicKeyId = DeriveKeyId(material.PublicKey);
            var symmetricKeyId = DeriveKeyId(material.SessionKey);

            int symmetricFlags = BlobMetadataWriter.GetSymmetricKeyFlags(material.Family);
            int publicFlags = BlobMetadataWriter.GetPublicKeyFlags(material.Family);

            var o = new List<byte>();
            StructBegin(o, Ids.StructSecurityKey);

            Vlq.AppendUInt32(o, 1801); UDIntValue(o, 0);                         // Version
            Vlq.AppendUInt32(o, 1802); USIntValue(o, 0);                         // SecurityLevel
            Vlq.AppendUInt32(o, 1803); o.AddRange(KeyDescriptor(publicKeyId, (uint)publicFlags));
            Vlq.AppendUInt32(o, 1804); o.AddRange(KeyDescriptor(symmetricKeyId, (uint)symmetricFlags | 0x10000));
            Vlq.AppendUInt32(o, 1805); BlobValue(o, material.Blob);              // EncryptedKey

            o.Add(0x00);                                                          // end of structure
            return o.ToArray();
        }

        private static byte[] KeyDescriptor(byte[] keyId, uint flags)
        {
            // The key id goes on the wire as a little-endian unsigned 64-bit value.
            ulong keyIdValue = 0;
            for (int i = keyId.Length - 1; i >= 0; i--) keyIdValue = (keyIdValue << 8) | keyId[i];

            var o = new List<byte>();
            StructBegin(o, Ids.SecurityKeyId);
            Vlq.AppendUInt32(o, 1826); ULIntValue(o, keyIdValue);    // KeyId
            Vlq.AppendUInt32(o, 1827); UDIntValue(o, flags);         // KeyFlags
            Vlq.AppendUInt32(o, 1828); UDIntValue(o, 0);             // InternalFlags
            o.Add(0x00);
            return o.ToArray();
        }

        private static void StructBegin(List<byte> o, uint structId)
        {
            o.Add(0x00);
            o.Add((byte)DataType.Struct);
            S7Codec.AppendUInt32(o, structId);
        }

        private static void UDIntValue(List<byte> o, uint value)
        {
            o.Add(0x00); o.Add((byte)DataType.UDInt); Vlq.AppendUInt32(o, value);
        }

        private static void USIntValue(List<byte> o, byte value)
        {
            o.Add(0x00); o.Add((byte)DataType.USInt); o.Add(value);
        }

        private static void ULIntValue(List<byte> o, ulong value)
        {
            o.Add(0x00); o.Add((byte)DataType.ULInt); Vlq.AppendUInt64(o, value);
        }

        private static void BlobValue(List<byte> o, byte[] data)
        {
            o.Add(0x00); o.Add((byte)DataType.Blob); o.Add(0x00);
            Vlq.AppendUInt32(o, (uint)data.Length);
            o.AddRange(data);
        }

        private static byte[] DeriveKeyId(byte[] key)
        {
            var keyId = new byte[HarpoS7.Constants.KeyIdLength];
            KeyExtensions.DeriveKeyId(key.AsSpan(), keyId.AsSpan());
            return keyId;
        }
    }
}
