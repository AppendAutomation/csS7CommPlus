using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CsS7CommPlus.V3.Protocol;
using CsS7CommPlus.V3.Session;
using Xunit;

namespace CsS7CommPlus.Tests
{
    /// <summary>
    /// The two CreateObject variants that open a session.  Firmware is split:
    /// most CPUs want the full TIA-Portal-style identification, while some
    /// S7-1200 firmware rejects it - a non-zero return value and no
    /// ServerSessionVersion - and accepts only the minimal ClientRID-only
    /// request the reference driver sends.  The connect path therefore tries the
    /// full set and retries with the minimal one on a fresh transport, which was
    /// proven against a live S7-1200 that exhibits the refusal.  These tests
    /// pin down the frames the two variants emit and the exception the retry
    /// keys on.
    /// </summary>
    public class V3SessionRequestTests
    {
        /// <summary>The ClientRID attribute both variants must carry.</summary>
        private static byte[] ClientRidAttribute()
        {
            var expected = new List<byte> { (byte)ElementId.Attribute };
            Vlq.AppendUInt32(expected, (uint)ObjectId.ServerSessionClientRid);
            expected.Add(0x00);
            expected.Add((byte)DataType.Rid);
            S7Codec.AppendUInt32(expected, 0x80C3C901);
            return expected.ToArray();
        }

        private static int CountOccurrences(byte[] haystack, byte[] needle)
        {
            int found = 0;
            for (int i = 0; i + needle.Length <= haystack.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                }
                if (match) found++;
            }
            return found;
        }

        [Fact]
        public void BothVariantsCarryTheClientRidExactlyOnce()
        {
            var rid = ClientRidAttribute();

            Assert.Equal(1, CountOccurrences(
                S7CommPlusConnection.BuildCreateSessionRequest(1, fullIdentification: true), rid));
            Assert.Equal(1, CountOccurrences(
                S7CommPlusConnection.BuildCreateSessionRequest(1, fullIdentification: false), rid));
        }

        [Fact]
        public void MinimalVariantOmitsTheIdentificationAttributes()
        {
            var minimal = S7CommPlusConnection.BuildCreateSessionRequest(1, fullIdentification: false);
            var full = S7CommPlusConnection.BuildCreateSessionRequest(1, fullIdentification: true);

            // Attributes 233, 289, 296 and 298 all carry the client id as a
            // WString, and 289 carries it inside the interface string.  None of
            // them belongs in the minimal request.
            var clientId = Encoding.UTF8.GetBytes("CsS7CommPlus");
            var interfaceString = Encoding.UTF8.GetBytes("1:::6.0::CsS7CommPlus");

            Assert.Equal(0, CountOccurrences(minimal, clientId));
            Assert.Equal(0, CountOccurrences(minimal, interfaceString));
            Assert.True(CountOccurrences(full, clientId) >= 4);
            Assert.Equal(1, CountOccurrences(full, interfaceString));
            Assert.True(minimal.Length < full.Length);
        }

        [Fact]
        public void BothVariantsKeepTheSubscriptionContainerAndTheSameHeader()
        {
            var minimal = S7CommPlusConnection.BuildCreateSessionRequest(7, fullIdentification: false);
            var full = S7CommPlusConnection.BuildCreateSessionRequest(7, fullIdentification: true);

            var container = Encoding.UTF8.GetBytes("SubscriptionContainer");
            Assert.Equal(1, CountOccurrences(minimal, container));
            Assert.Equal(1, CountOccurrences(full, container));

            // Everything ahead of the attribute section is the same request, so
            // only the identification differs between the two.
            var header = S7Codec.EncodeRequestHeader((ushort)FunctionCode.CreateObject, 7,
                                                     (uint)ObjectId.ObjectNullServerSession, 0x36);
            Assert.Equal(header, minimal.Take(header.Length).ToArray());
            Assert.Equal(header, full.Take(header.Length).ToArray());
            Assert.Equal(full.Take(header.Length + 10).ToArray(),
                         minimal.Take(header.Length + 10).ToArray());
        }

        [Fact]
        public void MissingSessionVersionIsAConnectionExceptionSoTheModeFallbackStillCatchesIt()
        {
            var e = new S7MissingSessionVersionException("no ServerSessionVersion");

            Assert.IsAssignableFrom<S7ConnectionException>(e);
            Assert.IsAssignableFrom<S7Exception>(e);
            Assert.Equal("no ServerSessionVersion", e.Message);
        }
    }
}
