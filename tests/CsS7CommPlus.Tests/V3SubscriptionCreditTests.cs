using System;
using System.Collections.Generic;
using CsS7CommPlus.V3.Protocol;
using CsS7CommPlus.V3.Session;
using Xunit;

namespace CsS7CommPlus.Tests
{
    /// <summary>
    /// The subscription's credit limit, which decides how long the CPU keeps
    /// sending notifications.  Measured on an S7-1212C FW V4.6: a positive limit
    /// is honored to its low byte only, so the old default of 1000 silenced the
    /// subscription after 232 notifications - about two minutes on FlynnProbe's
    /// 500 ms cycle, which its watchdog read as a lost connection.  -1 asks for
    /// unlimited credit and does not stop.  Nothing covered this attribute
    /// before, which is how the defect shipped.
    /// </summary>
    public class V3SubscriptionCreditTests
    {
        private static SubscriptionItem OneItem() =>
            new SubscriptionItem(0x8A0E0001, new uint[] { 1, 2 }, null, 0, 1);

        /// <summary>The credit-limit attribute as it appears on the wire.</summary>
        private static byte[] CreditAttribute(byte high, byte low)
        {
            var expected = new List<byte> { (byte)ElementId.Attribute };
            Vlq.AppendUInt32(expected, Ids.SubscriptionCreditLimit);
            expected.Add(0x00);
            expected.Add((byte)DataType.Int);
            expected.Add(high);
            expected.Add(low);
            return expected.ToArray();
        }

        private static bool Contains(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i + needle.Length <= haystack.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        }

        private static byte[] Build(short creditLimit) =>
            SubscriptionCodec.BuildSubscriptionRequest(
                0x7040000C, new[] { OneItem() }, out _, 500, creditLimit);

        [Fact]
        public void TheDefaultAsksForUnlimitedCredit()
        {
            // A positive default is the defect: the CPU stops after
            // (limit & 0xFF) notifications and nothing replenishes it here.
            Assert.Equal(-1, SubscriptionCodec.DefaultCreditLimit);
            Assert.True(Contains(Build(SubscriptionCodec.DefaultCreditLimit), CreditAttribute(0xFF, 0xFF)));
        }

        [Theory]
        [InlineData((short)-1, (byte)0xFF, (byte)0xFF)]
        [InlineData((short)300, (byte)0x01, (byte)0x2C)]
        [InlineData((short)10, (byte)0x00, (byte)0x0A)]
        public void TheCreditLimitIsTwoRawBigEndianBytes(short creditLimit, byte high, byte low)
        {
            // DataType.Int is a fixed-width 16-bit value in this protocol, as in
            // S7Codec and in the Python reference - not a VLQ.  Encoding it as a
            // VLQ happens to work for 1000 (0x87 0x68, which reads back as a
            // negative int16 and so as unlimited), but it is not the fix.
            Assert.True(Contains(Build(creditLimit), CreditAttribute(high, low)));
        }

        [Fact]
        public void ACreditLimitBelowMinusOneIsRejected()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Build(-2));
        }
    }
}
