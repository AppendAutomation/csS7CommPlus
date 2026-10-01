using System;
using System.Collections.Generic;
using CsS7CommPlus.V3.Protocol;
using Xunit;

namespace CsS7CommPlus.Tests
{
    /// <summary>
    /// The V3 wire codecs, checked against vectors produced by the MIT-licensed
    /// s7commplus Python backend this layer was ported from.  Every expected
    /// value below is that implementation's output for the same input, so a
    /// divergence in the port shows up as a failing assertion rather than as a
    /// PLC that silently rejects a request.
    /// </summary>
    public class V3VlqTests
    {
        private static string Hex(byte[] data) => BitConverter.ToString(data).Replace("-", string.Empty).ToLowerInvariant();

        [Theory]
        [InlineData(0u, "00")]
        [InlineData(1u, "01")]
        [InlineData(63u, "3f")]
        [InlineData(64u, "40")]
        [InlineData(127u, "7f")]
        [InlineData(128u, "8100")]
        [InlineData(255u, "817f")]
        [InlineData(256u, "8200")]
        [InlineData(16383u, "ff7f")]
        [InlineData(16384u, "818000")]
        [InlineData(0x7FFFFFFFu, "87ffffff7f")]
        [InlineData(0x80000000u, "8880808000")]
        [InlineData(0xFFFFFFFFu, "8fffffff7f")]
        [InlineData(2550u, "9376")]
        [InlineData(3736u, "9d18")]
        [InlineData(0x8A0E0001u, "88d0b88001")]
        public void EncodeUInt32MatchesReference(uint value, string expected)
        {
            Assert.Equal(expected, Hex(Vlq.EncodeUInt32(value)));
        }

        [Theory]
        [InlineData(0u)]
        [InlineData(1u)]
        [InlineData(127u)]
        [InlineData(128u)]
        [InlineData(16384u)]
        [InlineData(2550u)]
        [InlineData(0x8A0E0001u)]
        [InlineData(0xFFFFFFFFu)]
        public void UInt32RoundTrips(uint value)
        {
            var encoded = Vlq.EncodeUInt32(value);
            Assert.Equal(value, Vlq.DecodeUInt32(encoded, 0, out int consumed));
            Assert.Equal(encoded.Length, consumed);
        }

        [Theory]
        [InlineData(0, "00")]
        [InlineData(1, "01")]
        [InlineData(-1, "7f")]
        [InlineData(63, "3f")]
        [InlineData(-64, "ff40")]
        [InlineData(64, "8040")]
        [InlineData(-65, "ff3f")]
        [InlineData(127, "807f")]
        [InlineData(-128, "ff00")]
        [InlineData(1000, "8768")]
        [InlineData(-1000, "f818")]
        [InlineData(int.MaxValue, "87ffffff7f")]
        [InlineData(int.MinValue, "f880808000")]
        public void EncodeInt32MatchesReference(int value, string expected)
        {
            Assert.Equal(expected, Hex(Vlq.EncodeInt32(value)));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(-1)]
        [InlineData(1000)]
        [InlineData(-1000)]
        [InlineData(int.MaxValue)]
        [InlineData(int.MinValue)]
        public void Int32RoundTrips(int value)
        {
            var encoded = Vlq.EncodeInt32(value);
            Assert.Equal(value, Vlq.DecodeInt32(encoded, 0, out int consumed));
            Assert.Equal(encoded.Length, consumed);
        }

        [Theory]
        [InlineData(0ul, "00")]
        [InlineData(1ul, "01")]
        [InlineData(127ul, "7f")]
        [InlineData(128ul, "8100")]
        [InlineData(0xFFFFul, "83ff7f")]
        [InlineData(0x34ul, "34")]
        [InlineData(0x00FFFFFFFFFFFFFFul, "ffffffffffffff7f")]
        [InlineData(0x0100000000000000ul, "80c080808080808000")]
        [InlineData(0xFFFFFFFFFFFFFFFFul, "ffffffffffffffffff")]
        public void EncodeUInt64MatchesReference(ulong value, string expected)
        {
            Assert.Equal(expected, Hex(Vlq.EncodeUInt64(value)));
        }

        [Theory]
        [InlineData(0ul)]
        [InlineData(1ul)]
        [InlineData(0xFFFFul)]
        [InlineData(0x00FFFFFFFFFFFFFFul)]
        [InlineData(0x0100000000000000ul)]
        [InlineData(0xFFFFFFFFFFFFFFFFul)]
        public void UInt64RoundTrips(ulong value)
        {
            var encoded = Vlq.EncodeUInt64(value);
            Assert.Equal(value, Vlq.DecodeUInt64(encoded, 0, out int consumed));
            Assert.Equal(encoded.Length, consumed);
        }

        [Theory]
        [InlineData(0L, "00")]
        [InlineData(1L, "01")]
        [InlineData(-1L, "7f")]
        [InlineData(63L, "3f")]
        [InlineData(-64L, "ff40")]
        [InlineData(0x007FFFFFFFFFFFFFL, "bfffffffffffff7f")]
        [InlineData(0x0080000000000000L, "80a080808080808000")]
        [InlineData(long.MinValue, "c08080808080808000")]
        [InlineData(long.MaxValue, "bfffffffffffffffff")]
        public void EncodeInt64MatchesReference(long value, string expected)
        {
            Assert.Equal(expected, Hex(Vlq.EncodeInt64(value)));
        }

        /// <summary>
        /// The 64-bit forms carry eight 7-bit groups plus a ninth byte of eight
        /// data bits, so a value above 2^56 must not be truncated.
        /// </summary>
        [Fact]
        public void UInt64HandlesTheNinthByte()
        {
            const ulong value = 0x0123456789ABCDEFul;
            var encoded = Vlq.EncodeUInt64(value);
            Assert.Equal(value, Vlq.DecodeUInt64(encoded, 0, out _));
        }
    }

    /// <summary>The request-building and value-decoding codecs.</summary>
    public class V3CodecTests
    {
        private static string Hex(byte[] data) => BitConverter.ToString(data).Replace("-", string.Empty).ToLowerInvariant();

        private static byte[] FromHex(string hex)
        {
            var data = new byte[hex.Length / 2];
            for (int i = 0; i < data.Length; i++) data[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return data;
        }

        [Fact]
        public void ObjectQualifierV2MatchesReference()
        {
            Assert.Equal("000004e88969001200000000896a001300896b00040000",
                         Hex(S7Codec.EncodeObjectQualifier(0, ProtocolVersion.V2)));
        }

        /// <summary>A V1-initial session sends the key qualifier fixed-width, with no terminator.</summary>
        [Fact]
        public void ObjectQualifierV1MatchesReference()
        {
            Assert.Equal("000004e88969001200000000896a001300896b000400000007",
                         Hex(S7Codec.EncodeObjectQualifier(7, ProtocolVersion.V1)));
        }

        [Fact]
        public void ItemAddressForADataBlockMatchesReference()
        {
            var bytes = S7Codec.EncodeItemAddress(0x8A0E0007, Ids.DbValueActual,
                                                  new uint[] { 0xA, 0x2 }, out int fieldCount);
            Assert.Equal(6, fieldCount);
            Assert.Equal("0088d0b880070393760a02", Hex(bytes));
        }

        /// <summary>
        /// A process area uses the controller-area sub-area, not a data block's.
        /// Sending 2551 here is what made every I/Q/M access fail.
        /// </summary>
        [Fact]
        public void ItemAddressForAProcessAreaMatchesReference()
        {
            var bytes = S7Codec.EncodeItemAddress(Ids.NativeTheMAreaRid, Ids.ControllerAreaValueActual,
                                                  new uint[] { 5 }, out int fieldCount);
            Assert.Equal(5, fieldCount);
            Assert.Equal("0052029d1805", Hex(bytes));
        }

        [Theory]
        [InlineData(DataType.Real, "42aa0000", "000e42aa0000")]
        [InlineData(DataType.Bool, "01", "000101")]
        [InlineData(DataType.Int, "fff0", "0007fff0")]
        [InlineData(DataType.DInt, "fffffc18", "0008f818")]
        [InlineData(DataType.UDInt, "0000ffff", "000483ff7f")]
        [InlineData(DataType.LReal, "4005bf0a8b145769", "000f4005bf0a8b145769")]
        public void TypedPValueMatchesReference(DataType datatype, string input, string expected)
        {
            Assert.Equal(expected, Hex(S7Codec.EncodePValueTyped(datatype, FromHex(input))));
        }

        /// <summary>A fixed-width type is length-checked so a bad write fails here, not on the PLC.</summary>
        [Fact]
        public void TypedPValueRejectsAWrongLength()
        {
            Assert.Throws<S7ProtocolException>(() => S7Codec.EncodePValueTyped(DataType.Real, new byte[] { 0x01 }));
        }

        [Theory]
        [InlineData("000e42aa0000", "42aa0000", 6)]
        [InlineData("000101", "01", 3)]
        [InlineData("0007fff0", "fff0", 4)]
        [InlineData("00088768", "000003e8", 4)]
        [InlineData("00048fffffff7f", "ffffffff", 7)]
        [InlineData("000f4005bf0a8b145769", "4005bf0a8b145769", 10)]
        [InlineData("0014000461626364", "61626364", 8)]
        [InlineData("001503414243", "414243", 6)]
        [InlineData("00100000000000000064", "0000000000000064", 10)]
        [InlineData("000c12345678", "12345678", 6)]
        [InlineData("10020401020304", "01020304", 7)]
        public void DecodePValueMatchesReference(string input, string expectedValue, int expectedConsumed)
        {
            var value = S7Codec.DecodePValueToBytes(FromHex(input), 0, out int consumed);
            Assert.Equal(expectedValue, Hex(value));
            Assert.Equal(expectedConsumed, consumed);
        }

        [Theory]
        [InlineData(DataType.UDInt, 0u, "0400")]
        [InlineData(DataType.Rid, 0x80C3C901u, "1280c3c901")]
        [InlineData(DataType.USInt, 5u, "0205")]
        [InlineData(DataType.Aid, 0u, "1300")]
        public void TypedValueMatchesReference(DataType datatype, uint value, string expected)
        {
            Assert.Equal(expected, Hex(S7Codec.EncodeTypedValue(datatype, value)));
        }

        [Fact]
        public void TypedWStringMatchesReference()
        {
            Assert.Equal("150c43735337436f6d6d506c7573",
                         Hex(S7Codec.EncodeTypedValue(DataType.WString, "CsS7CommPlus")));
        }

        /// <summary>The frame header is the protocol id, the version and a 16-bit length.</summary>
        [Fact]
        public void FrameHeaderRoundTrips()
        {
            var header = S7Codec.EncodeHeader(ProtocolVersion.V2, 0x1234);
            Assert.Equal("7202 1234".Replace(" ", string.Empty), Hex(header));

            int consumed = S7Codec.DecodeHeader(header, 0, out var version, out int length);
            Assert.Equal(4, consumed);
            Assert.Equal(ProtocolVersion.V2, version);
            Assert.Equal(0x1234, length);
        }

        [Fact]
        public void FrameHeaderRejectsAForeignProtocolId()
        {
            // 0x32 is the legacy S7comm protocol, which this client does not speak.
            Assert.Throws<S7ProtocolException>(
                () => S7Codec.DecodeHeader(new byte[] { 0x32, 0x02, 0x00, 0x04 }, 0, out _, out _));
        }

        /// <summary>A request header is 14 bytes and carries the session id; a response has 10 and does not.</summary>
        [Fact]
        public void RequestHeaderMatchesTheWireLayout()
        {
            var header = S7Codec.EncodeRequestHeader((ushort)FunctionCode.GetMultiVariables, 0x0102, 0x0A0B0C0D, 0x34);
            Assert.Equal(14, header.Length);
            Assert.Equal("31 0000 054c 0000 0102 0a0b0c0d 34".Replace(" ", string.Empty), Hex(header));
        }

        /// <summary>
        /// The device identity string in the echoed session version is blanked,
        /// as TIA Portal does; a PLC rejects the echo when it is sent back verbatim.
        /// </summary>
        [Fact]
        public void PaomStringIsStrippedFromTheSessionVersion()
        {
            // [prefix][key 0x823f][flags 0x00][WSTRING 0x15][len 3]["abc"][suffix]
            var input = FromHex("0017aabbccdd" + "823f" + "0015" + "03" + "616263" + "00");
            var stripped = S7Codec.StripPaomStringInSessionVersion(input);

            Assert.Equal(FromHex("0017aabbccdd" + "823f" + "0015" + "00" + "00"), stripped);
        }

        /// <summary>A session version without the element is passed through untouched.</summary>
        [Fact]
        public void PaomStrippingLeavesOtherSessionVersionsAlone()
        {
            var input = FromHex("0017aabbccdd00");
            Assert.Equal(input, S7Codec.StripPaomStringInSessionVersion(input));
        }

        /// <summary>
        /// The usable session id is the first object id of the CreateObject body,
        /// not the header's session-id field; the second is the subscription
        /// container the PLC allocated alongside it.
        /// </summary>
        [Fact]
        public void CreateObjectBodyYieldsTheSessionAndSubscriptionIds()
        {
            // ReturnValue 0, two object ids: 0x8000_0001 and 0x8000_0002.
            var body = new List<byte> { 0x00, 0x02 };
            body.AddRange(Vlq.EncodeUInt32(0x80000001));
            body.AddRange(Vlq.EncodeUInt32(0x80000002));

            var ids = S7Codec.ParseCreateObjectSessionId(body.ToArray(), out int offset, out ulong returnValue);

            Assert.Equal(0ul, returnValue);
            Assert.Equal(new uint[] { 0x80000001, 0x80000002 }, ids);
            Assert.Equal(body.Count, offset);
        }
    }
}
