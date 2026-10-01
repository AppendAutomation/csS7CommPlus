using CsS7CommPlus.Codec;

namespace CsS7CommPlus.Tests
{
    /// <summary>
    /// Validates the value codecs against every worked example in §11/§12/§12.1
    /// of the VM106 / S7-1200 specification (mirrors the Python test_codecs).
    /// </summary>
    public class CodecTests
    {
        private static byte[] H(string hex) =>
            Convert.FromHexString(hex.Replace(" ", ""));

        [Theory]
        [InlineData(25L, "19")]
        [InlineData(1000000L, "bd8440")]
        [InlineData(-999L, "f819")]
        public void DIntVarint_Encode_MatchesSpec(long value, string hex)
        {
            Assert.Equal(H(hex), S7PlusTypes.EncodeVarintTwos(value));
        }

        [Theory]
        [InlineData("19", 25L)]
        [InlineData("bd8440", 1000000L)]
        [InlineData("f819", -999L)]
        public void DIntVarint_Decode_MatchesSpec(string hex, long value)
        {
            var bytes = H(hex);
            var v = S7PlusTypes.DecodeVarintTwos(bytes, 0, out int consumed);
            Assert.Equal(value, v);
            Assert.Equal(bytes.Length, consumed);
        }

        [Theory]
        [InlineData(10L, "000a")]
        [InlineData(-12345L, "cfc7")]
        public void Int_Encode_MatchesSpec(long value, string hex)
        {
            Assert.Equal(H(hex), S7PlusTypes.EncodeValue(S7Type.Int, value));
        }

        [Theory]
        [InlineData(15.3f, "4174cccd")]
        [InlineData(85.5f, "42ab0000")]
        [InlineData(100.0f, "42c80000")]
        public void Real_Encode_MatchesSpec(float value, string hex)
        {
            Assert.Equal(H(hex), S7PlusTypes.EncodeValue(S7Type.Real, value));
        }

        public static IEnumerable<object[]> WriteBlockCases() => new[]
        {
            new object[] { S7Type.DInt, 25L, "01 00 08 19 00 00 00" },
            new object[] { S7Type.Real, 15.3f, "01 00 0e 41 74 cc cd 00 00 00" },
            new object[] { S7Type.Bool, true, "01 00 01 01 00 00 00" },
            new object[] { S7Type.Int, 10L, "01 00 07 00 0a 00 00 00" },
            new object[] { S7Type.Int, -12345L, "01 00 07 cf c7 00 00 00" },
            new object[] { S7Type.Real, 85.5f, "01 00 0e 42 ab 00 00 00 00 00" },
            new object[] { S7Type.DInt, 1000000L, "01 00 08 bd 84 40 00 00 00" },
            new object[] { S7Type.DInt, -999L, "01 00 08 f8 19 00 00 00" },
        };

        [Theory]
        [MemberData(nameof(WriteBlockCases))]
        public void WriteBlock_MatchesSpecTable15(S7Type type, object value, string hex)
        {
            Assert.Equal(H(hex), S7PlusTypes.EncodeWriteBlock(type, value));
        }

        [Fact]
        public void Decode_RoundTrips_And_SpecValues()
        {
            Assert.Equal((short)18262, (short)S7PlusTypes.DecodeValue(S7Type.Int, H("4756"), 0, out _));
            Assert.True((float)S7PlusTypes.DecodeValue(S7Type.Real, H("4174cccd"), 0, out _) - 15.3f < 1e-3);
            Assert.Equal(-999L, S7PlusTypes.DecodeValue(S7Type.DInt, H("f819"), 0, out _));
        }
    }
}
