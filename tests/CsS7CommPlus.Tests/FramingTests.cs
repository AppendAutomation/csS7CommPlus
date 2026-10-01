using CsS7CommPlus;
using CsS7CommPlus.Codec;
using CsS7CommPlus.Constants;

namespace CsS7CommPlus.Tests
{
    /// <summary>
    /// S7comm-plus envelope round-trip and PDU-builder tests (spec §6, §11, §12),
    /// mirroring the Python test_framing.
    /// </summary>
    public class FramingTests
    {
        private static byte[] H(string hex) => Convert.FromHexString(hex.Replace(" ", ""));

        [Theory]
        [InlineData(S7PlusConstants.Version1)]
        [InlineData(S7PlusConstants.Version3)]
        public void Envelope_RoundTrips(byte version)
        {
            var conn = new Connection(new PLC());   // NullIntegrityProvider by default
            var payload = H("deadbeef");
            var pdu = conn.BuildPdu(version, S7PlusConstants.OpRequest,
                                    S7PlusConstants.FuncGetMultiVar, 0x2d, payload);

            Assert.Equal(S7PlusConstants.S7pProtocolId, pdu[0]);           // header id
            Assert.Equal(S7PlusConstants.S7pProtocolId, pdu[pdu.Length - 4]); // trailer id

            var p = Connection.ParsePdu(pdu);
            Assert.Equal(version, p.Version);
            Assert.Equal(S7PlusConstants.OpRequest, p.Opcode);
            Assert.Equal(S7PlusConstants.FuncGetMultiVar, p.Function);
            Assert.Equal((ushort?)0x2d, p.Seq);
            Assert.Equal(payload, p.Body);

            if (version == S7PlusConstants.Version3)
            {
                Assert.NotNull(p.Digest);
                Assert.Equal(32, p.Digest!.Length);
            }
        }

        [Fact]
        public void WriteRequest_EndsWith_DriveKpValueBlock()
        {
            // driveKp Real 85.5, LID 0x10 -> value block 01 00 0e 42 ab 00 00 00 00 00
            var body = PLC.BuildWriteRequest(0xf8d0b880, 0x10, S7Type.Real, 85.5f);
            var tail = H("01000e42ab0000000000");
            var got = new byte[tail.Length];
            Array.Copy(body, body.Length - tail.Length, got, 0, tail.Length);
            Assert.Equal(tail, got);
        }

        [Fact]
        public void HeartbeatResponseValue_Decodes()
        {
            // spec §11.1 single-read value word 0x4756 = 18262
            Assert.Equal((short)18262, (short)S7PlusTypes.DecodeValue(S7Type.Int, H("4756"), 0, out _));
        }
    }
}
