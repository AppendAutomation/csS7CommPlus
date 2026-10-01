using System;
using System.Collections.Generic;
using CsS7CommPlus.V3.Protocol;
using CsS7CommPlus.V3.Session;
using CsS7CommPlus.V3.Symbols;
using CsS7CommPlus.V3.Values;
using Xunit;

namespace CsS7CommPlus.Tests
{
    /// <summary>
    /// The type-info parsers and the symbol-tree flattening, checked against the
    /// MIT-licensed s7commplus Python backend's output for the same bytes.
    ///
    /// These are the parsers that decide what a tag is called and which address
    /// it is read by, so a drift here would show up as tags that silently read
    /// the wrong memory rather than as an error.
    /// </summary>
    public class V3TypeInfoTests
    {
        private static byte[] FromHex(string hex)
        {
            var data = new byte[hex.Length / 2];
            for (int i = 0; i < data.Length; i++) data[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return data;
        }

        /// <summary>A scalar member with the Std offset-info variant (selector 8).</summary>
        [Fact]
        public void ScalarVartypeElementMatchesReference()
        {
            var bytes = FromHex("00140000000002000000efbeadde088000006400c8000000");

            var elements = TypeInfo.ParseVartypeList(bytes, 0, out int consumed);

            Assert.Single(elements);
            var e = elements[0];
            Assert.Equal(2u, e.Lid);
            Assert.Equal(0xDEADBEEFu, e.SymbolCrc);
            Assert.Equal((int)SoftDataType.Real, e.SoftDataType);
            Assert.Equal(8, e.OffsetInfoType);
            Assert.Equal(100u, e.OffsetInfo.OptAddr);
            Assert.Equal(200u, e.OffsetInfo.NonOptAddr);
            Assert.Equal(24, consumed);
        }

        /// <summary>
        /// A one-dimensional array uses selector 10, which carries the lower
        /// bound and the element count after the two addresses.
        /// </summary>
        [Fact]
        public void ArrayVartypeElementMatchesReference()
        {
            var bytes = FromHex("002400000000050000000000000005a00000000000000a0000001400000001000000030000000000");

            var elements = TypeInfo.ParseVartypeList(bytes, 0, out _);

            Assert.Single(elements);
            var oi = elements[0].OffsetInfo;
            Assert.True(oi.Is1Dim);
            Assert.Equal(1, oi.ArrayLowerBound);
            Assert.Equal(3u, oi.ArrayElementCount);
            Assert.Equal(10u, oi.OptAddr);
            Assert.Equal(20u, oi.NonOptAddr);
        }

        [Fact]
        public void VarnameListMatchesReference()
        {
            var bytes = FromHex("00120764726976654b700007484254696d6572000000");

            var names = TypeInfo.ParseVarnameList(bytes, 0, out int consumed);

            Assert.Equal(new[] { "driveKp", "HBTimer" }, names);
            Assert.Equal(22, consumed);
        }

        /// <summary>
        /// The flattened tag must carry both the TIA name and the hex address
        /// path, since the path is what the PLC is actually asked for.
        /// </summary>
        [Fact]
        public void FlatteningProducesTheNameAndAddressPath()
        {
            var elements = TypeInfo.ParseVartypeList(
                FromHex("00140000000002000000efbeadde088000006400c8000000"), 0, out _);

            var typeObject = new TypeInfo.PObject { RelationId = 0x90001234, ClassId = Ids.ClassTypeInfo };
            typeObject.VartypeList = elements;
            typeObject.VarnameList = new List<string> { "driveKp" };

            var root = new SymbolNode
            {
                NodeType = NodeType.Root,
                Name = "SPDL BLU Winder DB",
                AccessId = 0x8A0E0005,
                RelationId = 0x90001234,
            };

            SymbolTree.BuildTree(new List<SymbolNode> { root }, new List<TypeInfo.PObject> { typeObject });
            var flat = SymbolTree.BuildFlatList(new List<SymbolNode> { root });

            Assert.Single(flat);
            Assert.Equal("SPDL BLU Winder DB.driveKp", flat[0].Name);
            Assert.Equal("8A0E0005.2", flat[0].AccessSequence);
            Assert.Equal((int)SoftDataType.Real, flat[0].SoftDataType);
            Assert.Equal(100, flat[0].OptAddress);
            Assert.Equal(200, flat[0].NonOptAddress);
            Assert.Equal(0xDEADBEEFu, flat[0].SymbolCrc);
        }

        /// <summary>
        /// The browse result turns into the symbol a read is built from: the
        /// access area is the path's first component and the LIDs are the rest.
        /// </summary>
        [Fact]
        public void SymbolicTagResolvesTheAddressPath()
        {
            var tag = SymbolicTag.FromVarInfo(new VarInfo
            {
                Name = "SPDL BLU Winder DB.InstTPID.Kp1",
                AccessSequence = "8A0E0005.2.A",
                SoftDataType = (int)SoftDataType.Real,
            });

            Assert.Equal(0x8A0E0005u, tag.AccessArea);
            Assert.Equal(new uint[] { 2, 0xA }, tag.Lids);
            Assert.Equal(DataType.Real, tag.DataType);
            Assert.Equal(Ids.DbValueActual, tag.AccessSubArea);
        }

        /// <summary>A process-area symbol must select the controller-area sub-area.</summary>
        [Fact]
        public void ProcessAreaSymbolUsesTheControllerSubArea()
        {
            var tag = SymbolicTag.FromVarInfo(new VarInfo
            {
                Name = "HBTimer",
                AccessSequence = "52.5",
                SoftDataType = (int)SoftDataType.Bool,
            });

            Assert.Equal(Ids.NativeTheMAreaRid, tag.AccessArea);
            Assert.Equal(Ids.ControllerAreaValueActual, tag.AccessSubArea);
        }

        /// <summary>
        /// The browse roots the I/Q/M subtrees under a name it invents, because
        /// those areas have none.  TIA Portal shows those symbols as plain PLC
        /// tags, and a site tag list spells them that way, so the catalogued name
        /// must be the plain one — with the browse's own spelling still resolving.
        /// </summary>
        [Fact]
        public void CatalogStripsTheInventedProcessAreaRoot()
        {
            var tag = new SymbolicTag { Name = "Tension Raw", AccessArea = Ids.NativeTheIAreaRid };
            var catalog = new SymbolCatalog(
                new[] { tag },
                new[] { new KeyValuePair<string, SymbolicTag>("IArea.Tension Raw", tag) });

            Assert.Equal(1, catalog.Count);
            Assert.Same(tag, catalog.Resolve("Tension Raw"));
            Assert.Same(tag, catalog.Resolve("IArea.Tension Raw"));
        }

        /// <summary>A data block keeps its own name, which is already the TIA one.</summary>
        [Fact]
        public void CatalogKeepsDataBlockNames()
        {
            var catalog = new SymbolCatalog(new[]
            {
                new SymbolicTag { Name = "HMI_Tags.Core_Size", AccessArea = 0x8A0E0006 },
            });

            Assert.Equal("HMI_Tags.Core_Size", catalog.Resolve("HMI_Tags.Core_Size").Name);
        }

        /// <summary>An alternative spelling never shadows a real symbol of that name.</summary>
        [Fact]
        public void CatalogPrefersARealSymbolOverAnAlias()
        {
            var real = new SymbolicTag { Name = "Overlap" };
            var other = new SymbolicTag { Name = "MArea.Overlap" };

            var catalog = new SymbolCatalog(
                new[] { real },
                new[] { new KeyValuePair<string, SymbolicTag>("Overlap", other) });

            Assert.Same(real, catalog.Resolve("Overlap"));
        }

        [Fact]
        public void CatalogMatchesNamesCaseSensitively()
        {
            var catalog = new SymbolCatalog(new[]
            {
                new SymbolicTag { Name = "HMI_Tags.Core_Size" },
                new SymbolicTag { Name = "HBTimer" },
            });

            Assert.Equal(2, catalog.Count);
            Assert.Equal("HBTimer", catalog.Resolve("HBTimer").Name);
            Assert.False(catalog.TryResolve("hbtimer", out _));
            Assert.Throws<KeyNotFoundException>(() => catalog.Resolve("Nope"));
        }
    }

    /// <summary>Subscription notification decoding.</summary>
    public class V3SubscriptionTests
    {
        private static byte[] FromHex(string hex)
        {
            var data = new byte[hex.Length / 2];
            for (int i = 0; i < data.Length; i++) data[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return data;
        }

        private static string Hex(byte[] data) => BitConverter.ToString(data).Replace("-", string.Empty).ToLowerInvariant();

        /// <summary>
        /// One notification carrying a 4-byte-reference value, a VLQ-reference
        /// value and an error item.  The vector is the Python backend's own parse
        /// of these bytes.
        /// </summary>
        [Fact]
        public void NotificationMatchesReference()
        {
            var data = FromHex("33800000110000000000000507019200000001000e42ab00009b02000101030000000300");

            var n = SubscriptionCodec.ParseNotification(data);

            Assert.Equal(0x80000011u, n.SubscriptionId);
            Assert.Equal(5, n.CreditTick);
            Assert.Equal(7u, n.SequenceNumber);
            Assert.Equal(1, n.ChangeCounter);

            Assert.Equal(2, n.Values.Count);
            Assert.Equal("42ab0000", Hex(n.Values[1]));
            Assert.Equal("01", Hex(n.Values[2]));

            Assert.Single(n.Errors);
            Assert.Equal(0x03, n.Errors[3]);
        }

        /// <summary>
        /// An empty notification is what the PLC sends each cycle when nothing
        /// changed, so it must parse as a healthy result with no values.
        /// </summary>
        [Fact]
        public void EmptyNotificationIsNotAnError()
        {
            var data = FromHex("33800000110000000000000507" + "01" + "00");

            var n = SubscriptionCodec.ParseNotification(data);

            Assert.Equal(0x80000011u, n.SubscriptionId);
            Assert.Empty(n.Values);
            Assert.Empty(n.Errors);
        }

        [Fact]
        public void NotificationRejectsAnotherOpcode()
        {
            // 0x32 is a response, not a notification.
            Assert.Throws<S7ProtocolException>(
                () => SubscriptionCodec.ParseNotification(FromHex("32000000000000000000")));
        }

        /// <summary>
        /// A subscription addresses items by reference id, and a duplicate would
        /// make two tags indistinguishable in the notifications.
        /// </summary>
        [Fact]
        public void SubscriptionRejectsDuplicateReferenceIds()
        {
            var items = new[]
            {
                new SubscriptionItem(0x8A0E0005, new uint[] { 2 }, null, 0, 1),
                new SubscriptionItem(0x8A0E0005, new uint[] { 3 }, null, 0, 1),
            };

            Assert.Throws<ArgumentException>(
                () => SubscriptionCodec.BuildSubscriptionRequest(0x80000002, items, out _));
        }

        /// <summary>
        /// A CreateObject carries its IntegrityId between the request set and the
        /// object tree, so the builder reports that tail rather than the usual 4.
        /// </summary>
        [Fact]
        public void SubscriptionRequestReportsItsIntegrityTail()
        {
            var items = new[] { new SubscriptionItem(0x8A0E0005, new uint[] { 2 }) };

            var payload = SubscriptionCodec.BuildSubscriptionRequest(0x80000002, items, out int integrityTail);

            // The request set is a 4-byte container id, a 3-byte UDInt PValue and
            // 4 bytes of padding; everything after it is the object tree.
            Assert.Equal(payload.Length - 11, integrityTail);
            Assert.True(integrityTail > 0);
        }
    }

    /// <summary>Value decoding from the PLC's big-endian bytes.</summary>
    public class V3ValueDecoderTests
    {
        [Fact]
        public void DecodesRealAndLReal()
        {
            Assert.Equal(85.5f, (float)S7ValueDecoder.Decode(SoftDataType.Real, new byte[] { 0x42, 0xAB, 0x00, 0x00 })!);
            Assert.Equal(2.718281828459045d,
                         (double)S7ValueDecoder.Decode(SoftDataType.LReal,
                             new byte[] { 0x40, 0x05, 0xBF, 0x0A, 0x8B, 0x14, 0x57, 0x69 })!, 12);
        }

        [Fact]
        public void DecodesSignedAndUnsignedIntegers()
        {
            Assert.Equal((short)-16, S7ValueDecoder.Decode(SoftDataType.Int, new byte[] { 0xFF, 0xF0 }));
            Assert.Equal((ushort)65520, S7ValueDecoder.Decode(SoftDataType.UInt, new byte[] { 0xFF, 0xF0 }));
            Assert.Equal(-1000, S7ValueDecoder.Decode(SoftDataType.DInt, new byte[] { 0xFF, 0xFF, 0xFC, 0x18 }));
            Assert.Equal(4294966296u, S7ValueDecoder.Decode(SoftDataType.UDInt, new byte[] { 0xFF, 0xFF, 0xFC, 0x18 }));
            Assert.Equal((sbyte)-2, S7ValueDecoder.Decode(SoftDataType.SInt, new byte[] { 0xFE }));
        }

        [Fact]
        public void DecodesBool()
        {
            Assert.Equal(true, S7ValueDecoder.Decode(SoftDataType.Bool, new byte[] { 0x01 }));
            Assert.Equal(false, S7ValueDecoder.Decode(SoftDataType.Bool, new byte[] { 0x00 }));
        }

        /// <summary>TIME is a signed millisecond span, so a negative value must stay negative.</summary>
        [Fact]
        public void DecodesTimeAsASignedSpan()
        {
            Assert.Equal(TimeSpan.FromMilliseconds(1500),
                         S7ValueDecoder.Decode(SoftDataType.Time, new byte[] { 0x00, 0x00, 0x05, 0xDC }));
            Assert.Equal(TimeSpan.FromMilliseconds(-1000),
                         S7ValueDecoder.Decode(SoftDataType.Time, new byte[] { 0xFF, 0xFF, 0xFC, 0x18 }));
        }

        /// <summary>DATE counts whole days from 1990-01-01.</summary>
        [Fact]
        public void DecodesDate()
        {
            Assert.Equal(new DateTime(1990, 1, 1), S7ValueDecoder.Decode(SoftDataType.Date, new byte[] { 0x00, 0x00 }));
            Assert.Equal(new DateTime(1990, 1, 11), S7ValueDecoder.Decode(SoftDataType.Date, new byte[] { 0x00, 0x0A }));
        }

        /// <summary>A DTL is a calendar structure rather than a tick count.</summary>
        [Fact]
        public void DecodesDtl()
        {
            var raw = new byte[] { 0x07, 0xEA, 0x0A, 0x01, 0x03, 0x0E, 0x1E, 0x2D, 0x00, 0x00, 0x00, 0x00 };
            Assert.Equal(new DateTime(2026, 10, 1, 14, 30, 45), S7ValueDecoder.Decode(SoftDataType.Dtl, raw));
        }

        /// <summary>A classic STRING carries its maximum and actual length ahead of the text.</summary>
        [Fact]
        public void DecodesS7String()
        {
            var raw = new byte[] { 0x10, 0x05, (byte)'H', (byte)'e', (byte)'l', (byte)'l', (byte)'o', 0x00, 0x00 };
            Assert.Equal("Hello", S7ValueDecoder.Decode(SoftDataType.String, raw));
        }

        /// <summary>
        /// Formatting is what reaches a historian, so booleans become 1 and 0 and
        /// numbers use the invariant culture rather than the host's decimal comma.
        /// </summary>
        [Theory]
        [InlineData(true, "1")]
        [InlineData(false, "0")]
        [InlineData(7.5f, "7.5")]
        [InlineData(-16, "-16")]
        public void FormatsValuesForAHistorian(object value, string expected)
        {
            Assert.Equal(expected, S7ValueDecoder.Format(value));
        }

        [Fact]
        public void FormatsTimeSpansAsMilliseconds()
        {
            Assert.Equal("1500", S7ValueDecoder.Format(TimeSpan.FromMilliseconds(1500)));
        }

        [Fact]
        public void FormatsDateTimesWithMilliseconds()
        {
            Assert.Equal("2026-10-01 14:30:45.123",
                         S7ValueDecoder.Format(new DateTime(2026, 10, 1, 14, 30, 45, 123)));
        }

        [Fact]
        public void FormatsNullAsNull()
        {
            Assert.Null(S7ValueDecoder.Format(null));
        }

        /// <summary>Encoding and decoding a value must round-trip for every scalar type.</summary>
        [Theory]
        [InlineData(SoftDataType.Bool, true)]
        [InlineData(SoftDataType.USInt, (byte)200)]
        [InlineData(SoftDataType.SInt, (sbyte)-100)]
        [InlineData(SoftDataType.Int, (short)-12345)]
        [InlineData(SoftDataType.UInt, (ushort)54321)]
        [InlineData(SoftDataType.DInt, -1234567)]
        [InlineData(SoftDataType.UDInt, 4000000000u)]
        [InlineData(SoftDataType.Real, 85.5f)]
        [InlineData(SoftDataType.LReal, 1234.5678d)]
        public void EncodeDecodeRoundTrips(SoftDataType type, object value)
        {
            var raw = S7ValueDecoder.Encode(type, value);
            Assert.Equal(value, S7ValueDecoder.Decode(type, raw));
        }

        /// <summary>
        /// A write arrives from configuration as text, so "1" and "true" must both
        /// reach the PLC as a set bit.
        /// </summary>
        [Theory]
        [InlineData("1")]
        [InlineData("true")]
        [InlineData("True")]
        public void EncodesBooleanTextForAWrite(string value)
        {
            Assert.Equal(new byte[] { 0x01 }, S7ValueDecoder.Encode(SoftDataType.Bool, value));
        }

        [Theory]
        [InlineData("0")]
        [InlineData("false")]
        public void EncodesFalseBooleanText(string value)
        {
            Assert.Equal(new byte[] { 0x00 }, S7ValueDecoder.Encode(SoftDataType.Bool, value));
        }
    }
}
