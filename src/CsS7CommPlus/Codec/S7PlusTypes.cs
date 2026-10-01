using System;
using System.Collections.Generic;

namespace CsS7CommPlus.Codec
{
    /// <summary>
    /// S7comm-plus data-type ids (spec §12).
    /// </summary>
    public enum S7Type : byte
    {
        /// <summary>Boolean.</summary>
        Bool = 0x01,
        /// <summary>Unsigned 8-bit.</summary>
        USInt = 0x02,
        /// <summary>Unsigned 16-bit.</summary>
        UInt = 0x03,
        /// <summary>Unsigned 32-bit.</summary>
        UDInt = 0x04,
        /// <summary>Signed 8-bit.</summary>
        SInt = 0x06,
        /// <summary>Signed 16-bit.</summary>
        Int = 0x07,
        /// <summary>Signed 32-bit (base-128 varint on the wire).</summary>
        DInt = 0x08,
        /// <summary>16-bit word.</summary>
        Word = 0x0B,
        /// <summary>32-bit double word.</summary>
        DWord = 0x0C,
        /// <summary>IEEE-754 single-precision float.</summary>
        Real = 0x0E,
        /// <summary>IEEE-754 double-precision float.</summary>
        LReal = 0x0F,
    }

    /// <summary>Raised when a value cannot be encoded/decoded for a given type.</summary>
    public class S7PlusTypeException : Exception
    {
        /// <summary>Creates the exception with a message.</summary>
        public S7PlusTypeException(string message) : base(message) { }
    }

    /// <summary>
    /// S7comm-plus value codecs — the on-wire encoding/decoding of §12.1 of the
    /// VM106 / S7-1200 specification.  Direct port of the Python module
    /// s7p_types.py; every rule is validated against the spec's worked examples
    /// (see the CodecTests).
    /// </summary>
    public static class S7PlusTypes
    {
        /// <summary>Friendly names for the type ids (mirrors the Python TYPE_NAMES).</summary>
        public static readonly Dictionary<S7Type, string> TypeNames = new Dictionary<S7Type, string>
        {
            { S7Type.Bool, "Bool" }, { S7Type.USInt, "USInt" }, { S7Type.UInt, "UInt" },
            { S7Type.UDInt, "UDInt" }, { S7Type.SInt, "SInt" }, { S7Type.Int, "Int" },
            { S7Type.DInt, "DInt" }, { S7Type.Word, "Word" }, { S7Type.DWord, "DWord" },
            { S7Type.Real, "Real" }, { S7Type.LReal, "LReal" },
        };

        private static readonly Dictionary<string, S7Type> NameToType = BuildNameToType();

        private static Dictionary<string, S7Type> BuildNameToType()
        {
            var d = new Dictionary<string, S7Type>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in TypeNames) d[kv.Value] = kv.Key;
            d["Float"] = S7Type.Real;
            return d;
        }

        /// <summary>Resolve a friendly type name (case-insensitive) to its id.</summary>
        public static S7Type ResolveType(string datatype)
        {
            if (datatype != null && NameToType.TryGetValue(datatype, out var t)) return t;
            throw new S7PlusTypeException("unknown datatype " + datatype);
        }

        // --- base-128 (VLQ) two's-complement integer, used by DInt ---------
        // Spec §12.1: each byte holds 7 value bits, most-significant group
        // first; the high bit (0x80) means "more bytes follow"; the value is
        // two's-complement, sign-extended to a whole number of 7-bit groups.

        /// <summary>Encode a signed integer as the spec's big-endian base-128 varint.</summary>
        public static byte[] EncodeVarintTwos(long value)
        {
            int n = 1;
            while (!(-(1L << (7 * n - 1)) <= value && value < (1L << (7 * n - 1))))
                n++;
            ulong mask = (n * 7 >= 64) ? ulong.MaxValue : ((1UL << (7 * n)) - 1);
            ulong u = unchecked((ulong)value) & mask;
            var outBytes = new byte[n];
            for (int i = 0; i < n; i++)
            {
                int shift = 7 * (n - 1 - i);
                byte g = (byte)((u >> shift) & 0x7F);
                outBytes[i] = (i < n - 1) ? (byte)(g | 0x80) : g;
            }
            return outBytes;
        }

        /// <summary>Decode a base-128 varint. Returns the value and sets bytesConsumed.</summary>
        public static long DecodeVarintTwos(byte[] data, int offset, out int bytesConsumed)
        {
            int n = 0;
            long acc = 0;
            while (true)
            {
                if (offset + n >= data.Length)
                    throw new S7PlusTypeException("truncated varint");
                byte b = data[offset + n];
                acc = (acc << 7) | (long)(b & 0x7F);
                n++;
                if ((b & 0x80) == 0) break;
            }
            int bits = 7 * n;
            if (bits < 64 && (acc & (1L << (bits - 1))) != 0)
                acc -= (1L << bits);
            bytesConsumed = n;
            return acc;
        }

        // --- big-endian fixed-width helpers --------------------------------
        private static byte[] BeBytes(ulong v, int width)
        {
            var b = new byte[width];
            for (int i = 0; i < width; i++)
                b[width - 1 - i] = (byte)((v >> (8 * i)) & 0xFF);
            return b;
        }

        private static ulong BeUlong(byte[] data, int offset, int width)
        {
            ulong v = 0;
            for (int i = 0; i < width; i++)
                v = (v << 8) | data[offset + i];
            return v;
        }

        /// <summary>
        /// Encode just the value bytes for a given S7comm-plus type id.
        /// Accepts bool, integer or floating-point values as appropriate.
        /// </summary>
        public static byte[] EncodeValue(S7Type type, object value)
        {
            switch (type)
            {
                case S7Type.Bool:
                    return new byte[] { ToBool(value) ? (byte)0x01 : (byte)0x00 };
                case S7Type.Int:
                {
                    long v = ToLong(value);
                    if (v < -32768 || v > 32767) throw new S7PlusTypeException("Int out of range: " + v);
                    return BeBytes(unchecked((ulong)v) & 0xFFFF, 2);
                }
                case S7Type.UInt:
                case S7Type.Word:
                    return BeBytes((ulong)(ToLong(value) & 0xFFFF), 2);
                case S7Type.SInt:
                    return new byte[] { (byte)(sbyte)ToLong(value) };
                case S7Type.USInt:
                    return new byte[] { (byte)(ToLong(value) & 0xFF) };
                case S7Type.UDInt:
                case S7Type.DWord:
                    return BeBytes((ulong)(ToLong(value) & 0xFFFFFFFF), 4);
                case S7Type.Real:
                {
                    var raw = BitConverter.GetBytes((float)ToDouble(value));
                    if (BitConverter.IsLittleEndian) Array.Reverse(raw);
                    return raw;
                }
                case S7Type.LReal:
                {
                    var raw = BitConverter.GetBytes(ToDouble(value));
                    if (BitConverter.IsLittleEndian) Array.Reverse(raw);
                    return raw;
                }
                case S7Type.DInt:
                    return EncodeVarintTwos(ToLong(value));
                default:
                    throw new S7PlusTypeException(string.Format("no encoder for type 0x{0:x2}", (byte)type));
            }
        }

        /// <summary>
        /// Build the full write value block exactly as seen on the wire (spec §12):
        /// flag(0x01) reserved(0x00) type(1) &lt;value bytes&gt; 00 00 00.
        /// </summary>
        public static byte[] EncodeWriteBlock(S7Type type, object value)
        {
            var val = EncodeValue(type, value);
            var outBytes = new byte[3 + val.Length + 3];
            outBytes[0] = 0x01;
            outBytes[1] = 0x00;
            outBytes[2] = (byte)type;
            Array.Copy(val, 0, outBytes, 3, val.Length);
            // trailing 00 00 00 already zero-initialised
            return outBytes;
        }

        /// <summary>
        /// Decode a value of the given type from data[offset..], returning the
        /// native value and setting bytesConsumed.
        /// </summary>
        public static object DecodeValue(S7Type type, byte[] data, int offset, out int bytesConsumed)
        {
            switch (type)
            {
                case S7Type.Bool: bytesConsumed = 1; return data[offset] != 0;
                case S7Type.Int: bytesConsumed = 2; return (short)BeUlong(data, offset, 2);
                case S7Type.UInt:
                case S7Type.Word: bytesConsumed = 2; return (ushort)BeUlong(data, offset, 2);
                case S7Type.SInt: bytesConsumed = 1; return (sbyte)data[offset];
                case S7Type.USInt: bytesConsumed = 1; return data[offset];
                case S7Type.UDInt:
                case S7Type.DWord: bytesConsumed = 4; return (uint)BeUlong(data, offset, 4);
                case S7Type.Real:
                {
                    bytesConsumed = 4;
                    var raw = new byte[4];
                    Array.Copy(data, offset, raw, 0, 4);
                    if (BitConverter.IsLittleEndian) Array.Reverse(raw);
                    return BitConverter.ToSingle(raw, 0);
                }
                case S7Type.LReal:
                {
                    bytesConsumed = 8;
                    var raw = new byte[8];
                    Array.Copy(data, offset, raw, 0, 8);
                    if (BitConverter.IsLittleEndian) Array.Reverse(raw);
                    return BitConverter.ToDouble(raw, 0);
                }
                case S7Type.DInt:
                    return DecodeVarintTwos(data, offset, out bytesConsumed);
                default:
                    throw new S7PlusTypeException(string.Format("no decoder for type 0x{0:x2}", (byte)type));
            }
        }

        private static bool ToBool(object v)
        {
            if (v is bool b) return b;
            if (v is string s) return s.Equals("true", StringComparison.OrdinalIgnoreCase) || s == "1";
            return ToLong(v) != 0;
        }

        private static long ToLong(object v)
        {
            if (v is bool b) return b ? 1 : 0;
            return Convert.ToInt64(v, System.Globalization.CultureInfo.InvariantCulture);
        }

        private static double ToDouble(object v)
        {
            return Convert.ToDouble(v, System.Globalization.CultureInfo.InvariantCulture);
        }
    }
}
