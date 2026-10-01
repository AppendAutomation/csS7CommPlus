using System;
using System.Collections.Generic;
using System.Text;
using CsS7CommPlus.V3.Protocol;

namespace CsS7CommPlus.V3.Values
{
    /// <summary>
    /// Converts between a PLC symbol's raw big-endian value bytes and .NET
    /// values, using the symbol's software datatype.
    ///
    /// The PLC sends every value big-endian, so each conversion reverses the
    /// bytes on a little-endian host.  Time types decode to their natural .NET
    /// counterparts: TIME and LTIME to <see cref="TimeSpan"/>, DATE, DTL and
    /// DATE_AND_TIME to <see cref="DateTime"/>.
    /// </summary>
    public static class S7ValueDecoder
    {
        /// <summary>The S7 epoch for DATE and the long date/time types.</summary>
        private static readonly DateTime S7Epoch = new DateTime(1990, 1, 1, 0, 0, 0, DateTimeKind.Unspecified);
        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Unspecified);

        /// <summary>
        /// Decode raw value bytes to a .NET value.  Returns the raw bytes when the
        /// datatype has no natural .NET counterpart.
        /// </summary>
        public static object? Decode(SoftDataType type, byte[] raw)
        {
            if (raw == null) return null;

            switch (type)
            {
                case SoftDataType.Bool:
                case SoftDataType.BBool:
                    return raw.Length > 0 && raw[0] != 0;

                case SoftDataType.Byte:
                case SoftDataType.USInt:
                    return raw.Length > 0 ? raw[0] : (byte)0;

                case SoftDataType.SInt:
                    return raw.Length > 0 ? unchecked((sbyte)raw[0]) : (sbyte)0;

                case SoftDataType.Char:
                    return raw.Length > 0 ? (char)raw[0] : '\0';

                case SoftDataType.Word:
                case SoftDataType.S5Time:
                    return ReadUInt16(raw);

                case SoftDataType.UInt:
                    return ReadUInt16(raw);

                case SoftDataType.WChar:
                    return (char)ReadUInt16(raw);

                case SoftDataType.Int:
                    return unchecked((short)ReadUInt16(raw));

                case SoftDataType.DWord:
                case SoftDataType.UDInt:
                    return ReadUInt32(raw);

                case SoftDataType.DInt:
                    return unchecked((int)ReadUInt32(raw));

                case SoftDataType.Real:
                    return BitConverter.ToSingle(ToHostOrder(raw, 4), 0);

                case SoftDataType.LReal:
                    return BitConverter.ToDouble(ToHostOrder(raw, 8), 0);

                case SoftDataType.LWord:
                case SoftDataType.ULInt:
                    return ReadUInt64(raw);

                case SoftDataType.LInt:
                    return unchecked((long)ReadUInt64(raw));

                // TIME is a signed 32-bit millisecond span; LTIME a signed 64-bit
                // nanosecond span.
                case SoftDataType.Time:
                    return TimeSpan.FromMilliseconds(unchecked((int)ReadUInt32(raw)));
                case SoftDataType.LTime:
                    return TimeSpan.FromTicks(unchecked((long)ReadUInt64(raw)) / 100);

                // TIME_OF_DAY counts milliseconds since midnight; LTOD nanoseconds.
                case SoftDataType.TimeOfDay:
                    return TimeSpan.FromMilliseconds(ReadUInt32(raw));
                case SoftDataType.LTod:
                    return TimeSpan.FromTicks((long)(ReadUInt64(raw) / 100));

                // DATE counts days since 1990-01-01.
                case SoftDataType.Date:
                    return S7Epoch.AddDays(ReadUInt16(raw));

                // DATE_AND_TIME and LDT arrive as nanoseconds since the Unix epoch.
                case SoftDataType.DateAndTime:
                case SoftDataType.Ldt:
                    return UnixEpoch.AddTicks((long)(ReadUInt64(raw) / 100));

                case SoftDataType.Dtl:
                    return DecodeDtl(raw);

                case SoftDataType.String:
                    return DecodeS7String(raw);

                case SoftDataType.WString:
                    return DecodeWString(raw);

                default:
                    return raw;
            }
        }

        /// <summary>
        /// Format a decoded value the way FLYNN and other string-based historians
        /// expect: booleans as 1 or 0, numbers in the invariant culture, time
        /// spans as whole milliseconds, and date/times as "yyyy-MM-dd HH:mm:ss.fff".
        /// </summary>
        public static string? Format(object? value)
        {
            switch (value)
            {
                case null:
                    return null;
                case bool b:
                    return b ? "1" : "0";
                case float f:
                    return f.ToString("R", System.Globalization.CultureInfo.InvariantCulture);
                case double d:
                    return d.ToString("R", System.Globalization.CultureInfo.InvariantCulture);
                case TimeSpan ts:
                    return ((long)ts.TotalMilliseconds).ToString(System.Globalization.CultureInfo.InvariantCulture);
                case DateTime dt:
                    return dt.ToString("yyyy-MM-dd HH:mm:ss.fff", System.Globalization.CultureInfo.InvariantCulture);
                case char c:
                    return c.ToString();
                case byte[] raw:
                    return BitConverter.ToString(raw).Replace("-", string.Empty);
                case IFormattable formattable:
                    return formattable.ToString(null, System.Globalization.CultureInfo.InvariantCulture);
                default:
                    return value.ToString();
            }
        }

        /// <summary>
        /// Encode a .NET value into the raw big-endian bytes a write expects for
        /// the given software datatype.
        /// </summary>
        public static byte[] Encode(SoftDataType type, object value)
        {
            switch (type)
            {
                case SoftDataType.Bool:
                case SoftDataType.BBool:
                    return new[] { ToBoolean(value) ? (byte)1 : (byte)0 };

                case SoftDataType.Byte:
                case SoftDataType.USInt:
                    return new[] { Convert.ToByte(value, System.Globalization.CultureInfo.InvariantCulture) };

                case SoftDataType.SInt:
                    return new[] { unchecked((byte)Convert.ToSByte(value, System.Globalization.CultureInfo.InvariantCulture)) };

                case SoftDataType.Char:
                    return new[] { (byte)Convert.ToChar(value, System.Globalization.CultureInfo.InvariantCulture) };

                case SoftDataType.Word:
                case SoftDataType.UInt:
                case SoftDataType.S5Time:
                    return FromUInt16(Convert.ToUInt16(value, System.Globalization.CultureInfo.InvariantCulture));

                case SoftDataType.WChar:
                    return FromUInt16(Convert.ToChar(value, System.Globalization.CultureInfo.InvariantCulture));

                case SoftDataType.Int:
                    return FromUInt16(unchecked((ushort)Convert.ToInt16(value, System.Globalization.CultureInfo.InvariantCulture)));

                case SoftDataType.DWord:
                case SoftDataType.UDInt:
                    return FromUInt32(Convert.ToUInt32(value, System.Globalization.CultureInfo.InvariantCulture));

                case SoftDataType.DInt:
                    return FromUInt32(unchecked((uint)Convert.ToInt32(value, System.Globalization.CultureInfo.InvariantCulture)));

                case SoftDataType.Real:
                    return ToNetworkOrder(BitConverter.GetBytes(Convert.ToSingle(value, System.Globalization.CultureInfo.InvariantCulture)));

                case SoftDataType.LReal:
                    return ToNetworkOrder(BitConverter.GetBytes(Convert.ToDouble(value, System.Globalization.CultureInfo.InvariantCulture)));

                case SoftDataType.LWord:
                case SoftDataType.ULInt:
                    return FromUInt64(Convert.ToUInt64(value, System.Globalization.CultureInfo.InvariantCulture));

                case SoftDataType.LInt:
                    return FromUInt64(unchecked((ulong)Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture)));

                case SoftDataType.Time:
                    return FromUInt32(unchecked((uint)(int)ToMilliseconds(value)));

                case SoftDataType.TimeOfDay:
                    return FromUInt32((uint)ToMilliseconds(value));

                case SoftDataType.LTime:
                case SoftDataType.LTod:
                    return FromUInt64(unchecked((ulong)(ToMilliseconds(value) * 1_000_000L)));

                default:
                    if (value is byte[] raw) return raw;
                    throw new S7ProtocolException($"No wire encoding for the datatype {type}");
            }
        }

        private static bool ToBoolean(object value)
        {
            if (value is bool b) return b;
            if (value is string s)
            {
                if (bool.TryParse(s, out bool parsed)) return parsed;
                if (double.TryParse(s, System.Globalization.NumberStyles.Any,
                                    System.Globalization.CultureInfo.InvariantCulture, out double num))
                    return num != 0;
                throw new S7ProtocolException($"Cannot read '{s}' as a boolean");
            }
            return Convert.ToBoolean(value, System.Globalization.CultureInfo.InvariantCulture);
        }

        private static long ToMilliseconds(object value)
        {
            if (value is TimeSpan ts) return (long)ts.TotalMilliseconds;
            return Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Decode a DTL: a 12-byte structure of year, month, day, weekday, hour,
        /// minute, second and a 32-bit nanosecond field.
        /// </summary>
        private static object DecodeDtl(byte[] raw)
        {
            if (raw.Length < 12) return raw;
            int year = (raw[0] << 8) | raw[1];
            int month = raw[2];
            int day = raw[3];
            int hour = raw[5];
            int minute = raw[6];
            int second = raw[7];
            uint nanoseconds = ((uint)raw[8] << 24) | ((uint)raw[9] << 16) | ((uint)raw[10] << 8) | raw[11];

            if (year < 1 || year > 9999 || month < 1 || month > 12 || day < 1 || day > 31 ||
                hour > 23 || minute > 59 || second > 59)
                return raw;

            return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Unspecified)
                .AddTicks(nanoseconds / 100);
        }

        /// <summary>
        /// Decode a classic S7 STRING: a maximum-length byte, an actual-length
        /// byte, then that many single-byte characters.
        /// </summary>
        private static string DecodeS7String(byte[] raw)
        {
            if (raw.Length < 2) return string.Empty;
            int actual = raw[1];
            if (actual > raw.Length - 2) actual = raw.Length - 2;
            return Encoding.GetEncoding("ISO-8859-1").GetString(raw, 2, actual);
        }

        /// <summary>
        /// Decode a WSTRING: a maximum-length and an actual-length 16-bit field,
        /// then that many UTF-16BE characters.  Values that arrive already
        /// unwrapped are returned as plain UTF-8 text.
        /// </summary>
        private static string DecodeWString(byte[] raw)
        {
            if (raw.Length >= 4)
            {
                int actual = (raw[2] << 8) | raw[3];
                int available = (raw.Length - 4) / 2;
                if (actual <= available)
                    return Encoding.BigEndianUnicode.GetString(raw, 4, actual * 2);
            }
            return Encoding.UTF8.GetString(raw).TrimEnd('\0');
        }

        private static ushort ReadUInt16(byte[] raw)
        {
            if (raw.Length < 2) return raw.Length == 1 ? raw[0] : (ushort)0;
            return (ushort)((raw[0] << 8) | raw[1]);
        }

        private static uint ReadUInt32(byte[] raw)
        {
            uint v = 0;
            int take = Math.Min(4, raw.Length);
            for (int i = 0; i < take; i++) v = (v << 8) | raw[i];
            return v;
        }

        private static ulong ReadUInt64(byte[] raw)
        {
            ulong v = 0;
            int take = Math.Min(8, raw.Length);
            for (int i = 0; i < take; i++) v = (v << 8) | raw[i];
            return v;
        }

        private static byte[] ToHostOrder(byte[] raw, int size)
        {
            var b = new byte[size];
            int take = Math.Min(size, raw.Length);
            Array.Copy(raw, 0, b, size - take, take);
            if (BitConverter.IsLittleEndian) Array.Reverse(b);
            return b;
        }

        private static byte[] ToNetworkOrder(byte[] b)
        {
            if (BitConverter.IsLittleEndian) Array.Reverse(b);
            return b;
        }

        private static byte[] FromUInt16(ushort v) => new[] { (byte)(v >> 8), (byte)v };

        private static byte[] FromUInt32(uint v) =>
            new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v };

        private static byte[] FromUInt64(ulong v)
        {
            var b = new byte[8];
            for (int i = 0; i < 8; i++) b[i] = (byte)(v >> ((7 - i) * 8));
            return b;
        }
    }
}
