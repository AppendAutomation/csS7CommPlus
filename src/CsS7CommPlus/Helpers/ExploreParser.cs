using System.Collections.Generic;
using System.Text;

namespace CsS7CommPlus.Helpers
{
    /// <summary>
    /// Explore name-block parsers (spec §9).  Direct port of the Python
    /// s7p_tag.py parse functions.  Symbol names appear on the wire only during
    /// the Explore (browse) phase, in two framings:
    /// member names as <c>00 &lt;len&gt; &lt;ASCII&gt;</c> (§9.2) and the
    /// data-block directory as <c>0x15 &lt;len&gt; &lt;ASCII&gt;</c> (§9.1).
    /// </summary>
    public static class ExploreParser
    {
        private static bool LooksAscii(byte[] data, int start, int len)
        {
            for (int i = start; i < start + len; i++)
                if (data[i] < 0x20 || data[i] >= 0x7f) return false;
            return true;
        }

        private static List<string> ScanFramed(byte[] data, byte marker)
        {
            var names = new List<string>();
            int i = 0, n = data.Length;
            while (i + 2 <= n)
            {
                if (data[i] == marker)
                {
                    int ln = data[i + 1];
                    if (ln >= 1 && ln <= 64 && i + 2 + ln <= n && LooksAscii(data, i + 2, ln))
                    {
                        names.Add(Encoding.ASCII.GetString(data, i + 2, ln));
                        i += 2 + ln;
                        continue;
                    }
                }
                i++;
            }
            return names;
        }

        /// <summary>Parse the <c>00 &lt;len&gt; &lt;ASCII&gt;</c> member-name framing (spec §9.2).</summary>
        public static List<string> ParseMemberNames(byte[] data) => ScanFramed(data, 0x00);

        /// <summary>Parse the data-block directory names <c>0x15 &lt;len&gt; &lt;ASCII&gt;</c> (spec §9.1).</summary>
        public static List<string> ParseBlockNames(byte[] data) => ScanFramed(data, 0x15);

        /// <summary>
        /// Scan <c>&lt;marker&gt; &lt;len&gt; &lt;ASCII*len&gt;</c> runs for identity
        /// strings (spec §7/§9.1); marker 0x15 and minimum length 2 match the
        /// Python _scan_strings default.
        /// </summary>
        public static List<string> ScanStrings(byte[] data, byte marker = 0x15, int minLen = 2, int maxLen = 64)
        {
            var names = new List<string>();
            int i = 0, n = data.Length;
            while (i + 2 <= n)
            {
                if (data[i] == marker)
                {
                    int ln = data[i + 1];
                    if (ln >= minLen && ln <= maxLen && i + 2 + ln <= n && LooksAscii(data, i + 2, ln))
                    {
                        names.Add(Encoding.ASCII.GetString(data, i + 2, ln));
                        i += 2 + ln;
                        continue;
                    }
                }
                i++;
            }
            return names;
        }
    }
}
