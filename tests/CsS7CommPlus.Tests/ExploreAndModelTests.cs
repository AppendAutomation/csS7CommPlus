using System.Text;
using CsS7CommPlus.Helpers;
using CsS7CommPlus.Models;

namespace CsS7CommPlus.Tests
{
    /// <summary>Explore name-parser (spec §9) and model tests.</summary>
    public class ExploreAndModelTests
    {
        [Fact]
        public void ParseMemberNames_FindsTargetTags()
        {
            // Build a §9.2 name block (00 <len> <ascii>) embedded in descriptor junk.
            var ms = new MemoryStream();
            ms.Write(Convert.FromHexString("a3936f00058cb6c3"));  // leading junk
            foreach (var name in new[] { "CommsHeartbeat", "mem1", "mem2",
                                         "alway off", "Always On", "Core OD Offset", "HBTimer" })
            {
                ms.WriteByte(0x00);
                ms.WriteByte((byte)name.Length);
                ms.Write(Encoding.ASCII.GetBytes(name));
                ms.Write(Convert.FromHexString("8aa3"));          // interleaved junk
            }
            var names = ExploreParser.ParseMemberNames(ms.ToArray());
            Assert.Contains("Always On", names);
            Assert.Contains("Core OD Offset", names);
            Assert.Contains("HBTimer", names);
        }

        [Fact]
        public void ParseBlockNames_FindsBlocks()
        {
            var ms = new MemoryStream();
            ms.Write(Convert.FromHexString("a38169"));
            ms.WriteByte(0x15); ms.WriteByte(8); ms.Write(Encoding.ASCII.GetBytes("HMI_Tags"));
            ms.Write(Convert.FromHexString("a3936f"));
            ms.WriteByte(0x15); ms.WriteByte(5); ms.Write(Encoding.ASCII.GetBytes("MArea"));
            var names = ExploreParser.ParseBlockNames(ms.ToArray());
            Assert.Equal(new[] { "HMI_Tags", "MArea" }, names.ToArray());
        }

        [Fact]
        public void Response_ToString_And_Status()
        {
            Assert.Equal("Success", new Response("t", 1, 0x00).Status);
            Assert.Equal("Success", new Response("t", 1, 0x34).Status);   // write-success marker
            Assert.Equal("t 42 Success", new Response("t", 42, 0x00).ToString());
            Assert.Equal("boom", new Response("t", null, "boom").Status);
        }

        [Fact]
        public void Tag_ToString_UsesParent()
        {
            Assert.Equal("MArea.HBTimer", new Tag("HBTimer", "MArea").ToString());
            Assert.Equal("HBTimer", new Tag("HBTimer").ToString());
        }
    }
}
