using System.Collections.Generic;

namespace CsS7CommPlus.Backend
{
    /// <summary>One symbol's value in a subscription notification.</summary>
    public class V3SubscriptionValue
    {
        /// <summary>The symbolic name the value belongs to.</summary>
        public string Name { get; set; } = string.Empty;
        /// <summary>The decoded value, or null when the PLC reported bad quality.</summary>
        public object? Value { get; set; }
        /// <summary>True when the PLC reported good quality for this item.</summary>
        public bool IsGood { get; set; }
    }

    /// <summary>
    /// The optional push half of the V3 seam.  A backend that implements it lets
    /// the PLC subscribe to a set of symbols and receive only the values that
    /// changed, instead of re-reading every symbol each cycle.  This is how TIA
    /// Portal and Siemens HMIs collect data, and it is far cheaper than polling
    /// for a large tag set.
    ///
    /// A backend may implement <see cref="IV3Backend"/> alone; callers check for
    /// this interface and fall back to polling when it is absent.
    /// </summary>
    public interface IV3SubscriptionBackend
    {
        /// <summary>
        /// Subscribe to the named symbols and have the PLC push changes every
        /// <paramref name="cycleMs"/>.  Returns false when the PLC refuses the
        /// subscription, in which case the caller should poll instead.
        /// </summary>
        bool Subscribe(IEnumerable<string> names, int cycleMs);

        /// <summary>
        /// Wait for the next notification and return the values it carried.  The
        /// PLC sends one each cycle, empty when nothing changed, so an empty list
        /// is a healthy result and not an error.  Returns null when nothing arrived
        /// within <paramref name="timeoutMs"/>.
        /// </summary>
        IList<V3SubscriptionValue>? WaitForChanges(int timeoutMs);

        /// <summary>Delete the subscription on the PLC.</summary>
        void Unsubscribe();

        /// <summary>Whether a subscription is currently active.</summary>
        bool Subscribed { get; }
    }
}
