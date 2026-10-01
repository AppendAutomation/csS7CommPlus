namespace CsS7CommPlus.Backend
{
    /// <summary>
    /// An optional capability for a backend that can drop its socket without the
    /// clean-up requests.  A graceful close talks to the PLC, so it blocks when
    /// the link is already dead or a call has hung; a driver that must stay
    /// responsive needs the hard path instead.
    /// </summary>
    public interface IV3AbortableBackend
    {
        /// <summary>Drop the socket immediately, without the clean-up requests.</summary>
        void Abort();
    }
}
