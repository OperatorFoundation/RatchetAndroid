package org.operatorfoundation.ratchet

/**
 * Represents a shared key derived from ECDH in the double ratchet algorithm.
 */
data class SharedKey(val bytes: ByteArray)
{
    override fun equals(other: Any?): Boolean
    {
        if (this === other) return true
        if (other !is SharedKey) return false

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int
    {
        return bytes.contentHashCode()
    }
}
