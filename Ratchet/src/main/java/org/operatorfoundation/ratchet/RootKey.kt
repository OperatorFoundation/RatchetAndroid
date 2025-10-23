package org.operatorfoundation.ratchet

/**
 * Represents the root key in the double ratchet algorithm.
 * The root key is used to derive chain keys.
 */
data class RootKey(val bytes: ByteArray)
{
    override fun equals(other: Any?): Boolean
    {
        if (this === other) return true
        if (other !is RootKey) return false

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int
    {
        return bytes.contentHashCode()
    }
}
