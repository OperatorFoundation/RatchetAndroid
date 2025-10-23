package org.operatorfoundation.ratchet

/**
 * Represents the chain key in the double ratchet algorithm.
 * The chain key is used to derive message keys.
 */
data class ChainKey(val bytes: ByteArray)
{
    override fun equals(other: Any?): Boolean
    {
        if (this === other) return true
        if (other !is ChainKey) return false

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int
    {
        return bytes.contentHashCode()
    }
}
