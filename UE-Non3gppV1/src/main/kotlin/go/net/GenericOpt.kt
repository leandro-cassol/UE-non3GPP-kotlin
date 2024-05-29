package go.net

import java.net.Socket
import java.util.concurrent.locks.ReentrantReadWriteLock

class GenericOpt {
    var conn: Socket? = null

    fun ok(): Boolean {
        return conn != null && conn!!.isConnected
    }
}


class DgramOpt {
    var conn: Socket? = null

    fun ok(): Boolean {
        return conn != null && conn!!.isConnected
    }
}



class RawOpt {
    private val lock = ReentrantReadWriteLock()
    private var cflags: ControlFlags = ControlFlags.NONE

    fun set(f: ControlFlags) {
        lock.writeLock().lock()
        try {
            cflags = cflags or f
        } finally {
            lock.writeLock().unlock()
        }
    }

    fun clear(f: ControlFlags) {
        lock.writeLock().lock()
        try {
            cflags = cflags and f.inv()
        } finally {
            lock.writeLock().unlock()
        }
    }

    fun isset(f: ControlFlags): Boolean {
        lock.readLock().lock()
        try {
            return cflags and f != ControlFlags.NONE
        } finally {
            lock.readLock().unlock()
        }
    }
}

enum class ControlFlags(val value: Int) {
    NONE(0),
    FLAG_TTL(1 shl 0),  // pass the TTL on the received packet
    FLAG_SRC(1 shl 1),  // pass the source address on the received packet
    FLAG_DST(1 shl 2),  // pass the destination address on the received packet
    FLAG_INTERFACE(1 shl 3);  // pass the interface index on the received packet

    infix fun or(other: ControlFlags): ControlFlags {
        return entries.find { it.value == this.value or other.value } ?: NONE
    }

    infix fun and(other: ControlFlags): ControlFlags {
        return entries.find { it.value == this.value and other.value } ?: NONE
    }

    fun inv(): ControlFlags {
        return entries.find { it.value == this.value.inv() } ?: NONE
    }
}
