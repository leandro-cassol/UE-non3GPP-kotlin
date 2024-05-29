package free5gc.util.idgenerator

import java.util.concurrent.locks.ReentrantLock

class IDGenerator(private val minValue: Long, private val maxValue: Long) {
    private val lock = ReentrantLock()
    private val valueRange: Long = maxValue - minValue + 1
    private var offset: Long = 0
    private val usedMap: MutableMap<Long, Boolean> = HashMap()

    init {
        offset = 0
        usedMap.clear()
    }

    fun allocate(): Long {
        lock.lock()
        try {
            val offsetBegin = offset
            while (usedMap.containsKey(offset)) {
                updateOffset()
                if (offset == offsetBegin) {
                    throw Exception("No available value range to allocate id")
                }
            }
            usedMap[offset] = true
            val id = offset + minValue
            updateOffset()
            return id
        } finally {
            lock.unlock()
        }
    }

    fun freeID(id: Long) {
        if (id < minValue || id > maxValue) {
            return
        }
        lock.lock()
        try {
            usedMap.remove(id - minValue)
        } finally {
            lock.unlock()
        }
    }

    private fun updateOffset() {
        offset++
        offset %= valueRange
    }
}