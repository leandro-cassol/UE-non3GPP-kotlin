package free5gc.nas.nasType

class BackoffTimerValue {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByte = 0u

    @JvmName("getIeiBackoffTimerValue")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiBackoffTimerValue")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenBackoffTimerValue")
    fun getLen(): UByte = len

    @JvmName("setLenBackoffTimerValue")
    fun setLen(len: UByte) {
        this.len = len
    }

    fun getUnitTimerValue(): UByte {
        return (octet.toInt() and getBitMask(8, 5).toInt() shr 5).toUByte()
    }

    fun setUnitTimerValue(unitTimerValue: UByte) {
        octet = ((octet.toInt() and 31) + ((unitTimerValue.toInt() and 7) shl 5)).toUByte()
    }

    fun getTimerValue(): UByte {
        return (octet.toInt() and getBitMask(5, 0).toInt()).toUByte()
    }

    fun setTimerValue(timerValue: UByte) {
        octet = ((octet.toInt() and 224) + (timerValue.toInt() and 31)).toUByte()
    }

    companion object {
        fun newBackoffTimerValue(iei: UByte): BackoffTimerValue {
            val backoffTimerValue = BackoffTimerValue()
            backoffTimerValue.setIei(iei)
            return backoffTimerValue
        }

        private fun getBitMask(startPos: Int, endPos: Int): UByte {
            var mask = 0
            for (i in startPos downTo endPos + 1) {
                mask = mask or (1 shl i)
            }
            return mask.toUByte()
        }
    }
}



