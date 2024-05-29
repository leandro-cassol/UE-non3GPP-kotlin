package free5gc.nas.nasType

class RQTimerValue {
    var iei: UByte = 0u
    var octet: UByte = 0u

    @JvmName("getIeiRQTimerValue")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiRQTimerValue")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    fun getUnit(): UByte {
        return (octet.toInt() and getBitMask(8, 5).toInt() shr 5).toUByte()
    }

    fun setUnit(unit: UByte) {
        octet = ((octet.toInt() and 31) + ((unit.toInt() and 7) shl 5)).toUByte()
    }

    fun getTimerValue(): UByte {
        return (octet.toInt() and getBitMask(5, 0).toInt()).toUByte()
    }

    fun setTimerValue(timerValue: UByte) {
        octet = ((octet.toInt() and 224) + (timerValue.toInt() and 31)).toUByte()
    }

    companion object {
        fun getBitMask(from: Int, to: Int): UByte {
            var mask = 0
            for (i in from downTo to) {
                mask = mask or (1 shl i)
            }
            return mask.toUByte()
        }

        fun newRQTimerValue(iei: UByte): RQTimerValue {
            val rQTimerValue = RQTimerValue()
            rQTimerValue.setIei(iei)
            return rQTimerValue
        }
    }
}