package free5gc.nas.nasType

class T3512Value {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByte = 0u

    @JvmName("getIeiT3512Value")
    fun getIei(): UByte {
        return iei
    }

    @JvmName("setIeiT3512Value")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenT3512Value")
    fun getLen(): UByte {
        return len
    }

    @JvmName("setLenT3512Value")
    fun setLen(len: UByte) {
        this.len = len
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
        fun newT3512Value(iei: UByte): T3512Value {
            val t3512Value = T3512Value()
            t3512Value.setIei(iei)
            return t3512Value
        }

        fun getBitMask(startPos: Int, endPos: Int): UByte {
            var mask = 0
            for (i in startPos downTo endPos) {
                mask = mask or (1 shl i)
            }
            return mask.toUByte()
        }
    }
}