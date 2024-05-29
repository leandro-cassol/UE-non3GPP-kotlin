package free5gc.nas.nasType

class LocalTimeZone {
    var iei: UByte = 0u
    var octet: UByte = 0u

    @JvmName("getIeiLocalTimeZone")
    fun getIei(): UByte = iei

    @JvmName("setIeiLocalTimeZone")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    fun getTimeZone(): UByte {
        return octet
    }

    fun setTimeZone(timeZone: UByte) {
        this.octet = timeZone
    }

    companion object {
        fun newLocalTimeZone(iei: UByte): LocalTimeZone {
            val localTimeZone = LocalTimeZone()
            localTimeZone.setIei(iei)
            return localTimeZone
        }
    }
}