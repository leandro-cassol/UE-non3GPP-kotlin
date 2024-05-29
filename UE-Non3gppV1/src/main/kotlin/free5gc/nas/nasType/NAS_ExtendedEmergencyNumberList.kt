package free5gc.nas.nasType

class ExtendedEmergencyNumberList {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)


    companion object {
        fun newExtendedEmergencyNumberList(iei: UByte): ExtendedEmergencyNumberList {
            val extendedEmergencyNumberList = ExtendedEmergencyNumberList()
            extendedEmergencyNumberList.setIei(iei)
            return extendedEmergencyNumberList
        }
    }

    @JvmName("getIeiExtendedEmergencyNumberList")
    fun getIei(): UByte = iei

    @JvmName("setIeiExtendedEmergencyNumberList")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenExtendedEmergencyNumberList")
    fun getLen(): UShort = len

    @JvmName("setLenExtendedEmergencyNumberList")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getEENL(): UByte = buffer[0] and 1u

    fun setEENL(eENL: UByte) {
        buffer[0] = (buffer[0] and 254u.toUByte()) or (eENL and 1u)
    }

    fun getEmergencyInformation(): UByteArray = buffer.copyOf()

    fun setEmergencyInformation(emergencyInformation: UByteArray) {
        buffer = emergencyInformation.copyOf()
    }
}

