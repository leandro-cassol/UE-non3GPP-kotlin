package free5gc.nas.nasType

class EmergencyNumberList {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiEmergencyNumberList")
    fun getIei(): UByte = iei

    @JvmName("setIeiEmergencyNumberList")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenEmergencyNumberList")
    fun getLen(): UByte = len

    @JvmName("setLenEmergencyNumberList")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getLengthOf1EmergencyNumberInformation(): UByte = buffer[0]

    fun setLengthOf1EmergencyNumberInformation(lengthOf1EmergencyNumberInformation: UByte) {
        buffer[0] = lengthOf1EmergencyNumberInformation
    }

    fun getEmergencyServiceCategoryValue(): UByte = buffer[1] and 0x1Fu

    fun setEmergencyServiceCategoryValue(emergencyServiceCategoryValue: UByte) {
        buffer[1] = (buffer[1] and 0xE0u) or (emergencyServiceCategoryValue and 0x1Fu)
    }

    fun getEmergencyInformation(): UByteArray = buffer.copyOf()

    fun setEmergencyInformation(emergencyInformation: UByteArray) {
        buffer = emergencyInformation.copyOf()
    }

    companion object {
        fun newEmergencyNumberList(iei: UByte): EmergencyNumberList {
            val emergencyNumberList = EmergencyNumberList()
            emergencyNumberList.setIei(iei)
            return emergencyNumberList
        }
    }
}