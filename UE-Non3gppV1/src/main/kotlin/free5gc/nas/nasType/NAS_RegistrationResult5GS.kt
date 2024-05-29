package free5gc.nas.nasType

class RegistrationResult5GS {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByte = 0u

    @JvmName("getIeiRegistrationResult5GS")
    fun getIei(): UByte = iei

    @JvmName("setIeiRegistrationResult5GS")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenRegistrationResult5GS")
    fun getLen(): UByte = len

    @JvmName("setLenRegistrationResult5GS")
    fun setLen(len: UByte) {
        this.len = len
    }

    /*
    fun getSMSAllowed(): UByte {
        return octet and getBitMask(4, 3).toUByte() shr 3
    }

    fun setSMSAllowed(sMSAllowed: UByte) {
        octet = (octet and 247u) + ((sMSAllowed and 1u) shl 3)
    }
*/
    fun getRegistrationResultValue5GS(): UByte {
        return octet and getBitMask(3, 0).toUByte()
    }

    fun setRegistrationResultValue5GS(registrationResultValue5GS: UByte) {
        octet = ((octet and 248u) + (registrationResultValue5GS and 7u)).toUByte()
    }

    companion object {
        private fun getBitMask(startPos: Int, endPos: Int): Int {
            var mask = 0
            for (i in startPos downTo endPos) {
                mask = mask or (1 shl i)
            }
            return mask
        }

        fun newRegistrationResult5GS(iei: UByte): RegistrationResult5GS {
            val registrationResult5GS = RegistrationResult5GS()
            registrationResult5GS.setIei(iei)
            return registrationResult5GS
        }
    }
}