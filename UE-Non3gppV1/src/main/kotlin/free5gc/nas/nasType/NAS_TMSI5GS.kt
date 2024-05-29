package free5gc.nas.nasType

class TMSI5GS {
    var iei: UByte = 0u
    var len: UShort = 0u
    var octet: UByteArray = UByteArray(7)

    @JvmName("getIeiTMSI5GS")
    fun getIei(): UByte = iei

    @JvmName("setIeiTMSI5GS")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenTMSI5GS")
    fun getLen(): UShort = len

    @JvmName("setLenTMSI5GS")
    fun setLen(len: UShort) {
        this.len = len
    }

    fun getSpare(): UByte {
        return ((octet[0].toInt() and getBitMask(4, 3)) shr 3).toUByte()
    }

    @JvmName("setSpareTMSI5GS")
    fun setSpare(spare: UByte) {
        octet[0] = (octet[0].toInt() and 247 or ((spare.toInt() and 1) shl 3)).toUByte()
    }

    fun getTypeOfIdentity(): UByte {
        return octet[0] and getBitMask(3, 0).toUByte()
    }

    fun setTypeOfIdentity(typeOfIdentity: UByte) {
        octet[0] = (octet[0].toInt() and 248 or (typeOfIdentity.toInt() and 7)).toUByte()
    }

    fun getAMFSetID(): UShort {
        return ((octet[1].toInt() shl 2) + ((octet[2].toInt() and getBitMask(8, 2)) shr 6)).toUShort()
    }

    fun setAMFSetID(aMFSetID: UShort) {
        octet[1] = ((aMFSetID.toInt() shr 2) and 255).toUByte()
        octet[2] = (octet[2].toInt() and getBitMask(6, 6) or ((aMFSetID.toInt() and 3) shl 6)).toUByte()
    }

    fun getAMFPointer(): UByte {
        return octet[2] and getBitMask(6, 0).toUByte()
    }

    fun setAMFPointer(aMFPointer: UByte) {
        octet[2] = (octet[2].toInt() and 192 or (aMFPointer.toInt() and 63)).toUByte()
    }

    fun getTMSI5G(): UByteArray {
        return octet.copyOfRange(3, 7)
    }

    fun setTMSI5G(tMSI5G: UByteArray) {
        System.arraycopy(tMSI5G, 0, octet, 3, 4)
    }

    fun get5GSTMSI(): Triple<String, String, Error?> {
        val partOfAmfId = octet.copyOfRange(1, 3).joinToString("") { eachByte -> "%02x".format(eachByte) }
        val tmsi5g = octet.copyOfRange(3, 7).joinToString("") { eachByte -> "%02x".format(eachByte) }
        val tMSI5GS = partOfAmfId + tmsi5g
        return Triple(tMSI5GS, "5G-S-TMSI", null)
    }

    companion object {
        private fun getBitMask(from: Int, to: Int): Int {
            var mask = 0
            for (i in from downTo to) {
                mask = mask or (1 shl i)
            }
            return mask
        }

        fun newTMSI5GS(iei: UByte): TMSI5GS {
            val tMSI5GS = TMSI5GS()
            tMSI5GS.setIei(iei)
            return tMSI5GS
        }
    }
}