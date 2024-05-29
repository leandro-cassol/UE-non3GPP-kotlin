package free5gc.nas.nasType

class UpdateType5GS {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByte = 0u

    companion object {
        fun newUpdateType5GS(iei: UByte): UpdateType5GS {
            val updateType5GS = UpdateType5GS()
            updateType5GS.setIei(iei)
            return updateType5GS
        }

        fun getBitMask(bitStart: Int, bitEnd: Int): Int {
            var mask = 0
            for (i in bitStart downTo bitEnd) {
                mask = mask or (1 shl i)
            }
            return mask
        }
    }

    @JvmName("getIeiUpdateType5GS")
    fun getIei(): UByte = iei

    @JvmName("setIeiUpdateType5GS")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenUpdateType5GS")
    fun getLen(): UByte = len

    @JvmName("setLenUpdateType5GS")
    fun setLen(len: UByte) {
        this.len = len
    }

/*
    fun getNGRanRcu(): UByte {
        return octet and getBitMask(2, 1).toUByte() shr 1
    }

    fun setNGRanRcu(nGRanRcu: UByte) {
        octet = (octet and 253u.toUByte()) or ((nGRanRcu and 1u) shl 1)
    }
*/

    fun getSMSRequested(): UByte {
        return octet and getBitMask(1, 0).toUByte()
    }

    fun setSMSRequested(sMSRequested: UByte) {
        octet = (octet and 254u.toUByte()) or (sMSRequested and 1u)
    }
}