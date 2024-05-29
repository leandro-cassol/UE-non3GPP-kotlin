package free5gc.nas.nasType

class SelectedNASSecurityAlgorithms {
    var iei: UByte = 0u
    var octet: UByte = 0u

    @JvmName("getIeiSelectedNASSecurityAlgorithms")
    fun getIei(): UByte = iei

    @JvmName("setIeiSelectedNASSecurityAlgorithms")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    fun getTypeOfCipheringAlgorithm(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    fun setTypeOfCipheringAlgorithm(typeOfCipheringAlgorithm: UByte) {
        octet = (octet.toInt() and 15 or ((typeOfCipheringAlgorithm.toInt() and 15) shl 4)).toUByte()
    }

    fun getTypeOfIntegrityProtectionAlgorithm(): UByte {
        return (octet.toInt() and getBitMask(4, 0).toInt()).toUByte()
    }

    fun setTypeOfIntegrityProtectionAlgorithm(typeOfIntegrityProtectionAlgorithm: UByte) {
        octet = (octet.toInt() and 240 or (typeOfIntegrityProtectionAlgorithm.toInt() and 15)).toUByte()
    }

    companion object {
        fun getBitMask(startPos: Int, endPos: Int): UByte {
            var mask = 0
            for (i in startPos downTo endPos + 1) {
                mask = mask or (1 shl i)
            }
            return mask.toUByte()
        }

        fun newSelectedNASSecurityAlgorithms(iei: UByte): SelectedNASSecurityAlgorithms {
            val selectedNASSecurityAlgorithms = SelectedNASSecurityAlgorithms()
            selectedNASSecurityAlgorithms.setIei(iei)
            return selectedNASSecurityAlgorithms
        }
    }
}