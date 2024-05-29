package free5gc.nas.nasType

class OperatordefinedAccessCategoryDefinitions {
    var iei: UByte = 0u
    var len: UShort = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiOperatordefinedAccessCategoryDefinitions")
    fun getIei(): UByte = iei

    @JvmName("setIeiOperatordefinedAccessCategoryDefinitions")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenOperatordefinedAccessCategoryDefinitions")
    fun getLen(): UShort = len

    @JvmName("setLenOperatordefinedAccessCategoryDefinitions")
    fun setLen(len: UShort) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getOperatorDefinedAccessCategoryDefinition(): UByteArray = buffer.copyOf()

    fun setOperatorDefinedAccessCategoryDefinition(operatorDefinedAccessCategoryDefinition: UByteArray) {
        buffer = operatorDefinedAccessCategoryDefinition.copyOf()
    }

    companion object {
        fun newOperatordefinedAccessCategoryDefinitions(iei: UByte): OperatordefinedAccessCategoryDefinitions {
            val operatordefinedAccessCategoryDefinitions = OperatordefinedAccessCategoryDefinitions()
            operatordefinedAccessCategoryDefinitions.setIei(iei)
            return operatordefinedAccessCategoryDefinitions
        }
    }
}

