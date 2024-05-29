package free5gc.ngap.ngapType

enum class ReflectiveQosAttributeValue(val value: Int) {
    ReflectiveQosAttributePresentSubjectTo(0)
}

class ReflectiveQosAttribute(val value: ReflectiveQosAttributeValue)
