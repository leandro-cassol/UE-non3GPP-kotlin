package free5gc.ngap.ngapType

enum class CriticalityEnum(val value: Int) {
    CriticalityPresentReject(0),
    CriticalityPresentIgnore(1),
    CriticalityPresentNotify(2);

    companion object {
        fun fromInt(value: Int) = values().firstOrNull { it.value == value }
    }
}

class Criticality(val value: CriticalityEnum) {
    // Métodos adicionais podem ser implementados conforme necessário
}
