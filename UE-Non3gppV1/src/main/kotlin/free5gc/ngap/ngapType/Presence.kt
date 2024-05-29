package free5gc.ngap.ngapType

enum class Presence(val value: Int) {
    PresencePresentOptional(0),
    PresencePresentConditional(1),
    PresencePresentMandatory(2)
}


