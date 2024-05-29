package free5gc.ngap.ngapType

class PLMNIdentity(val value: ByteArray) {
    init {
        // Validação do tamanho, se necessário
        require(value.size == 3) { "PLMNIdentity deve ter exatamente 3 bytes" }
    }
}