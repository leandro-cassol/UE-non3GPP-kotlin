package free5gc.ngap.ngapType

class AMFPointer(val value: Byte) {
    init {
        // Verifica se os 2 bits mais significativos estão zerados
        require((value.toInt() and 0xC0) == 0) { "Os 2 bits mais significativos devem ser 0" }
    }

    // Métodos adicionais podem ser implementados conforme necessário
}
