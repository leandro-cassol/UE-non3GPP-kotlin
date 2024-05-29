package free5gc.ngap.ngapType

class AMFSetID(val value: ByteArray) {
    init {
        // Assegura que o tamanho do BitString seja de 10 bits
        require(value.size == 2) { "AMFSetID deve ter exatamente 2 bytes (16 bits) para representar 10 bits" }

        // Verifica se os 6 bits mais significativos do segundo byte estão zerados
        require((value[1].toInt() and 0xFC) == 0) { "Os 6 bits mais significativos do segundo byte devem ser 0" }
    }

    // Métodos adicionais podem ser implementados conforme necessário
}
