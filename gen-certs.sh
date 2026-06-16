#!/bin/bash
#
# Genera un certificado TLS autofirmado para pruebas del modo servidor.
# Crea server.crt y server.key en el directorio actual, que es donde
# el binario los busca al arrancar (paths relativos en Server.cpp).
#
# Uso:
#   ./gen-certs.sh             -> usa la IP por defecto (192.168.0.251)
#   ./gen-certs.sh <ip|host>   -> usa la IP o hostname indicado como CN
#
# NOTA: certificado solo para desarrollo. Los clientes (curl, etc.)
# necesitan --insecure/-k porque no esta firmado por una CA.

set -e

CN="${1:-192.168.0.251}"
DIAS=365

# No pisar certificados existentes sin avisar
if [ -f server.crt ] || [ -f server.key ]; then
    read -p "Ya existen server.crt/server.key. ¿Sobrescribir? [s/N] " resp
    if [ "$resp" != "s" ] && [ "$resp" != "S" ]; then
        echo "Cancelado."
        exit 1
    fi
fi

openssl req -x509 -newkey rsa:2048 \
        -keyout server.key -out server.crt \
        -days "$DIAS" -nodes \
        -subj "/CN=$CN"

# La clave privada solo debe poder leerla el dueño
chmod 600 server.key

echo ""
echo "Listo: server.crt y server.key generados para CN=$CN (validez: $DIAS dias)"
echo "Ejecuta el servidor desde este directorio: ./output/aesexe ser $CN 8080"
