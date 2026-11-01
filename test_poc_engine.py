"""
test_poc_engine.py
Prueba de Concepto (PoC) - Entregable 3
Plataforma de Acreditación de Microcredenciales Digitales (TEC)

Qué hace este script (todo con datos y llaves de PRUEBA):
  CP-04  Genera llaves Ed25519 y arma la credencial W3C VC v2.0 (JSON-LD)
  CP-05  Firma la credencial con la clave privada del emisor (TEC)
  CP-06  Verifica la credencial íntegra dentro de una Verifiable Presentation (VP)
  CP-07  Altera un dato y comprueba que la verificación lo detecta
  CP-08  Consulta el estado de revocación en una Bitstring Status List

Requisito:  pip install cryptography
Uso:        python test_poc_engine.py
Salida:     imprime en consola y guarda un log por caso en la carpeta logs/
"""

import base64
import copy
import gzip
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

CARPETA_LOGS = Path(__file__).parent / "logs"

# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

ALFABETO_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def codificar_base58(datos_en_bytes: bytes) -> str:
    """Codifica bytes en Base58 (la codificación que usan los did:key)."""
    numero = int.from_bytes(datos_en_bytes, "big")
    resultado = ""
    while numero > 0:
        numero, residuo = divmod(numero, 58)
        resultado = ALFABETO_BASE58[residuo] + resultado
    ceros_iniciales = len(datos_en_bytes) - len(datos_en_bytes.lstrip(b"\x00"))
    return "1" * ceros_iniciales + resultado


def obtener_bytes_clave_publica(clave_publica: Ed25519PublicKey) -> bytes:
    return clave_publica.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def construir_did_key(clave_publica: Ed25519PublicKey) -> str:
    """Deriva un did:key a partir de la clave pública Ed25519 (prefijo multicodec 0xed01)."""
    bytes_con_prefijo = b"\xed\x01" + obtener_bytes_clave_publica(clave_publica)
    return "did:key:z" + codificar_base58(bytes_con_prefijo)


def serializar_canonico(documento: dict) -> bytes:
    """JSON determinista: mismas claves ordenadas, sin espacios. Es lo que se firma."""
    return json.dumps(
        documento, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def firmar(clave_privada: Ed25519PrivateKey, documento: dict) -> str:
    firma_en_bytes = clave_privada.sign(serializar_canonico(documento))
    return base64.b64encode(firma_en_bytes).decode("ascii")


def firma_es_valida(clave_publica: Ed25519PublicKey, documento: dict, firma_base64: str) -> bool:
    try:
        clave_publica.verify(base64.b64decode(firma_base64), serializar_canonico(documento))
        return True
    except InvalidSignature:
        return False


class RegistroDeCaso:
    """Imprime en consola y guarda cada línea en logs/<caso>.txt"""

    def __init__(self, nombre_del_caso: str, titulo: str):
        CARPETA_LOGS.mkdir(exist_ok=True)
        self.ruta_archivo = CARPETA_LOGS / f"{nombre_del_caso}.txt"
        self.lineas = []
        self.escribir("=" * 70)
        self.escribir(f"{nombre_del_caso} - {titulo}")
        self.escribir(f"Ejecutado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.escribir("=" * 70)

    def escribir(self, texto: str = ""):
        print(texto)
        self.lineas.append(texto)

    def guardar(self):
        self.ruta_archivo.write_text("\n".join(self.lineas) + "\n", encoding="utf-8")
        print(f"(log guardado en {self.ruta_archivo.name})\n")


# ---------------------------------------------------------------------------
# Bitstring Status List (estado de revocación)
# ---------------------------------------------------------------------------

TAMANO_MINIMO_LISTA_EN_BITS = 131072  # mínimo recomendado por la especificación (16 KB)


def crear_lista_de_estado(indices_revocados: list) -> str:
    """Crea la lista de bits (0 = activa, 1 = revocada), la comprime con GZIP y la codifica."""
    lista_de_bits = bytearray(TAMANO_MINIMO_LISTA_EN_BITS // 8)
    for indice in indices_revocados:
        lista_de_bits[indice // 8] |= 1 << (7 - indice % 8)  # el bit 0 es el más a la izquierda
    comprimida = gzip.compress(bytes(lista_de_bits))
    return "u" + base64.urlsafe_b64encode(comprimida).decode("ascii").rstrip("=")


def consultar_bit_de_estado(lista_codificada: str, indice: int) -> int:
    """Decodifica la lista publicada y devuelve el bit del índice consultado."""
    texto_base64 = lista_codificada[1:]
    texto_base64 += "=" * (-len(texto_base64) % 4)
    lista_de_bits = gzip.decompress(base64.urlsafe_b64decode(texto_base64))
    return (lista_de_bits[indice // 8] >> (7 - indice % 8)) & 1


# ---------------------------------------------------------------------------
# Programa principal
# ---------------------------------------------------------------------------

def main():
    # ----- CP-04: llaves y estructura W3C VC v2.0 ---------------------------
    registro = RegistroDeCaso("CP-04", "Generación de llaves y estructura W3C VC v2.0")

    clave_privada_emisor = Ed25519PrivateKey.generate()
    clave_publica_emisor = clave_privada_emisor.public_key()
    clave_privada_titular = Ed25519PrivateKey.generate()
    clave_publica_titular = clave_privada_titular.public_key()

    did_emisor = "did:web:tec.ac.cr"
    did_titular = construir_did_key(clave_publica_titular)

    registro.escribir(f"Llaves Ed25519 generadas para el emisor y el titular (datos de prueba).")
    registro.escribir(f"DID del emisor : {did_emisor}")
    registro.escribir(f"DID del titular: {did_titular}")
    registro.escribir()

    credencial = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://schema.tec.ac.cr/microcredentials/v1",
        ],
        "id": "urn:uuid:7c9e6679-7425-40de-944b-e07fc1f90ae7",
        "type": ["VerifiableCredential", "Microcredential", "AcademicAchievementCredential"],
        "issuer": {
            "id": did_emisor,
            "name": "Instituto Tecnológico de Costa Rica",
            "department": "Escuela de Ingeniería en Computación",
        },
        "validFrom": "2026-10-15T00:00:00Z",
        "validUntil": "2031-10-15T23:59:59Z",
        "credentialStatus": {
            "id": "https://credenciales.tec.ac.cr/status/2026#4182",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": "4182",
        },
        "credentialSubject": {
            "id": did_titular,
            "name": "Nicole Gamboa Padilla",
            "achievement": {
                "identifier": "TEC-MIC-CLOUD-01",
                "name": "Fundamentos de Computación en la Nube y Arquitectura Escalable",
                "description": "Acredita el dominio técnico en diseño de arquitecturas distribuidas, contenerización y despliegue seguro en entornos de nube.",
                "academicHours": 45,
                "credits": 2,
                "evaluationCriteria": "Aprobación con nota >= 80 en prueba práctica de laboratorio.",
            },
        },
    }

    campos_obligatorios = ["@context", "id", "type", "issuer", "validFrom", "credentialSubject"]
    faltantes = [campo for campo in campos_obligatorios if campo not in credencial]
    registro.escribir("Credencial JSON-LD (W3C VC v2.0):")
    registro.escribir(json.dumps(credencial, indent=2, ensure_ascii=False))
    registro.escribir()
    if faltantes:
        registro.escribir(f"[ERROR] Faltan campos obligatorios: {faltantes}")
    else:
        registro.escribir("[OK] Estructura válida: contiene todos los campos obligatorios de W3C VC v2.0.")
    registro.guardar()

    # ----- CP-05: firma del emisor ------------------------------------------
    registro = RegistroDeCaso("CP-05", "Firma criptográfica Ed25519 por el emisor")

    firma_del_emisor = firmar(clave_privada_emisor, credencial)
    prueba_de_integridad = {
        "type": "DataIntegrityProof",
        "cryptosuite": "ed25519-jcs-poc",
        "verificationMethod": f"{did_emisor}#key-1",
        "proofPurpose": "assertionMethod",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "proofValue": firma_del_emisor,
    }
    registro.escribir(f"Firma (Base64): {firma_del_emisor}")
    registro.escribir(f"Vinculada a   : {prueba_de_integridad['verificationMethod']}")
    registro.escribir("[OK] Credencial firmada con la clave privada del TEC.")
    registro.guardar()

    # ----- CP-06: VP + verificación -----------------------------------------
    registro = RegistroDeCaso("CP-06", "Verificación exitosa de credencial íntegra")

    # 1) El verificador (empresa) genera un nonce para evitar ataques de repetición
    nonce_del_verificador = secrets.token_hex(16)
    registro.escribir(f"Nonce del verificador: {nonce_del_verificador}")

    # 2) La billetera arma la Verifiable Presentation y la firma con la clave del titular
    presentacion_sin_firma = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": did_titular,
        "challenge": nonce_del_verificador,
        "verifiableCredential": [{"credential": credencial, "proof": prueba_de_integridad}],
    }
    firma_del_titular = firmar(clave_privada_titular, presentacion_sin_firma)
    registro.escribir("Verifiable Presentation (VP) armada y firmada por el titular.")
    registro.escribir()

    def verificar_presentacion(presentacion: dict, firma_titular: str, nonce_esperado: str) -> bool:
        """Devuelve True solo si TODAS las comprobaciones pasan."""
        credencial_recibida = presentacion["verifiableCredential"][0]["credential"]
        prueba_recibida = presentacion["verifiableCredential"][0]["proof"]

        nonce_correcto = presentacion["challenge"] == nonce_esperado
        registro.escribir(f"  [1] Nonce coincide con la solicitud : {nonce_correcto}")

        titular_correcto = firma_es_valida(clave_publica_titular, presentacion, firma_titular)
        registro.escribir(f"  [2] Firma del titular válida         : {titular_correcto}")

        emisor_reconocido = credencial_recibida["issuer"]["id"] == did_emisor
        registro.escribir(f"  [3] Emisor reconocido ({did_emisor}) : {emisor_reconocido}")

        firma_emisor_correcta = firma_es_valida(
            clave_publica_emisor, credencial_recibida, prueba_recibida["proofValue"]
        )
        registro.escribir(f"  [4] Firma del emisor válida          : {firma_emisor_correcta}")

        ahora = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        dentro_de_vigencia = (
            credencial_recibida["validFrom"] <= ahora <= credencial_recibida["validUntil"]
        )
        registro.escribir(f"  [5] Dentro del periodo de validez     : {dentro_de_vigencia}")

        return all([nonce_correcto, titular_correcto, emisor_reconocido,
                    firma_emisor_correcta, dentro_de_vigencia])

    registro.escribir("Comprobaciones del verificador:")
    if verificar_presentacion(presentacion_sin_firma, firma_del_titular, nonce_del_verificador):
        registro.escribir("[OK] Firma válida. Credencial íntegra y auténtica.")
    else:
        registro.escribir("[ALERTA] La verificación falló.")
    registro.guardar()

    # ----- CP-07: prueba de manipulación ------------------------------------
    registro = RegistroDeCaso("CP-07", "Prueba de manipulación de datos (adulteración)")

    credencial_adulterada = copy.deepcopy(credencial)
    credencial_adulterada["credentialSubject"]["achievement"]["credits"] = 3  # antes: 2
    registro.escribir("Se cambió un solo dato: créditos 2 -> 3 (la firma original NO se tocó).")

    if firma_es_valida(clave_publica_emisor, credencial_adulterada, firma_del_emisor):
        registro.escribir("[OK] Firma válida (esto NO debería pasar).")
    else:
        registro.escribir("[ALERTA] Firma inválida. Se detectó manipulación de datos.")
    registro.guardar()

    # ----- CP-08: estado de revocación --------------------------------------
    registro = RegistroDeCaso("CP-08", "Consulta de estado de revocación (Bitstring Status List)")

    indice_de_la_credencial = int(credencial["credentialStatus"]["statusListIndex"])
    registro.escribir(f"Índice consultado: #{indice_de_la_credencial}")
    registro.escribir(f"Tamaño de la lista: {TAMANO_MINIMO_LISTA_EN_BITS} bits (0 = activa, 1 = revocada)")
    registro.escribir()

    # Escenario A: la credencial no está revocada
    lista_publicada = crear_lista_de_estado(indices_revocados=[17, 90210])
    bit_de_estado = consultar_bit_de_estado(lista_publicada, indice_de_la_credencial)
    registro.escribir(f"Escenario A - bit en #{indice_de_la_credencial}: {bit_de_estado}")
    if bit_de_estado == 0:
        registro.escribir("[ESTADO] Credencial activa y vigente en lista de estado.")
    else:
        registro.escribir("[ESTADO] Credencial REVOCADA.")
    registro.escribir()

    # Escenario B: el TEC la revoca (se activa el bit) y se vuelve a consultar
    lista_publicada_tras_revocar = crear_lista_de_estado(
        indices_revocados=[17, 90210, indice_de_la_credencial]
    )
    bit_de_estado = consultar_bit_de_estado(lista_publicada_tras_revocar, indice_de_la_credencial)
    registro.escribir(f"Escenario B (tras revocar) - bit en #{indice_de_la_credencial}: {bit_de_estado}")
    if bit_de_estado == 0:
        registro.escribir("[ESTADO] Credencial activa y vigente en lista de estado.")
    else:
        registro.escribir("[ESTADO] Credencial REVOCADA. Ya no debe aceptarse.")
    registro.guardar()

    print("Listo. Los logs de CP-04 a CP-08 están en la carpeta logs/.")


if __name__ == "__main__":
    main()