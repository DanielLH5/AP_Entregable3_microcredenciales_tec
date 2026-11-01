# PoC Microcredenciales TEC

Prueba de Concepto (PoC) del **Entregable 3** del proyecto "Plataforma de Acreditación de Microcredenciales Digitales", del curso Administración de Proyectos (IC-4810), Instituto Tecnológico de Costa Rica.

## ¿Para qué sirve este repositorio?

Aquí vive el código que demuestra que una microcredencial digital puede:

1. **Emitirse** y firmarse por el TEC.
2. **Verificarse** para comprobar que es auténtica.
3. **Detectar alteraciones**: si alguien cambia un dato, la verificación falla.
4. **Consultar su estado**: saber si sigue vigente o fue revocada.

Es un prototipo de demostración. No es un sistema real ni se conecta a sistemas del TEC. Todos los datos y llaves son de prueba.

## ¿Qué contiene?

- `test_poc_engine.py`: el script en Python que ejecuta las pruebas.
- `logs/`: las salidas de la consola de cada caso de prueba (CP-04 a CP-08).
- `capturas/`: capturas de pantalla de la consola, para el informe técnico.

## ¿Cómo se usa?

1. Instalar Python 3.
2. Instalar la librería: `pip install cryptography`
3. Correr el script: `python test_poc_engine.py`

## Estándares usados

- W3C Verifiable Credentials Data Model v2.0
- Firma digital Ed25519
- Bitstring Status List v1.0 (para el estado de revocación)

## Equipo

Nicole Gamboa Padilla, Johana Jiménez Mata, Marco González González, Daniel Liao Huang, Franco Rojas Lagos.

Profesor: Ing. Mauricio Arroyo Herrera.