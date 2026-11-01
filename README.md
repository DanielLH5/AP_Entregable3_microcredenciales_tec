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
- `logs/`: las salidas de la consola de cada caso de prueba (`CP-04.txt` a `CP-08.txt`).
- `capturas/`: capturas de pantalla de la consola, para el informe técnico.

## ¿Cómo se usa?

1. Instalar Python 3.
2. Instalar la librería: `pip install cryptography`
3. Correr el script: `python test_poc_engine.py`

Al correrlo, se imprime todo en la consola y se guarda un archivo por caso en `logs/`. Las llaves se generan nuevas en cada ejecución, por eso las firmas cambian cada vez.

## ¿Qué hace cada caso de prueba?

| Caso | Qué hace, en simple | Resultado esperado |
| :---: | :--- | :--- |
| **CP-04** | Crea las llaves de prueba y arma la credencial con los datos de la microcredencial piloto (nombre, horas, créditos, emisor, titular). | La credencial tiene todos los campos que exige el estándar W3C. |
| **CP-05** | El TEC firma la credencial con su llave privada, como un sello que solo él puede poner. | Se genera la firma y queda ligada al DID del TEC. |
| **CP-06** | La estudiante arma una presentación con la credencial y la envía a una empresa. La empresa revisa que todo esté bien: la solicitud, las firmas, el emisor y las fechas. | `[OK] Firma válida. Credencial íntegra y auténtica.` |
| **CP-07** | Se cambia un solo dato (créditos de 2 a 3) sin tocar la firma, para ver si alguien podría hacer trampa. | `[ALERTA] Firma inválida. Se detectó manipulación de datos.` |
| **CP-08** | Se consulta la lista de estado del TEC para ver si la credencial sigue vigente. Se prueba con la credencial activa y luego ya revocada. | Primero `[ESTADO] Credencial activa y vigente...`, luego `Credencial REVOCADA`. |

## Estándares usados

- W3C Verifiable Credentials Data Model v2.0
- Firma digital Ed25519
- Bitstring Status List v1.0 (para el estado de revocación)

## Equipo

Nicole Gamboa Padilla, Johana Jiménez Mata, Marco González González, Daniel Liao Huang, Franco Rojas Lagos.

Profesor: Ing. Mauricio Arroyo Herrera.