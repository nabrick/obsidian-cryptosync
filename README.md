[![Version](https://img.shields.io/badge/version-1.2.1-lightgrey.svg)]()
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/status-active-lightgrey.svg)]()

# CryptoSync for Obsidian

Plugin para Obsidian que cifra tu vault completo y lo sincroniza con la nube.

Actualmente implementado con **Azure Blob Storage**, pero diseñado para ser agnóstico puedes implementar cualquier otro proveedor (Amazon S3, Backblaze B2, Wasabi) cambiando únicamente el módulo de almacenamiento, código no implementado.

Los archivos en la nube son completamente ilegibles sin tu passphrase.

## Características

- **Cifrado AES-GCM 256 bits** con derivación de clave PBKDF2-SHA256 (250.000 iteraciones)
- **Nombres de archivos hasheados** nadie sabe qué contiene cada archivo ni cómo se llama
- **Passphrase en memoria** nunca se guarda en disco ni en la nube · credenciales Azure cifradas con tu passphrase
- **Sincronización con Azure Blob Storage** solo archivos `.enc`, la nube nunca ve contenido en claro
- **Debounce 60s** cifra y sube a Azure automáticamente mientras trabajas
- **Botón 🔒 en ribbon** para sincronizar el vault manualmente antes de cerrar
- **Detección de conflictos** si editas la misma nota en dos dispositivos, guarda ambas versiones (`nota-conflicto-fecha.md`)
- **Avisos de vencimiento** del SAS token (10, 5 y 3 días antes)
- **Backup automático en Azure** snapshot cifrado cada 7 días, restaurable desde Settings
- **Rotación de passphrase** cambia tu passphrase desde Settings sin perder datos
- **Mapa cifrado** de hashes → paths originales para recuperación
- Interfaz adaptada a **móvil** (Android e iOS)

## Instalación

### Método manual

1. Descarga este repositorio como `.zip`
2. Extrae el contenido
3. Copia la carpeta `cryptosync` dentro de:

```
<tu-vault>/.obsidian/plugins/
```

4. Abre Obsidian → *Settings* → *Community plugins*
5. Activa **CryptoSync**

> Asegúrate de tener activados los *Community plugins*.

## Primer uso

1. Activa el plugin — aparece el modal de passphrase
2. Elige tu passphrase (no se puede recuperar si la olvidas)
3. El plugin cifra todo el vault automáticamente
4. Configura Azure en *Settings → CryptoSync*
5. Usa el botón 🔒 en el ribbon cuando termines de trabajar

## Configuración de Azure

Ve a **Settings → CryptoSync** y completa:

| Campo | Descripción |
|---|---|
| Storage Account | Nombre de tu cuenta de Azure Blob Storage |
| Container | Nombre del contenedor donde se guardan los archivos |
| SAS Token | Token de acceso compartido con permisos de lectura, escritura, eliminación y lista |

Usa el botón **Probar conexión** para verificar que las credenciales son correctas antes de guardar.

### Configurar CORS en Azure

En Azure Portal → tu Storage Account → CORS, agrega estas reglas:

| Origen | Métodos | Headers |
|---|---|---|
| `app://obsidian.md` | GET, PUT, DELETE, HEAD | * |
| `capacitor://localhost` | GET, PUT, DELETE, HEAD | * |
| `http://localhost` | GET, PUT, DELETE, HEAD | * |

### Generar SAS Token

1. Azure Portal → tu Storage Account → Firma de acceso compartido
2. Servicios: **Blob**
3. Tipos de recursos: **Contenedor + Objeto**
4. Permisos: **Lectura, Escritura, Eliminar, Lista, Crear**
5. Fecha de expiración: 1 año recomendado
6. Protocolo: **HTTPS solamente**

## Uso entre dispositivos

### Primer dispositivo (PC)

1. Instala y activa el plugin
2. Define tu passphrase — el vault se cifra automáticamente
3. Configura Azure en Settings
4. Presiona 🔒 para bloquear y subir todo a Azure

### Segundo dispositivo (celular / otra PC)

1. Copia estas carpetas al nuevo dispositivo:

```
.obsidian/plugins/cryptosync/   # código del plugin
.cryptosync/                    # canary y mapa cifrado
```

2. Activa el plugin en Obsidian
3. Ingresa tu passphrase — baja todo de Azure y descifra automáticamente

> La configuración de Azure se guarda cifrada en `.obsidian/plugins/cryptosync/data.json` con tu passphrase. Incluso si copias ese archivo a otro dispositivo, no será legible sin la passphrase correcta. Deberás ingresar las credenciales nuevamente en cada dispositivo nuevo.

## Flujo de trabajo

```
Abres Obsidian
  → passphrase → sincroniza con Azure → descifra → trabajas normal

Mientras trabajas
  → cada 60s por archivo modificado → cifra → guarda .enc → sube a Azure

Terminas de trabajar
  → botón 🔒 → cifra todo en disco → vault bloqueado

Cada 7 días (automático, al bloquear)
  → crea snapshot en Azure → backup/YYYY-MM-DD/ → elimina snapshot anterior
```

## Backup automático

CryptoSync crea un snapshot de tu vault en Azure cada 7 días automáticamente. El backup:

- Se guarda íntegramente **en Azure** (`backup/YYYY-MM-DD/`) — nunca toca el disco local
- Es una copia **Azure → Azure**: no requiere que el vault esté desbloqueado para crearse
- Conserva siempre el **último snapshot** — el anterior se elimina automáticamente
- Está **cifrado** igual que el resto del vault — la passphrase es la misma

### Restaurar desde backup

En *Settings → CryptoSync → Backup automático* verás la fecha del último snapshot y cuántos días faltan para el próximo. Para restaurar:

1. Haz clic en **Restaurar backup**
2. Confirma la acción
3. CryptoSync copia los archivos del snapshot al contenedor principal de Azure y descifra todo localmente

> El snapshot en `backup/` no se modifica durante la restauración.

## Cambiar passphrase

Puedes cambiar tu passphrase en cualquier momento desde *Settings → CryptoSync → Seguridad*. El proceso:

1. Verifica tu passphrase actual
2. Re-cifra todo el vault con la nueva passphrase
3. Sube todo a Azure
4. Vuelve a descifrar — puedes seguir trabajando sin interrupciones

> El proceso puede tardar algunos segundos según el tamaño del vault. No cierres Obsidian mientras opera.

## Resolución de conflictos

Si editas la misma nota en dos dispositivos sin sincronizar, CryptoSync guarda ambas versiones:

- Versión local: `nota.md`
- Versión remota: `nota-conflicto-2026-03-22.md`

Tú decides cuál conservar.

## Estructura del proyecto

```
cryptosync/
├── main.js           ← lógica del plugin
├── styles.css        ← estilos de la interfaz
└── manifest.json     ← metadata

.obsidian/plugins/cryptosync/
└── data.json         ← credenciales Azure cifradas con tu passphrase + checksums locales

.cryptosync/          ← datos del vault (viaja con el vault)
├── vaultsync.enc     ← canary de verificación de passphrase
└── vaultsync-map.enc ← mapa hash → path original (cifrado)
```

## Estructura en Azure

```
Azure Container/
├── cryptosync-map.enc              ← mapa hashedPath → originalPath (cifrado)
├── cryptosync-checksums.enc        ← SHA-256 del plaintext por hashedPath (cifrado)
├── a3f8c2d1/
│   └── b7c3d2e1.enc               ← archivos con nombres hasheados
├── 9f2e1a4b/
│   └── c9d4e5f6.enc
└── backup/
    └── 2026-03-22/                 ← snapshot más reciente
        ├── cryptosync-map.enc
        ├── cryptosync-checksums.enc
        ├── a3f8c2d1/
        │   └── b7c3d2e1.enc
        └── 9f2e1a4b/
            └── c9d4e5f6.enc
```

## Recuperación sin Obsidian

Si Obsidian deja de existir, puedes descifrar tu vault con el script Python incluido:

```bash
python decrypt.py --vault /ruta/vault --output /ruta/salida
```

El script lee el mapa, descifra cada archivo y reconstruye la estructura original. Sin internet, sin Obsidian.

> **Importante:** Si olvidas tu passphrase, no hay forma de recuperar los datos. Guárdala en un lugar seguro.

## Notas de implementación

**Derivación de clave:** PBKDF2-SHA256 con 250.000 iteraciones coste mínimo recomendado por OWASP 2023. Cada intento de fuerza bruta cuesta ~300ms en hardware moderno, haciendo inviable el ataque por diccionario sobre cualquier passphrase razonablemente aleatoria. Se eligió sobre Argon2id para evitar dependencias externas, ya que PBKDF2 está disponible de forma nativa en la Web Crypto API que Obsidian expone.

**Hash de rutas:** Cada segmento de ruta se hashea con SHA-256 y se trunca a 16 caracteres hexadecimales (64 bits). El birthday paradox implica colisión al 50% a partir de ~4.300 millones de segmentos únicos, por lo que en cualquier vault de uso personal el riesgo es prácticamente inexistente.

**Sistema de checksums (`cryptosync-checksums.enc`):** Los blobs cifrados cambian en cada cifrado (por el salt/IV aleatorio), por lo que no se pueden comparar directamente para detectar cambios. El plugin mantiene un registro SHA-256 del **plaintext** de cada archivo, guardado en dos lugares:
- `localChecksums` en `data.json` (local, por dispositivo)
- `cryptosync-checksums.enc` en Azure (compartido entre dispositivos, cifrado con la passphrase)

Al sincronizar, si `localChecksums[hash] === remoteChecksums[hash]` el contenido es idéntico y no se sube ni descarga nada. Si existe un archivo legacy `cryptosync-checksums.json` en claro de una versión anterior, el plugin lo migra automáticamente al formato cifrado al primer sync.

**Sin rollback en cifrado parcial:** Si `encryptVault()` falla a mitad de camino por un error de disco, algunos archivos quedarán cifrados y otros en claro. Si esto ocurre, vuelve a abrir Obsidian e ingresa tu passphrase — el plugin retomará desde el estado actual y completará el proceso.

**Credenciales cifradas (`data.json`):** El Storage Account, Container y SAS Token se cifran con AES-GCM usando la passphrase del vault antes de escribirse en `data.json`. Al arrancar, el plugin pide la passphrase primero y solo entonces descifra las credenciales en memoria. Si existe un `data.json` legacy con credenciales en claro (versión anterior), el plugin las migra automáticamente al formato cifrado en el primer arranque. Nunca se escriben en claro en disco a partir de la versión 1.1.0.

**Passphrase en memoria:** La passphrase se mantiene en RAM mientras Obsidian está abierto. Se limpia automáticamente al descargar el plugin o al presionar 🔒. Nunca se escribe en disco.

**Tiempo de ejecución:** En vaults grandes, la carga inicial puede demorar varios segundos. Espera a que finalice antes de editar notas.

## Licencia

Este proyecto está bajo licencia **MIT**.
