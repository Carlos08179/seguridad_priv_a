# Evaluación Técnica: Análisis y Mejora de Seguridad en Aplicación Android

## Introducción

Esta evaluación técnica se basa en una aplicación Android que implementa un sistema de demostración de permisos y protección de datos. La aplicación utiliza tecnologías modernas como Kotlin, Android Security Crypto, SQLCipher y patrones de arquitectura MVVM.

---

## Parte 1: Análisis de Seguridad Básico (0-7 puntos)

### 1.1 Identificación de Vulnerabilidades (2 puntos)

Analiza el archivo `DataProtectionManager.kt` y responde:

- **¿Qué método de encriptación se utiliza para proteger datos sensibles?**
  
Se utilizan dos esquemas de cifrado AES de 256 bits, provistos por la clase EncryptedSharedPreferences:
1)	Para las claves (nombres de las variables):
i)	PrefKeyEncryptionScheme.AES256_SIV

2)	Para los valores (contenido de las variables):
i)	PrefValueEncryptionScheme.AES256_GCM
Esto significa que:
1.	La clave del dato se cifra con AES-256-SIV (determinístico y resistente a manipulaciones).
2.	El valor del dato se cifra con AES-256-GCM (modo autenticado, garantiza integridad).



- **Identifica al menos 2 posibles vulnerabilidades en la implementación actual del logging**

 a) Logs almacenados en texto plano (sin encriptar)
Los logs se guardan en SharedPreferences normales (accessLogPrefs) sin ningún tipo de cifrado.
	Problema: Cualquier app con acceso root o malicioso podría leer los registros.

b) Logs acumulados en una única clave (logs) como string largo
Los registros se concatenan en un solo campo de texto con saltos de línea.
	Problema:

	Se puede llegar al límite de almacenamiento de SharedPreferences.
	Es ineficiente buscar, filtrar o eliminar entradas específicas.
	Puede ser vulnerable a corrupción de datos si la app se cierra inesperadamente mientras escribe.


- **¿Qué sucede si falla la inicialización del sistema de encriptación?**

 Si la inicialización falla (por ejemplo, si el dispositivo no soporta EncryptedSharedPreferences o hay un error en la generación del MasterKey), se ejecuta este bloque:
catch (e: Exception) {
    // Fallback a SharedPreferences normales
    encryptedPrefs = context.getSharedPreferences("fallback_prefs", Context.MODE_PRIVATE)
    accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
    
Esto significa que:
•	Los datos no estarán encriptados (se usa SharedPreferences comunes).
•	A pesar del nombre de la clase (DataProtectionManager), los datos estarán desprotegidos si falla la encriptación.
Consecuencia grave: se rompe el principio de "fail secure", ya que debería impedir el almacenamiento de datos sensibles si no se puede garantizar su seguridad.


---

### 1.2 Permisos y Manifiesto (2 puntos)

Examina `AndroidManifest.xml` y `MainActivity.kt`:

- **Lista todos los permisos peligrosos declarados en el manifiesto**

Los permisos peligrosos (según la clasificación de Android) son aquellos que acceden a datos o recursos personales del usuario y requieren solicitud en tiempo de ejecución (runtime) desde Android 6.0 (API 23) en adelante.
De los permisos declarados en el AndroidManifest.xml, los siguientes son considerados peligrosos:
1.	android.permission.CAMERA
→ Toma de fotos y grabación de video.
2.	android.permission.READ_EXTERNAL_STORAGE (peligroso, pero obsoleto desde Android 13)
3.	android.permission.READ_MEDIA_IMAGES
→ Acceso a imágenes almacenadas (nuevo permiso para Android 13+).
4.	android.permission.RECORD_AUDIO
→ Grabación de sonido con el micrófono.
5.	android.permission.READ_CONTACTS
→ Acceso a los contactos del usuario.
6.	android.permission.CALL_PHONE
→ Permite iniciar llamadas directamente.
7.	android.permission.ACCESS_COARSE_LOCATION
→ Acceso a la ubicación aproximada del usuario.


- **¿Qué patrón se utiliza para solicitar permisos en runtime?**
  
En MainActivity.kt, se utiliza el patrón: 
Activity Result API (Jetpack) con ActivityResultContracts.RequestPermission()
	Ventajas de este patrón:
•	Más seguro y claro que requestPermissions().
•	Maneja automáticamente el ciclo de vida.
•	Compatible con AndroidX y componentes modernos.

- **Identifica qué configuración de seguridad previene backups automáticos**

La siguiente línea en el <application> del AndroidManifest.xml es clave:
android:allowBackup="false"
Esto desactiva los backups automáticos del sistema, incluyendo:
•	Backups a Google Drive.
•	Backups mediante adb (adb backup).
Evita que datos sensibles (como preferencias, tokens o configuraciones privadas) se guarden y restauren en otro dispositivo, protegiendo la privacidad y seguridad del usuario.

### 1.3 Gestión de Archivos (3 puntos)

Revisa `CameraActivity.kt` y `file_paths.xml`:

- **¿Cómo se implementa la compartición segura de archivos de imágenes?**

 La compartición segura de imágenes se implementa utilizando FileProvider, que evita exponer directamente rutas de archivos internas (como file://...) a otras aplicaciones. El flujo que se sigue es el siguiente:
1.	Creación del archivo de imagen:
val photoFile = createImageFile()
Este archivo se guarda en un directorio controlado (getExternalFilesDir(null)/Pictures).
2.	Generación del URI seguro:
currentPhotoUri = FileProvider.getUriForFile(
    this,
    "com.example.seguridad_priv_a.fileprovider", // autoridad
    photoFile
)
Aquí, el URI devuelto es del tipo content://, que puede ser compartido con otras apps de forma segura.
3.	Uso de ese URI en una intent para tomar foto:
takePictureLauncher.launch(uri)
Se lanza una intent con ese URI como destino de la imagen capturada.
4.	Configuración en file_paths.xml:
El archivo especifica a qué subdirectorios se puede acceder a través de FileProvider:
<external-files-path name="my_images" path="Pictures" />


- **¿Qué autoridad se utiliza para el FileProvider?**

La autoridad definida es:
android:authorities="com.example.seguridad_priv_a.fileprovider"
Y es usada en el código:
FileProvider.getUriForFile(
    this,
    "com.example.seguridad_priv_a.fileprovider",
    photoFile
)
Esta autoridad debe coincidir exactamente entre el código y el AndroidManifest.xml.


- **Explica por qué no se debe usar `file://` URIs directamente**

Usar file:// URIs está desaconsejado y bloqueado desde Android 7.0 (API 24) debido a razones de seguridad:
•	Expone la ruta real del sistema de archivos, lo cual puede ser un riesgo.
•	Rompe el aislamiento entre apps: una app podría intentar leer archivos de otra sin permiso.
•	Causa FileUriExposedException cuando se intenta compartir un file:// URI con otra app.

## Parte 2: Implementación y Mejoras Intermedias (8-14 puntos)

### 2.1 Fortalecimiento de la Encriptación (3 puntos)
Modifica `DataProtectionManager.kt` para implementar:

- Rotación automática de claves maestras cada 30 días
**Descripción:**
Cada 30 días se fuerza la rotación de la clave maestra utilizada por `EncryptedSharedPreferences`. Se almacena la última fecha de rotación en el mismo archivo seguro.

**Código relevante:**

```kotlin
fun rotateEncryptionKey(): Boolean {
        return try {
            val allData = encryptedPrefs.all

            context.deleteSharedPreferences("secure_prefs")

            val newMasterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            encryptedPrefs = EncryptedSharedPreferences.create(
                context,
                "secure_prefs",
                newMasterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            val editor = encryptedPrefs.edit()
            for ((key, value) in allData) {
                when (value) {
                    is String -> editor.putString(key, value)
                    is Int -> editor.putInt(key, value)
                    is Boolean -> editor.putBoolean(key, value)
                    is Float -> editor.putFloat(key, value)
                    is Long -> editor.putLong(key, value)
                }
            }
            editor.apply()

            accessLogPrefs.edit().putLong("last_key_rotation", System.currentTimeMillis()).apply()
            logAccess("KEY_ROTATION", "Clave maestra rotada exitosamente")
            true
        } catch (e: Exception) {
            logAccess("KEY_ROTATION", "Error al rotar clave: ${e.message}")
            false
        }
    }
```
- Verificación de integridad de datos encriptados usando HMAC
```kotlin
fun verifyDataIntegrity(key: String): Boolean {
        val value = encryptedPrefs.getString(key, null) ?: return false
        val storedHmac = encryptedPrefs.getString("${key}_hmac", null) ?: return false
        val calculatedHmac = computeHMAC(value, key)
        return storedHmac == calculatedHmac
    }
```
- Implementación de key derivation con salt único por usuario
```kotlin
private fun generateHMAC(data: String, userId: String): String {
    val salt = userId.toByteArray(StandardCharsets.UTF_8)
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val spec = PBEKeySpec(userId.toCharArray(), salt, 10000, 256)
    val secret = factory.generateSecret(spec).encoded
    val hmacKey = SecretKeySpec(secret, "HmacSHA256")
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(hmacKey)
    val result = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
    return Base64.encodeToString(result, Base64.NO_WRAP)
}
```

### 2.2 Sistema de Auditoría Avanzado (3 puntos)
Crea una nueva clase `SecurityAuditManager` que:
- Detecte intentos de acceso sospechosos (múltiples solicitudes en corto tiempo)
- Implemente rate limiting para operaciones sensibles
- Genere alertas cuando se detecten patrones anómalos
- Exporte logs en formato JSON firmado digitalmente

1. SecurityAuditManager.kt

Clase personalizada encargada de:

⚡ Detección de accesos sospechosos: identifica intentos múltiples en corto tiempo por ID de permiso.

⛔ Rate limiting: bloquea acciones cuando hay muchos accesos seguidos (por defecto más de 3 intentos en 10 segundos).

🚨 Generación de alertas: muestra un AlertDialog si se detectan patrones anómalos.

📃 Exportación de logs firmados: exporta un archivo .json con los eventos registrados, firmado digitalmente con HMAC-SHA256.
```kotlin
val securityAuditManager = SecurityAuditManager.getInstance(context)
val allowed = securityAuditManager.registerAccess("Camera")
if (allowed) {
    startActivity(Intent(context, CameraActivity::class.java))
} else {
    // Bloqueado por actividad sospechosa
}
```
📂 Estructura del Proyecto
```kotlin
com.example.seguridad_priv_a
|├── data/
|   ├── DataProtectionManager.kt
|   ├── PermissionItem.kt
|   └── SecurityAuditManager.kt   ← Nueva clase implementada
|
|├── adapter/
|   └── PermissionsAdapter.kt
|
|├── MainActivity.kt               ← Integración con SecurityAuditManager
|├── CameraActivity.kt
|├── CalendarActivity.kt
|├── MicrophoneActivity.kt
|└── StorageActivity.kt
```
### 2.3 Biometría y Autenticación (3 puntos)
Implementa autenticación biométrica en `DataProtectionActivity.kt`:
- Integra BiometricPrompt API para proteger el acceso a logs
- Implementa fallback a PIN/Pattern si biometría no está disponible
- Añade timeout de sesión tras inactividad de 5 minutos
#### 🔐 1. Autenticación Biométrica (Huella, Rostro, etc.)
Se ha integrado la API `BiometricPrompt` de Android para permitir el acceso a la actividad **solo mediante autenticación biométrica válida**.

- Al iniciar la actividad, se muestra un cuadro de diálogo biométrico al usuario.
- Si el usuario cancela o falla la autenticación, no puede acceder a los datos sensibles.
- La autenticación se vuelve a solicitar si la app es reabierta tras tiempo de inactividad.

#### 🔁 2. Mecanismo de Respaldo (Fallback)
Si el dispositivo **no cuenta con sensores biométricos** o el usuario no tiene una biometría configurada, se usa un **fallback manual**, actualmente simulado como un diálogo personalizado que permite ingresar un código de respaldo (PIN o patrón simulado).

> 📌 Este fallback puede conectarse con almacenamiento cifrado o autenticación real basada en contraseña en futuras versiones.

#### ⏳ 3. Expiración de Sesión (Inactividad > 5 min)
Se implementó un sistema de control de sesión que:
- Guarda la hora del último uso mediante `EncryptedSharedPreferences`.
- Al volver a abrir la actividad, se compara la hora actual con la última actividad.
- Si han pasado más de **5 minutos de inactividad**, se solicita **reautenticación**.

---
### 📁 Archivos Relevantes

- `DataProtectionActivity.kt`: Lógica de autenticación biométrica y verificación de sesión.
- `DataProtectionManager.kt`: Clase encargada del almacenamiento seguro y auditoría.
- `res/xml/biometric_prompt.xml`: (opcional) Configuración visual del prompt.
- `AndroidManifest.xml`: Incluye permisos y declaración de la actividad protegida.

---
```kotlin
private fun setupBiometricAuthentication() {
    val executor = ContextCompat.getMainExecutor(this)

    biometricPrompt = BiometricPrompt(this, executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Toast.makeText(applicationContext, "Autenticación exitosa", Toast.LENGTH_SHORT).show()
                // Permitir acceso a los datos protegidos
                lastInteractionTime = System.currentTimeMillis()
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Toast.makeText(applicationContext, "Autenticación fallida", Toast.LENGTH_SHORT).show()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Toast.makeText(applicationContext, "Error: $errString", Toast.LENGTH_SHORT).show()
            }
        })

    promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Autenticación Requerida")
        .setSubtitle("Usa tu huella o patrón para continuar")
        .setDeviceCredentialAllowed(true) // Permite PIN/Patrón como fallback
        .build()
}
```
## Parte 3: Arquitectura de Seguridad Avanzada (15-20 puntos)

### 3.1 Implementación de Zero-Trust Architecture (3 puntos)
Diseña e implementa un sistema que:
- Valide cada operación sensible independientemente
- Implemente principio de menor privilegio por contexto
- Mantenga sesiones de seguridad con tokens temporales
- Incluya attestation de integridad de la aplicación

### 3.2 Protección Contra Ingeniería Inversa (3 puntos)
Implementa medidas anti-tampering:
- Detección de debugging activo y emuladores
- Obfuscación de strings sensibles y constantes criptográficas
- Verificación de firma digital de la aplicación en runtime
- Implementación de certificate pinning para comunicaciones futuras
# 3.2 - Seguridad en Android: Protección de Datos y Permisos

## 📱 Descripción General

Este proyecto Android en Kotlin implementa mecanismos de seguridad enfocados en la **protección de datos sensibles** y el **control de permisos**, utilizando prácticas modernas como `EncryptedSharedPreferences`, detección de debugging, cifrado HMAC, derivación de claves con `PBKDF2`, y políticas de permisos explícitas.

## ✅ Funcionalidades Implementadas

### 🔐 Protección de Datos
- Uso de `EncryptedSharedPreferences` para guardar datos sensibles cifrados.
- Generación de claves maestras mediante `MasterKey`.
- Implementación de rotación automática de claves cada 30 días.
- Integridad verificada con HMAC (SHA-256).
- Derivación de claves personalizadas con salt por usuario usando PBKDF2.

### 🛡️ Seguridad Avanzada
- Detección de debugging (modo desarrollador) para cerrar la app si se detecta.
- Ofuscación de strings sensibles.
- Uso de ProGuard/R8 para minimizar y ofuscar código en versiones `release`.

### 🔧 Permisos Sensibles
- Actividades individuales para cada permiso:
  - Cámara (`CameraActivity`)
  - Micrófono (`MicrophoneActivity`)
  - Calendario (`CalendarActivity`)
  - Almacenamiento (`StorageActivity`)
- Solicitud dinámica de permisos sensibles.
- Iconos personalizados e interfaz simple para usuarios.

## 📂 Estructura del Proyecto

├── app/
│ ├── java/com/example/seguridad_priv_a/
│ │ ├── MainActivity.kt
│ │ ├── CameraActivity.kt
│ │ ├── MicrophoneActivity.kt
│ │ ├── CalendarActivity.kt
│ │ ├── StorageActivity.kt
│ │ ├── PermissionsApplication.kt
│ │ ├── data/
│ │ │ ├── DataProtectionManager.kt
│ │ │ └── PermissionItem.kt
│ │ └── adapter/
│ │ └── PermissionsAdapter.kt
│ └── res/
│ ├── layout/
│ ├── values/
│ └── xml/

## ⚙️ Configuración de ProGuard (build.gradle)

```groovy
buildTypes {
    release {
        minifyEnabled true
        shrinkResources true
        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
    }
}
```
### 3.3 Framework de Anonimización Avanzado (2 puntos)
Mejora el método `anonymizeData()` actual implementando:
- Algoritmos de k-anonimity y l-diversity
- Differential privacy para datos numéricos
- Técnicas de data masking específicas por tipo de dato
- Sistema de políticas de retención configurables

```kotlin
class AdvancedAnonymizer {
    fun anonymizeWithKAnonymity(data: List<PersonalData>, k: Int): List<AnonymizedData>
    fun applyDifferentialPrivacy(data: NumericData, epsilon: Double): NumericData
    fun maskByDataType(data: Any, maskingPolicy: MaskingPolicy): Any
}
```

### 3.4 Análisis Forense y Compliance (2 puntos)
Desarrolla un sistema de análisis forense que:
- Mantenga chain of custody para evidencias digitales
- Implemente logs tamper-evident usando blockchain local
- Genere reportes de compliance GDPR/CCPA automáticos
- Incluya herramientas de investigación de incidentes

## Criterios de Evaluación

### Puntuación Base (0-7 puntos):
- Correcta identificación de vulnerabilidades y patrones de seguridad
- Comprensión de conceptos básicos de Android Security
- Documentación clara de hallazgos

### Puntuación Intermedia (8-14 puntos):
- Implementación funcional de mejoras de seguridad
- Código limpio siguiendo principios SOLID
- Manejo adecuado de excepciones y edge cases
- Pruebas unitarias para componentes críticos

### Puntuación Avanzada (15-20 puntos):
- Arquitectura robusta y escalable
- Implementación de patrones de seguridad industry-standard
- Consideración de amenazas emergentes y mitigaciones
- Documentación técnica completa con diagramas de arquitectura
- Análisis de rendimiento y optimización de operaciones criptográficas

## Entregables Requeridos

1. **Código fuente** de todas las implementaciones solicitadas
2. **Informe técnico** detallando vulnerabilidades encontradas y soluciones aplicadas
3. **Diagramas de arquitectura** para componentes de seguridad nuevos
4. **Suite de pruebas** automatizadas para validar medidas de seguridad
5. **Manual de deployment** con consideraciones de seguridad para producción

## Tiempo Estimado
- Parte 1: 2-3 horas
- Parte 2: 4-6 horas  
- Parte 3: 8-12 horas

## Recursos Permitidos
- Documentación oficial de Android
- OWASP Mobile Security Guidelines
- Libraries de seguridad open source
- Stack Overflow y comunidades técnicas

---

**Nota**: Esta evaluación requiere conocimientos sólidos en seguridad móvil, criptografía aplicada y arquitecturas Android modernas. Se valorará especialmente la capacidad de aplicar principios de security-by-design y el pensamiento crítico en la identificación de vectores de ataque.
