# 🛡Another Process Hollowing

Explicación y prueba de concepto (POC) de la técnica Process Hollowing (Windows), comúnmente utilizada por malware para evadir sistemas de seguridad
<p align="center">
  <a href="README_ES.md">Readme Español</a> |
  <a href="README.md">Readme English</a>
</p>

## 🔍 ¿Qué es Process Hollowing?
Process Hollowing es una **técnica de evasión** sofisticada ampliamente utilizada por malware moderno para:
- Ejecutar código malicioso bajo la apariencia de procesos legítimos
- Evadir sistemas de detección y prevención de intrusiones
- Mantener persistencia en sistemas comprometidos
  
> 💡 **En esencia**: se crea un proceso legítimo en estado suspendido, su contenido en memoria es vaciado y reemplazado por código malicioso. Cuando el proceso se reanuda, el código malicioso se ejecuta con los privilegios y la apariencia del proceso original.

## ⚠️ Solo para Fines Educativos
Este repositorio contiene:
- **Explicación detallada** de la técnica Process Hollowing (en inglés y español)
- **Código fuente completo** para una Prueba de Concepto (PoC)
  
## 🔧 Cómo Funciona
La técnica se divide en varios pasos críticos:
1. **Creación**: Un proceso legítimo (como notepad.exe) se crea en estado suspendido
2. **Desmontaje**: Se obtiene y desasocia el PEB (Bloque de Entorno del Proceso)
3. **Vaciado**: Se libera la memoria del proceso original
4. **Inyección**: Se escribe código malicioso en el espacio de memoria liberado
5. **Reconstrucción**: Se reconfigura el punto de entrada y se restaura el contexto
6. **Ejecución**: El proceso se reanuda, ahora ejecutando el código malicioso

Una explicacion completa esta disponible en <p align="center">
  <a href="docs/technique_ES.md">Español</a> |
  <a href="docs/technique_EN.md">English</a>
</p>


## 📚 Aplicaciones en Ciberseguridad
- **Investigación de malware**: Entender cómo operan las amenazas avanzadas
- **Pruebas de penetración**: Evaluar defensas contra técnicas de evasión
- **Desarrollo de defensas**: Crear sistemas de detección para esta técnica
  
## 🧩 Estructura del Repositorio
```
AnotherProcessHollowing/
├── src/
│   ├── main.cpp           # Código Fuente
├── docs/                  
│   ├── technique_ES.md    # Explicación detallada en español
│   └── technique_EN.md    # Explicación detallada en inglés
├── README.md              # README en inglés
└── README_ES.md           # README en español
```
