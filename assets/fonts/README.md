# Tipografías del informe (opcional)

`corvus.py report` incrusta en el HTML y el PDF todos los ficheros `.woff2` de esta carpeta, así que el informe se ve igual en cualquier equipo. **Ya vienen incluidas** las fuentes de la marca (subconjunto latino de Google Fonts, unos 118 KB). Sus licencias están en `licenses/`.

La marca por defecto usa (todas con licencia SIL Open Font License, que permite incrustarlas):

| Uso (`brand.json` → `tipografias`) | Familia | Nombre de fichero sugerido |
|---|---|---|
| `texto` | Inter | `Inter[wght].woff2` |
| `titulos` | Mona Sans | `MonaSans[wght].woff2` |
| `tecnica` | Chakra Petch | `ChakraPetch-SemiBold.woff2`, `ChakraPetch-Bold.woff2` |

La familia se toma del nombre del fichero (`MonaSans` → «Mona Sans») y el peso, de su sufijo (`-SemiBold` → 600; `[wght]` o `Variable` → 100–900). Sin ficheros aquí, el informe usa las fuentes instaladas o Segoe UI.
