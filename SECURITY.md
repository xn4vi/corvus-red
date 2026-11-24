# Seguridad y uso responsable

## Uso autorizado únicamente

CORVUS Red está pensada **exclusivamente** para auditorías con autorización escrita, laboratorios propios, programas de bug bounty (dentro de sus reglas) y formación. La skill se niega a enviar tráfico sin un alcance con la autorización confirmada, pero la responsabilidad legal es siempre de quien la usa. En España, el acceso no autorizado a sistemas puede constituir delito (por ejemplo, artículos 197 bis y 264 del Código Penal); en otros países hay normas equivalentes.

## Datos de clientes

- La carpeta `engagements/` está en `.gitignore`: **nunca** subas evidencias, registros ni informes reales a un repositorio.
- `corvus.py redact` y `corvus.py http --save` tachan credenciales y tokens, pero revisa siempre la evidencia antes de entregarla.

## Informar de un problema de seguridad en la skill

Si encuentras un fallo en la propia skill (por ejemplo, una fuga de secretos en la evidencia, o una forma de saltarse la comprobación de alcance), **no abras un issue público**. Usa los [avisos de seguridad privados de GitHub](../../security/advisories/new) del repositorio.
