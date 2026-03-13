# T2
## Descripción del proyecto 
Este proyecto es una herramienta de seguridad desarrollada en C++ para sistemas Linux y tiene como objetivo monitorear la integridad de la red local mediante dos vías: la vigilancia de la identidad digital (cambios en IP/MAC) y la detección de tráfico anómalo mediante un sniffer de sockets crudos (raw sockets).  
La herramienta genera un registro estructurado en formato JSON con todos los eventos y alertas detectadas.  

## Integrantes y módulos
Jair Gonzalo Cortés Romero  
Implementación del motor de captura (Sniffer), manejo de sockets y concurrencia.  

Estefani Jazmín Meléndez Magallanes   
Desarrollo del módulo de monitoreo de identidad (NetMonitor), lógica de detección de anomalías y documentación.  

## Pasos de compilación y ejecución 
-SO: Ubuntu / Debian   
-Compilador: g++ con soporte para C++11 o superior.  
-Librerías: nlohmann/json (para la gestión de reportes JSON) y pthread (para el manejo de hilos/concurrencia).  

1.-Instalar dependencias: sudo apt-get install nlohmann-json3-dev  
2.-Para compilar todos los módulos, utiliza el siguiente comando: g++ main.cpp logger.cpp net_monitor.cpp sniffer.cpp -o monitor -pthread  
3.-Debido a que el programa utiliza RAW sockets para capturar tráfico de red, es necesario ejecutarlo con privilegios de superusuario con sudo ./monitor  
4.-El programa solicitará el nombre de la interfaz (ej. eth0 o wlan0), el intervalo de monitoreo y los bytes a capturar.  

## Enfoque técnico
- Uso de getifaddrs y archivos de sistema en /sys/class/net/ para obtener IP y MAC en tiempo real.
- Sniffing: Captura de paquetes mediante sockets de bajo nivel (AF_PACKET) permitiendo analizar tráfico ARP y TCP a nivel de cabeceras.  
- Implementación de hilos (std::thread) para permitir que el sniffer y el monitor de identidad funcionen simultáneamente sin bloquearse.  
- Clase JSONLogger con uso de std::mutex para garantizar que la escritura en el archivo logs.json sea segura entre diferentes hilos.  

## Criterios de anomalías 
Para que el programa no lance alertas por cualquier cosa, decidimos basarnos en la frecuencia de los eventos, es decir, si algo pasa demasiadas veces en muy poco tiempo, el sistema lo marca como sospechoso:
- Escaneo ARP: Como el tráfico ARP suele ser bajo, configuramos el sniffer para que si detecta más de 20 paquetes de una misma fuente, dispare la alerta arp_scan y esto es clave para notar cuando alguien está mapeando la red para ver quién está conectado.  
- Saltos de IP: No es normal que una compu cambie de IP a cada rato, si el monitor detecta más de 10 cambios en un intervalo corto, genera la alerta excessive_ip_changes, lo que nos ayuda a ver si hay inestabilidad o algún intento de manipulación de identidad.  
- Escaneo de puertos: Si vemos que una IP externa intenta tocar la puerta en más de 10 puertos diferentes (vía TCP SYN), el código lo registra como un escaneo de puertos, que es el paso típico para buscar vulnerabilidades.  
