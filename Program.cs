using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

class AntiDDoS
{
    private static string localIP;
    private static List<string> whitelistedIPs = new List<string>();
    private static List<int> ports = new List<int>();
    private static int requestLimit = 50;
    private static int interval = 5;
    private static Dictionary<string, Dictionary<int, List<DateTime>>> requestLog = new Dictionary<string, Dictionary<int, List<DateTime>>>();
    private static HashSet<string> blockedIPs = new HashSet<string>();
    private static string logFile = "ddos_log.txt";

    // Variables adicionales para la detección específica del Point Blank Socket
    private static Dictionary<string, List<byte[]>> packetSignatures = new Dictionary<string, List<byte[]>>();
    private static Dictionary<string, int> emptyPacketCounter = new Dictionary<string, int>();
    private static Dictionary<string, int> tcpConnectionAttempts = new Dictionary<string, int>();
    private static Dictionary<string, DateTime> lastTcpConnectionTime = new Dictionary<string, DateTime>();
    private static int tcpConnectionThreshold = 10; // Umbral para conexiones TCP rápidas
    private static int tcpConnectionInterval = 2; // Intervalo en segundos para considerar conexiones sospechosas
    private static int emptyPacketThreshold = 5; // Umbral para paquetes vacíos consecutivos

    static void Main()
    {
        LoadConfig();

        // Añadir automáticamente la IP local a la lista blanca
        AddLocalIPsToWhitelist();

        Console.WriteLine("Anti-DDoS mejorado iniciado... Escaneando tráfico en " + localIP);
        Console.WriteLine($"IPs en lista blanca: {string.Join(", ", whitelistedIPs)}");
        Console.WriteLine($"Configuración: Límite={requestLimit} peticiones en {interval} segundos");
        Console.WriteLine($"Protección específica contra Point Blank Socket activada");

        // Iniciar logs
        File.AppendAllText(logFile, $"[{DateTime.Now}] Sistema Anti-DDoS mejorado iniciado. Monitoreando IP: {localIP} Puertos: {string.Join(",", ports)}\n");
        File.AppendAllText(logFile, $"[{DateTime.Now}] Lista blanca: {string.Join(", ", whitelistedIPs)}\n");
        File.AppendAllText(logFile, $"[{DateTime.Now}] Protección específica contra Point Blank Socket activada\n");

        // Iniciar hilo para mostrar estadísticas cada minuto
        Thread statsThread = new Thread(ShowStatistics);
        statsThread.Start();

        // Iniciar monitoreo del tráfico
        Thread monitorThread = new Thread(MonitorTraffic);
        monitorThread.Start();

        // Iniciar monitoreo de firewalls
        Thread firewallThread = new Thread(MonitorFirewallRules);
        firewallThread.Start();
    }

    private static void AddLocalIPsToWhitelist()
    {
        try
        {
            // Añadir la IP especificada en la configuración
            if (!whitelistedIPs.Contains(localIP))
                whitelistedIPs.Add(localIP);

            // Obtener todas las IPs locales del equipo
            string hostName = Dns.GetHostName();
            IPHostEntry hostEntry = Dns.GetHostEntry(hostName);

            foreach (IPAddress address in hostEntry.AddressList)
            {
                if (address.AddressFamily == AddressFamily.InterNetwork) // Solo IPv4
                {
                    string ip = address.ToString();
                    if (!whitelistedIPs.Contains(ip))
                    {
                        whitelistedIPs.Add(ip);
                        Console.WriteLine($"IP local detectada y añadida a la lista blanca: {ip}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error al añadir IPs locales a la lista blanca: {ex.Message}");
        }
    }

    private static void LoadConfig()
    {
        try
        {
            if (!File.Exists("config.ini"))
            {
                // Crear archivo de configuración con valores predeterminados actualizados
                string defaultConfig =
                    "LocalIP=127.0.0.1\n" +
                    "Ports=80,443,8080\n" +
                    "RequestLimit=50\n" +
                    "Interval=5\n" +
                    "Whitelist=192.168.1.1,127.0.0.1\n" +
                    "TCPConnectionThreshold=10\n" +  // Nuevo umbral para conexiones TCP
                    "TCPConnectionInterval=2\n" +    // Nuevo intervalo para conexiones TCP
                    "EmptyPacketThreshold=5";        // Nuevo umbral para paquetes vacíos
                File.WriteAllText("config.ini", defaultConfig);
                Console.WriteLine("Archivo de configuración creado con valores predeterminados.");
            }

            string[] lines = File.ReadAllLines("config.ini");
            foreach (string line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                    continue;

                string[] parts = line.Split('=');
                if (parts.Length != 2)
                    continue;

                string key = parts[0].Trim();
                string value = parts[1].Trim();

                switch (key)
                {
                    case "LocalIP":
                        localIP = value;
                        break;
                    case "Ports":
                        ports.Clear();
                        string[] portStrings = value.Split(',');
                        foreach (string port in portStrings)
                            if (int.TryParse(port.Trim(), out int portNum))
                                ports.Add(portNum);
                        break;
                    case "RequestLimit":
                        int.TryParse(value, out requestLimit);
                        break;
                    case "Interval":
                        int.TryParse(value, out interval);
                        break;
                    case "Whitelist":
                        string[] ips = value.Split(',');
                        foreach (string ip in ips)
                        {
                            string trimmedIP = ip.Trim();
                            if (!string.IsNullOrEmpty(trimmedIP) && !whitelistedIPs.Contains(trimmedIP))
                                whitelistedIPs.Add(trimmedIP);
                        }
                        break;
                    case "TCPConnectionThreshold":
                        int.TryParse(value, out tcpConnectionThreshold);
                        break;
                    case "TCPConnectionInterval":
                        int.TryParse(value, out tcpConnectionInterval);
                        break;
                    case "EmptyPacketThreshold":
                        int.TryParse(value, out emptyPacketThreshold);
                        break;
                }
            }

            // Validar configuración
            if (string.IsNullOrEmpty(localIP) || !IPAddress.TryParse(localIP, out _))
                throw new Exception("IP local inválida en config.ini");
            if (ports.Count == 0)
                throw new Exception("No se especificaron puertos válidos en config.ini");
            if (requestLimit <= 0)
                requestLimit = 50;
            if (interval <= 0)
                interval = 5;
            if (tcpConnectionThreshold <= 0)
                tcpConnectionThreshold = 10;
            if (tcpConnectionInterval <= 0)
                tcpConnectionInterval = 2;
            if (emptyPacketThreshold <= 0)
                emptyPacketThreshold = 5;

            Console.WriteLine($"Configuración cargada: IP={localIP} \nPuertos={string.Join(",", ports)} \nLímite={requestLimit} Intervalo={interval} seg.");
            Console.WriteLine($"Límites Point Blank: TCP={tcpConnectionThreshold}/{tcpConnectionInterval}s Paquetes vacíos={emptyPacketThreshold}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error al cargar la configuración: {ex.Message}");
            Environment.Exit(1);
        }
    }

    private static void MonitorTraffic()
    {
        try
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            socket.Bind(new IPEndPoint(IPAddress.Parse(localIP), 0));
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

            // Esto es crucial para capturar todo el tráfico IP
            byte[] inBytes = new byte[] { 1, 0, 0, 0 };
            byte[] outBytes = new byte[] { 0, 0, 0, 0 };
            socket.IOControl(IOControlCode.ReceiveAll, inBytes, outBytes);

            byte[] buffer = new byte[65536];

            while (true)
            {
                try
                {
                    int received = socket.Receive(buffer);

                    if (received > 20) // Asegurarse de que hay suficientes bytes para ser un paquete IP
                    {
                        // Extraer información del encabezado IP
                        int headerLength = (buffer[0] & 0x0F) * 4;
                        string protocol = buffer[9].ToString();
                        string sourceIP = $"{buffer[12]}.{buffer[13]}.{buffer[14]}.{buffer[15]}";
                        string destIP = $"{buffer[16]}.{buffer[17]}.{buffer[18]}.{buffer[19]}";

                        // Verificar si la IP de origen está en la lista blanca
                        if (whitelistedIPs.Contains(sourceIP))
                            continue; // Ignorar paquetes de IPs en lista blanca

                        // Verificar si ya está bloqueada
                        if (blockedIPs.Contains(sourceIP))
                            continue; // Ignorar paquetes de IPs ya bloqueadas

                        // Verificar si es TCP (protocolo 6) o UDP (protocolo 17)
                        if ((protocol == "6" || protocol == "17") && received >= headerLength + 4) // TCP o UDP
                        {
                            int sourcePort = (buffer[headerLength] << 8) + buffer[headerLength + 1];
                            int destPort = (buffer[headerLength + 2] << 8) + buffer[headerLength + 3];

                            // Solo procesamos paquetes dirigidos a los puertos que estamos monitoreando
                            if (ports.Contains(destPort) && destIP == localIP)
                            {
                                // Procesamiento general de peticiones
                                ProcessRequest(sourceIP, destPort, DateTime.Now);

                                // Procesamiento específico para detectar Point Blank Socket
                                if (protocol == "6") // TCP
                                {
                                    DetectPointBlankTCPAttack(sourceIP, buffer, received, headerLength);
                                }
                                else if (protocol == "17") // UDP
                                {
                                    DetectPointBlankUDPAttack(sourceIP, buffer, received, headerLength);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error al procesar paquete: {ex.Message}");
                    // Continuamos monitoreando aunque haya errores en algunos paquetes
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error grave en el monitoreo de tráfico: {ex.Message}");
            File.AppendAllText(logFile, $"[{DateTime.Now}] ERROR GRAVE: {ex.Message}\n{ex.StackTrace}\n");

            // Esperar 5 segundos antes de reintentar
            Thread.Sleep(5000);
            MonitorTraffic(); // Reiniciar el monitoreo
        }
    }

    private static void DetectPointBlankTCPAttack(string sourceIP, byte[] buffer, int received, int headerLength)
    {
        lock (tcpConnectionAttempts)
        {
            DateTime now = DateTime.Now;

            // Inicializar contador si es necesario
            if (!tcpConnectionAttempts.ContainsKey(sourceIP))
            {
                tcpConnectionAttempts[sourceIP] = 0;
                lastTcpConnectionTime[sourceIP] = now;
            }

            // Detectar conexiones vacías o con pocos datos (característica de Point Blank)
            bool isEmptyOrSmallTCPPacket = false;
            int tcpHeaderLength = 0;

            if (received > headerLength + 20) // IP header + TCP header
            {
                tcpHeaderLength = ((buffer[headerLength + 12] >> 4) & 0xF) * 4;
                int dataSize = received - (headerLength + tcpHeaderLength);
                isEmptyOrSmallTCPPacket = dataSize <= 1; // Point Blank suele enviar paquetes TCP vacíos o muy pequeños

                // Actualizar contador de paquetes vacíos
                if (isEmptyOrSmallTCPPacket)
                {
                    if (!emptyPacketCounter.ContainsKey(sourceIP))
                        emptyPacketCounter[sourceIP] = 0;

                    emptyPacketCounter[sourceIP]++;

                    // Si se supera el umbral de paquetes vacíos, bloquear
                    if (emptyPacketCounter[sourceIP] >= emptyPacketThreshold)
                    {
                        Console.WriteLine($"ALERTA: Detección de paquetes TCP vacíos característicos de Point Blank desde {sourceIP}");
                        File.AppendAllText(logFile, $"[{now}] ALERTA: Paquetes TCP vacíos típicos de Point Blank desde {sourceIP}: {emptyPacketCounter[sourceIP]} consecutivos\n");
                        BlockIP(sourceIP, 0, emptyPacketCounter[sourceIP], now, "Paquetes TCP vacíos (Point Blank Socket)");
                        return;
                    }
                }
                else
                {
                    // Reiniciar contador si no es un paquete vacío
                    emptyPacketCounter.Remove(sourceIP);
                }
            }

            // Calcular tiempo desde la última conexión
            TimeSpan elapsed = now - lastTcpConnectionTime[sourceIP];

            // Si han pasado más de X segundos, reiniciar el contador
            if (elapsed.TotalSeconds > tcpConnectionInterval)
            {
                tcpConnectionAttempts[sourceIP] = 1;
                lastTcpConnectionTime[sourceIP] = now;
            }
            else
            {
                // Incrementar contador y actualizar tiempo
                tcpConnectionAttempts[sourceIP]++;
                lastTcpConnectionTime[sourceIP] = now;

                // Verificar si supera el umbral
                if (tcpConnectionAttempts[sourceIP] >= tcpConnectionThreshold)
                {
                    Console.WriteLine($"ALERTA: Detección de patrón de conexiones TCP rápidas desde {sourceIP} ({tcpConnectionAttempts[sourceIP]} en {elapsed.TotalSeconds:F1}s)");
                    File.AppendAllText(logFile, $"[{now}] ALERTA: Patrón de conexiones TCP rápidas desde {sourceIP}: {tcpConnectionAttempts[sourceIP]} conexiones en {elapsed.TotalSeconds:F1}s\n");
                    BlockIP(sourceIP, 0, tcpConnectionAttempts[sourceIP], now, "Conexiones TCP rápidas (Point Blank Socket)");
                }
            }
        }
    }

    private static void DetectPointBlankUDPAttack(string sourceIP, byte[] buffer, int received, int headerLength)
    {
        // Verificar paquetes UDP específicos que podrían ser de Point Blank Socket
        DateTime now = DateTime.Now;

        // Analizar tamaño y contenido del paquete UDP
        int udpLength = received - headerLength;
        bool isPointBlankSignature = false;

        if (udpLength > 8) // UDP header es 8 bytes
        {
            // Extraer datos del paquete
            byte[] packetData = new byte[udpLength - 8];
            Array.Copy(buffer, headerLength + 8, packetData, 0, udpLength - 8);

            // Registrar firma del paquete para análisis
            if (!packetSignatures.ContainsKey(sourceIP))
                packetSignatures[sourceIP] = new List<byte[]>();

            packetSignatures[sourceIP].Add(packetData);

            // Mantener solo las últimas 10 firmas
            if (packetSignatures[sourceIP].Count > 10)
                packetSignatures[sourceIP].RemoveAt(0);

            // Verificar firmas de Point Blank Socket
            // Point Blank suele enviar paquetes con ciertos patrones o vacíos
            if (IsPointBlankUDPSignature(packetData))
            {
                Console.WriteLine($"ALERTA: Detección de firma UDP específica de Point Blank desde {sourceIP}");
                File.AppendAllText(logFile, $"[{now}] ALERTA: Firma UDP de Point Blank detectada desde {sourceIP}\n");
                BlockIP(sourceIP, 0, 1, now, "Firma UDP (Point Blank Socket)");
            }

            // Analizar patrones en secuencias de paquetes (más de 3 paquetes similares consecutivos)
            if (packetSignatures[sourceIP].Count >= 3 && AreConsecutiveUDPPacketsSimilar(packetSignatures[sourceIP]))
            {
                Console.WriteLine($"ALERTA: Detección de patrón de paquetes UDP similares desde {sourceIP}");
                File.AppendAllText(logFile, $"[{now}] ALERTA: Patrón de paquetes UDP similares desde {sourceIP} - posible Point Blank Socket\n");
                BlockIP(sourceIP, 0, packetSignatures[sourceIP].Count, now, "Paquetes UDP similares consecutivos (Point Blank Socket)");
            }
        }
    }

    private static bool IsPointBlankUDPSignature(byte[] packetData)
    {
        // Point Blank Socket suele enviar paquetes UDP con ciertas características
        // 1. Paquetes completamente vacíos
        if (packetData.Length == 0)
            return true;

        // 2. Paquetes con todo valores cero o valores constantes
        if (packetData.Length > 0)
        {
            bool allSame = true;
            byte firstByte = packetData[0];

            for (int i = 1; i < packetData.Length; i++)
            {
                if (packetData[i] != firstByte)
                {
                    allSame = false;
                    break;
                }
            }

            if (allSame)
                return true;
        }

        // 3. Buscar patrones específicos de las firmas conocidas de Point Blank
        // Esto podría mejorarse con un análisis más detallado de las firmas de Point Blank

        return false;
    }

    private static bool AreConsecutiveUDPPacketsSimilar(List<byte[]> packets)
    {
        // Verificar si los últimos paquetes son muy similares (señal de un ataque automatizado)
        if (packets.Count < 3)
            return false;

        byte[] packet1 = packets[packets.Count - 1];
        byte[] packet2 = packets[packets.Count - 2];
        byte[] packet3 = packets[packets.Count - 3];

        // Verificar si tienen el mismo tamaño
        if (packet1.Length != packet2.Length || packet2.Length != packet3.Length)
            return false;

        // Si los paquetes son muy pequeños y del mismo tamaño, es sospechoso
        if (packet1.Length < 10)
            return true;

        // Contar bytes idénticos entre paquetes
        int similarBytes12 = 0;
        int similarBytes23 = 0;

        for (int i = 0; i < packet1.Length; i++)
        {
            if (packet1[i] == packet2[i])
                similarBytes12++;

            if (packet2[i] == packet3[i])
                similarBytes23++;
        }

        // Calcular porcentaje de similitud
        double similarityPercentage12 = (double)similarBytes12 / packet1.Length * 100;
        double similarityPercentage23 = (double)similarBytes23 / packet2.Length * 100;

        // Si la similitud es alta (más del 90%), probablemente es un ataque automatizado
        return similarityPercentage12 > 90 && similarityPercentage23 > 90;
    }

    private static void ProcessRequest(string ip, int port, DateTime timestamp)
    {
        // Verificación adicional para asegurarse de que no procesamos IPs en lista blanca
        if (blockedIPs.Contains(ip) || whitelistedIPs.Contains(ip))
            return;

        lock (requestLog)
        {
            // Inicializar estructura de datos si es la primera vez que vemos esta IP
            if (!requestLog.ContainsKey(ip))
                requestLog[ip] = new Dictionary<int, List<DateTime>>();

            // Inicializar lista de tiempos para este puerto si es necesario
            if (!requestLog[ip].ContainsKey(port))
                requestLog[ip][port] = new List<DateTime>();

            // Registrar la petición con su timestamp
            requestLog[ip][port].Add(timestamp);

            // Eliminar registros viejos para este puerto
            requestLog[ip][port].RemoveAll(time => (timestamp - time).TotalSeconds > interval);

            // Contar peticiones por puerto
            int requestCountForPort = requestLog[ip][port].Count;

            // Calcular total de peticiones para todos los puertos
            int totalRequests = requestLog[ip].Values.Sum(list => list.Count);

            // Mostrar la actividad de la IP en la consola
            Console.WriteLine($"[{timestamp:HH:mm:ss}] Detección: IP={ip} | Puerto={port} | Peticiones en puerto {port}: {requestCountForPort}/{requestLimit}");

            // Determinar si hay un ataque específico en este puerto
            bool isPortUnderAttack = requestCountForPort > requestLimit;
            bool isIPUnderAttack = totalRequests > requestLimit * 2; // Ataque distribuido en varios puertos

            // Log más detallado
            if (requestCountForPort > requestLimit * 0.5)
            {
                File.AppendAllText(logFile, $"[{timestamp}] Actividad sospechosa: IP={ip} | Puerto={port} | Peticiones={requestCountForPort}/{requestLimit}\n");
            }

            // Si hay un ataque específico en este puerto
            if (isPortUnderAttack)
            {
                Console.WriteLine($"ALERTA: Posible ataque detectado en puerto {port} desde IP {ip} ({requestCountForPort} peticiones)");
                File.AppendAllText(logFile, $"[{timestamp}] ALERTA: Puerto {port} bajo ataque desde IP {ip} | {requestCountForPort} peticiones\n");
                BlockIP(ip, port, requestCountForPort, timestamp, "Ataque de frecuencia por puerto");
            }
            // Si hay un ataque distribuido en varios puertos
            else if (isIPUnderAttack)
            {
                Console.WriteLine($"ALERTA: Posible ataque distribuido desde IP {ip} ({totalRequests} peticiones totales)");

                // Identificar el puerto más atacado
                var mostAttackedPort = requestLog[ip]
                    .OrderByDescending(kv => kv.Value.Count)
                    .First();

                Console.WriteLine($"   Puerto más atacado: {mostAttackedPort.Key} con {mostAttackedPort.Value.Count} peticiones");

                File.AppendAllText(logFile, $"[{timestamp}] ALERTA: Ataque distribuido desde IP {ip} | Total: {totalRequests} peticiones | " +
                                          $"Puerto principal: {mostAttackedPort.Key} ({mostAttackedPort.Value.Count} peticiones)\n");

                BlockIP(ip, mostAttackedPort.Key, totalRequests, timestamp, "Ataque distribuido");
            }
        }
    }

    private static void BlockIP(string ip, int attackedPort, int attempts, DateTime timestamp, string attackType = "")
    {
        // Verificación final para no bloquear IPs en lista blanca
        if (blockedIPs.Contains(ip) || whitelistedIPs.Contains(ip))
            return;

        blockedIPs.Add(ip);
        Console.WriteLine($"IP BLOQUEADA: {ip} | Tipo: {attackType} | Puerto: {attackedPort} | Intentos: {attempts} | Hora: {timestamp:HH:mm:ss}");

        StringBuilder attackDetails = new StringBuilder();
        attackDetails.AppendLine($"[{timestamp}] BLOQUEO: IP={ip} | Tipo={attackType} | Puerto={attackedPort} | Intentos={attempts}");

        // Registrar estadísticas detalladas por puerto si tenemos datos
        if (requestLog.ContainsKey(ip))
        {
            attackDetails.AppendLine("Detalles del ataque por puerto:");
            foreach (var portData in requestLog[ip].OrderByDescending(p => p.Value.Count))
            {
                attackDetails.AppendLine($"- Puerto {portData.Key}: {portData.Value.Count} peticiones");
            }
        }

        File.AppendAllText(logFile, attackDetails.ToString());

        try
        {
            // Comprobar si la IP ya está bloqueada
            Process process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd",
                    Arguments = $"/c netsh advfirewall firewall show rule name=\"Block {ip}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            if (output.Contains("No rules match"))
            {
                // Solo agregar la regla si no existe
                Process blockProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "cmd",
                        Arguments = $"/c netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip} description=\"Bloqueado por AntiDDoS - {attackType} - {timestamp}\"",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                blockProcess.Start();
                string blockOutput = blockProcess.StandardOutput.ReadToEnd();
                blockProcess.WaitForExit();

                if (blockProcess.ExitCode == 0)
                {
                    Console.WriteLine($"IP {ip} bloqueada en el firewall de Windows.");
                    File.AppendAllText(logFile, $"[{timestamp}] Firewall: IP {ip} bloqueada correctamente (Tipo: {attackType})\n");
                }
                else
                {
                    Console.WriteLine($"Error al bloquear IP {ip} en el firewall: {blockOutput}");
                    File.AppendAllText(logFile, $"[{timestamp}] ERROR Firewall: No se pudo bloquear IP {ip}: {blockOutput}\n");
                }
            }
            else
            {
                Console.WriteLine($"IP {ip} ya estaba bloqueada en el firewall.");
                File.AppendAllText(logFile, $"[{timestamp}] Firewall: IP {ip} ya estaba bloqueada\n");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error al bloquear IP: {ex.Message}");
            File.AppendAllText(logFile, $"[{timestamp}] ERROR al bloquear IP {ip}: {ex.Message}\n");
        }
    }

    private static void MonitorFirewallRules()
    {
        while (true)
        {
            try
            {
                // Revisar cada 5 minutos
                Thread.Sleep(300000);

                Console.WriteLine("\nVerificando reglas de firewall existentes...");

                // Obtener todas las reglas de firewall
                Process process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "cmd",
                        Arguments = "/c netsh advfirewall firewall show rule name=all dir=in | findstr /C:\"Block \"",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Analizar reglas existentes
                if (!string.IsNullOrEmpty(output))
                {
                    string[] rules = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    Console.WriteLine($"Reglas de firewall activas: {rules.Length}");

                    // Verificar si el número de reglas es excesivo (podría impactar el rendimiento)
                    if (rules.Length > 1000)
                    {
                        Console.WriteLine("ADVERTENCIA: Número elevado de reglas de firewall. Considere limpiar reglas antiguas.");
                        File.AppendAllText(logFile, $"[{DateTime.Now}] ADVERTENCIA: {rules.Length} reglas de firewall activas. Recomendable limpieza.\n");
                    }
                }
                else
                {
                    Console.WriteLine("No se encontraron reglas de firewall activas.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al monitorizar las reglas de firewall: {ex.Message}");
                File.AppendAllText(logFile, $"[{DateTime.Now}] ERROR: Monitorización de firewall: {ex.Message}\n");
            }
        }
    }

    private static void ShowStatistics()
    {
        while (true)
        {
            Thread.Sleep(60000); // Mostrar estadísticas cada minuto

            lock (requestLog)
            {
                Console.WriteLine("\n--------- ESTADÍSTICAS DE TRÁFICO ---------");
                Console.WriteLine($"Timestamp: {DateTime.Now}");
                Console.WriteLine($"IPs activas: {requestLog.Count}");
                Console.WriteLine($"IPs bloqueadas: {blockedIPs.Count}");
                Console.WriteLine($"IPs en lista blanca: {whitelistedIPs.Count}");

                if (requestLog.Count > 0)
                {
                    // Identificar puertos más activos en general
                    Dictionary<int, int> portActivityCount = new Dictionary<int, int>();
                    foreach (var ipData in requestLog)
                    {
                        foreach (var portData in ipData.Value)
                        {
                            if (!portActivityCount.ContainsKey(portData.Key))
                                portActivityCount[portData.Key] = 0;

                            portActivityCount[portData.Key] += portData.Value.Count;
                        }
                    }

                    if (portActivityCount.Count > 0)
                    {
                        Console.WriteLine("\nPuertos más activos:");
                        foreach (var port in portActivityCount.OrderByDescending(p => p.Value).Take(3))
                        {
                            Console.WriteLine($"- Puerto {port.Key}: {port.Value} peticiones totales");
                        }
                    }

                    // Mostrar las IPs más activas
                    Console.WriteLine("\nTop IPs más activas:");
                    var topIPs = requestLog
                        .Select(ip => new
                        {
                            IP = ip.Key,
                            TotalRequests = ip.Value.Sum(p => p.Value.Count),
                            MostActivePort = ip.Value.OrderByDescending(p => p.Value.Count).First().Key,
                            MostActivePortCount = ip.Value.OrderByDescending(p => p.Value.Count).First().Value.Count
                        })
                        .OrderByDescending(x => x.TotalRequests)
                        .Take(5);

                    foreach (var ip in topIPs)
                    {
                        Console.WriteLine($"- {ip.IP}: {ip.TotalRequests} peticiones totales");
                        Console.WriteLine($"  - Puerto más activo: {ip.MostActivePort} ({ip.MostActivePortCount} peticiones)");

                        // Mostrar distribución de puertos para esta IP
                        var portDistribution = requestLog[ip.IP]
                            .OrderByDescending(p => p.Value.Count)
                            .Take(3);

                        foreach (var port in portDistribution)
                        {
                            if (port.Key != ip.MostActivePort) // Evitar repetir el puerto más activo
                            {
                                Console.WriteLine($"  - Puerto {port.Key}: {port.Value.Count} peticiones");
                            }
                        }
                    }

                    // Estadísticas específicas de Point Blank
                    Console.WriteLine("\nDetección de Point Blank Socket:");
                    Console.WriteLine($"- IPs con patrones TCP sospechosos: {tcpConnectionAttempts.Count}");
                    if (tcpConnectionAttempts.Count > 0)
                    {
                        foreach (var entry in tcpConnectionAttempts.OrderByDescending(e => e.Value).Take(3))
                        {
                            Console.WriteLine($"  * {entry.Key}: {entry.Value} conexiones TCP rápidas");
                        }
                    }

                    Console.WriteLine($"- IPs con paquetes vacíos: {emptyPacketCounter.Count}");
                    if (emptyPacketCounter.Count > 0)
                    {
                        foreach (var entry in emptyPacketCounter.OrderByDescending(e => e.Value).Take(3))
                        {
                            Console.WriteLine($"  * {entry.Key}: {entry.Value} paquetes vacíos");
                        }
                    }
                }

                Console.WriteLine("------------------------------------------\n");
            }
        }
    }
}