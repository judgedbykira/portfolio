# Writeup: AguaDeMayo


# AguaDeMayo - Write-Up

## Enumeration

>To begin with, we must ping the machine to verify if it is powered on and to possibly deduce its OS using the TTL received, in this case the victim machine is Linux due to its TTL similar to 64:

```bash
ping -c 3 172.17.0.2
```
| Parámetro:    | Utilidad:                                           |
| ------------ | -------------------------------------------------- |
| -c           | Permite elegir la cantidad de solicitudes ICMP Echo Requests que serán enviadas.  |

![Pasted image 20240807151802](https://github.com/user-attachments/assets/da5393ad-d932-4746-8ccb-784e54860410)

>Once this is done, it is time to perform a port scan using the nmap utility. To do this, we will start by analyzing the TCP ports of the victim machine:

```bash
nmap -p- --open -sS -vvv -Pn -n --min-rate 5000 172.17.0.2
```

| Parámetro:    | Utilidad:                                           |
| ------------ | -------------------------------------------------- |
| -p-           | Escanear todos los puertos de la máquina (65535).  |
| --open   | Mostrar en el resultado solo los puertos abiertos.               |
| --min-rate | Solo enviar paquetes que vayan a una velocidad de x paquetes por segundo. | 
|-sS | Realizar un stealth scan que no concluye el three-way handshake del protocolo TCP enviando un RST en lugar de un ACK. (Agiliza el escaneo)
-vvv | Muestra muy detalladamente el resultado del comando.
-Pn | Dejamos de usar el protocolo de resolución de direcciones ARP para el escaneo. (Agiliza el escaneo)
-n | Dejamos de usar el servicio DNS para resolver la dirección. (Agiliza el escaneo)

>Here we can see two interesting ports that can serve as an input vector in the victim machine, the 22 corresponding to the SSH service and the 80 corresponding to the HTTP service.

![Pasted image 20240807151856](https://github.com/user-attachments/assets/5cd135d2-f199-4fba-84d2-0b51c0797e3b)


>Now we could perform a version scan and with recognition scripts to get interesting information about the services running on both open ports:

```bash
nmap -p22,80 -sCV -Pn -n -vvv 172.17.0.2
```

| Parámetro:    | Utilidad:                                           |
| ------------ | -------------------------------------------------- |
| -px           | Escanea solo los puertos o el rango especificado en lugar de la x.  |
| -sCV   | Realizar un escaneo de versión y usar scripts de reconocimiento propios de la utilidad.               |

![Pasted image 20240807152154](https://github.com/user-attachments/assets/b6fd27b7-47c5-41f4-9645-9cbe9d1085b5)


>Through the SSH service version we could obtain information about the OS of the victim machine. The machine is using a Linux distribution called Debian.

>On the other hand, since there is an HTTP service, we will try to fuzz to detect possible directories within the victim machine by brute force using a dictionary with the help of the gobuster tool:

```bash
gobuster dir -u http://172.17.0.2 -t 40 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
```

| Parámetro:    | Utilidad:                                           |
| ------------ | -------------------------------------------------- |
| dir           | Permite fuzzear directorios.  |
-u | Permite especificar la URL en la que se realizará el fuzzing.
-t | Permite fijar la cantidad de hilos empleados para el proceso de fuzzing.
-w | Permite especificar el diccionario que se empleará para el fuzzing.

![Pasted image 20240807152658](https://github.com/user-attachments/assets/04e07eaa-02c5-4810-b1b8-52a5090182e6)


>Here we can highlight that there is a directory called images but before that we will access the main page:

![Pasted image 20240807152751](https://github.com/user-attachments/assets/97496a1b-983b-421a-b1d7-6f0ecc16c6e2)


>Here we can see that it uses the index.html by default of apache2 but if we review its source code we can find a hidden comment that contains a string encoded in Brainfuck:

![Pasted image 20240807152917](https://github.com/user-attachments/assets/2f13e31b-ffd2-457d-92ab-f07d7dc9e392)


>If we try to decode it using a web tool we can get the following message:

![Pasted image 20240807152957](https://github.com/user-attachments/assets/96fd71c0-a2ef-4b4f-ae74-052a5e1c7f7c)


>This string could correspond to a credential or user of the other running service, which we remember was the SSH.

>Now let's try to see what content is in the images directory:

![Pasted image 20240807153118](https://github.com/user-attachments/assets/403bc567-e607-47ee-9222-2d2ca4be6a94)


>Here we can see an image called **agua_ssh** which can contrast our assumption about the previously decoded message, so we will try to enter the machine through SSH using **agua** and password **bebeaguaqueessano** as user.

![Pasted image 20240807153347](https://github.com/user-attachments/assets/cfd1dc0b-ba07-4fbd-a519-48b33a5a5a8e)


>And as simple as that, we would already be inside the victim machine. Now we would have to escalate privileges to become the root user of the system.

## Escalada de privilegios

>Let's try to see what sudo permissions we have as 'agua' user:

```bash
sudo -l
```

| Parámetro:    | Utilidad:                                           |
| ------------ | -------------------------------------------------- |
| -l           | Permite ver los permisos de sudo que tiene el usuario que lo lanza.  |

>As we can see, we can use the bettercap command without providing a password:

![Pasted image 20240807153659](https://github.com/user-attachments/assets/b8720bef-c4ed-4693-bd10-c76b5931bd80)


>Using the bettercap binary we can execute commands by starting them with a "!", this taking into account that the binary is being executed as root, will allow us to execute code as if we were root:

```bash
sudo /usr/bin/bettercap
!whoami
```

![Pasted image 20240807154216](https://github.com/user-attachments/assets/0434dcb7-ddbf-4026-9c30-be7e2cb1b435)


>We can see that when using the whoami command the program returns root, so we will change the bash permissions to be SUID and be able to give us a privileged bash:

```bash
!chmod +s /bin/bash
```

| Parámetro:    | Utilidad:                                           |
| ------------ | -------------------------------------------------- |
| +s           | Permite agregar el permiso SUID al binario. (4000)  |

>Once this is done, it will be enough to spawn a privileged bash through the following command and we will have completely committed the machine becoming the root user thanks to the SUID permission that we have added to the bash:

```bash
bash -p
```

| Parámetro:    | Utilidad:                                           |
| ------------ | -------------------------------------------------- |
| -p           | Lanza una bash de forma privilegiada.  |

![Pasted image 20240807154525](https://github.com/user-attachments/assets/2c0bed01-ca2e-42c6-9dab-e8534554fd49)

