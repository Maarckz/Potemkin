# Potemkin

Este é um script Python que simula serviços de porta aberta, gerando respostas falsas para várias portas TCP comuns, como FTP, SSH e HTTP. Além disso, monitora a atividade de conexão, bloqueando endereços IP que tentam se conectar com muita frequência. Requer privilégios de superusuário para interagir com o firewall do sistema operacional e realizar operações de bloqueio.

    Simulação de Serviços: Responde a solicitações de conexão em várias portas TCP comuns, fornecendo respostas falsas para simular serviços reais.
    Monitoramento de Atividade: Registra o número de solicitações de conexão de cada endereço IP e bloqueia endereços que fazem muitas solicitações em um curto período.
    Bloqueio de Endereços IP: Utiliza o firewall do sistema operacional para bloquear endereços IP que exibem comportamento suspeito.
