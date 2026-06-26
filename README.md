<div align="left">
  <a href="https://github.com/maarckz/Potemkin" target="_blank"><img height="260" width= "960" src="https://github.com/Maarckz/Maarckz/blob/main/Images/potemkin.png?raw=true"/> 
</div>


# Potemkin - Active Defense & Portscan Blocker

Potemkin é um serviço de **Defesa Ativa (Active Defense)** focado em proteger servidores de produção que rodam aplicações sensíveis. Em vez de ser usado puramente como honeypot para coleta de inteligência, o Potemkin age como um "campo minado" ao redor das suas aplicações reais.

Ele escuta em milhares de portas não utilizadas do seu servidor. Quando um atacante, script automatizado ou malware inicia um *portscan* para tentar descobrir onde estão os seus serviços reais (ex: uma porta SSH alterada, um painel administrativo oculto, bancos de dados), o Potemkin detecta a varredura instantaneamente e **bloqueia o atacante diretamente no firewall (`iptables`)** antes que ele consiga encontrar ou explorar seus serviços legítimos.

## Como Funciona?

1. **A Armadilha:** O Potemkin faz o bind em todas as portas não utilizadas do servidor simulando serviços (Tarpit). Suas portas reais (ex: 80, 443) são automaticamente puladas e continuam funcionando normalmente.
2. **Detecção por Janela Deslizante:** O tráfego é analisado em tempo real. Se um IP tocar em um número *X* de portas únicas dentro de *Y* segundos, ele é classificado como scanner.
3. **Bloqueio Ativo (Drop):** Ao detectar o scan, o Potemkin aciona um script privilegiado (`potemkin-firewall`) que insere uma regra de `DROP` no topo do `iptables` isolando o atacante.
4. **Escalonamento de Punição:** Infratores reincidentes recebem bloqueios progressivamente maiores (10 min -> 30 min -> 1 hora).
5. **Desbloqueio Automático:** Os bloqueios possuem tempo de vida e são removidos automaticamente para evitar travamentos acidentais permanentes.

## Principais Funcionalidades

* **Arquitetura Segura (Least Privilege):** O daemon principal roda sob um usuário sem privilégios. A manipulação do firewall é feita através de um script *helper* isolado, protegido com `chattr +i` e validado via `sudo` sem senha apenas para ações estritas.
* **Alta Performance:** Utiliza I/O multiplexing (`epoll`) em uma única thread. Consegue escutar em +65.000 portas consumindo pouquíssima CPU e Memória.
* **Integração Nativa com Wazuh (SIEM):** Gera logs estruturados em JSON direto para o `syslog`, facilitando a criação de *Active Responses* e Dashboards no Wazuh.
* **Proteção Anti-DoS Integrada:**
  * Limite restrito de IPs rastreados na memória (evita que um ataque DDoS esgote a RAM do servidor).
  * Rate-limiting dinâmico por conexões simultâneas.
  * Limite de bytes em *Echo/Chargen* para evitar amplificação (DDoS Reflection).
* **Engano Ativo (Tarpit):** Simula banners reais de serviços (SSH, Apache, MySQL, etc.) para atrasar ferramentas automatizadas como o Nmap.

## Instalação (Via Pacote Debian)

A forma recomendada e mais limpa de gerenciar o ciclo de vida do Potemkin no seu host é gerando o pacote `.deb`.

1. Compile o pacote Debian:
```bash
bash build_deb.sh
```

2. Instale usando o gerenciador de pacotes nativo:
```bash
sudo apt install ./build_deb/potemkin_3.0.0-1_all.deb
```

A instalação do pacote garante que o sistema implemente as seguintes diretrizes de segurança de forma automática:

* **Princípio do Menor Privilégio:** O serviço roda sob um usuário sem poderes (`potemkin`), com shell `/usr/sbin/nologin`.
* **Separação de Privilégios (Helper):** O potemkinnão roda como root, ele chama apenas um script específico (`potemkin-firewall`) através do `sudo` para manipular o iptables.
* **Imutabilidade anti-tampering:** O pacote aplica `chattr +i` no script do firewall e no arquivo sudoers. Se um invasor explorar uma vulnerabilidade no Python, ele não conseguirá alterar a lógica do firewall para executar comandos maliciosos como root.
* **Gerenciamento Resiliente:** Integração perfeita com `systemd` e `rsyslog`.

### Como Compilar / Criar nova versão

Se você fizer alterações no código fonte (ex: no `potemkin.py` ou `potemkin-firewall`) e quiser gerar uma atualização do pacote `.deb`:

1. Faça as suas alterações nos arquivos do projeto.
2. Abra o arquivo `build_deb.sh` e atualize a variável `VERSION=` no topo (ex: mude para `3.0.1`).
3. Rode o script de compilação:
```bash
bash build_deb.sh
```
4. Um novo arquivo `.deb` será gerado. Instale-o por cima da versão antiga para atualizar automaticamente o servidor:
```bash
sudo apt install ./build_deb/potemkin_3.0.1-1_all.deb
```

## Configuração

O arquivo principal fica em `/etc/potemkin/potemkin.conf`.
Você pode ajustar o nível de sensibilidade e o tempo de bloqueio:

```json
{
    "detection": {
        "threshold": 10,
        "window": 60,
        "ban_duration": 600,
        "escalation": true
    }
}
```
*Reinicie o serviço após qualquer alteração: `sudo systemctl restart potemkin`*

## Integração com Wazuh

Se você utiliza o **Wazuh** na sua infraestrutura, o Potemkin já vem com Decoders e Rules prontos para gerar alertas MITRE ATT&CK.

Copie os arquivos fornecidos para o seu **Wazuh Manager**:
1. Copie o `wazuh_decoder.xml` para `/var/ossec/etc/decoders/potemkin_decoder.xml`
2. Copie o `wazuh_rules.xml` para `/var/ossec/etc/rules/potemkin_rules.xml`
3. Reinicie o Manager: `systemctl restart wazuh-manager`

## Desinstalação

Como a instalação foi feita via `.deb`, a desinstalação é totalmente rastreável e limpa. O próprio pacote se encarrega de desfazer o *hardening* (imutabilidade) e remover as regras do iptables.

```bash
sudo apt remove potemkin
```

## Testes de Desenvolvimento

Se você for contribuir com o código, execute a suite de testes locais para garantir que a lógica de detecção e os mecanismos de segurança (anti-DoS, validação de IP) continuam funcionando:

```bash
python3 test_potemkin.py -v
```

## Forçando um desbloqueio
Se precisar desbloquear um ip por "cair na armadilha" voce pode usar o seguinte comando:

```bash
sudo iptables -D POTEMKIN -s <IP_A_SER_DESBLOQUEADO> -j DROP
```
