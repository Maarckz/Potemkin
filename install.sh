#!/bin/bash
# =============================================================================
# Potemkin v2.1.1 - Script de Instalacao Limpia (remove versao anterior)
# =============================================================================
# Uso: sudo bash install.sh
#
# Este script REMOVE completamente a versao anterior antes de instalar.
# Nenhuma configuracao anterior e preservada.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; }

if [[ "$(id -u)" -ne 0 ]]; then
    error "Execute com sudo/root."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/potemkin"
CONFIG_DIR="/etc/potemkin"
LOG_DIR="/var/log/potemkin"
RUN_DIR="/var/run/potemkin"
BIN_PATH="${INSTALL_DIR}/potemkin.py"
HELPER_PATH="/usr/local/bin/potemkin-firewall"
SERVICE_PATH="/etc/systemd/system/potemkin.service"
SUDOERS_PATH="/etc/sudoers.d/potemkin"
RSYSLOG_CONF="/etc/rsyslog.d/40-potemkin.conf"

#############################################
## FASE 1: REMOCAO COMPLETA DA VERSAO ANTERIOR
#############################################

echo ""
info "=== FASE 1: Remocao da versao anterior ==="
echo ""

# 1.1 Parar servico
if systemctl is-active --quiet potemkin 2>/dev/null; then
    info "Parando servico potemkin..."
    systemctl stop potemkin || true
    sleep 2
else
    warn "Servico potemkin nao esta rodando."
fi

# 1.2 Desativar servico
if systemctl is-enabled --quiet potemkin 2>/dev/null; then
    systemctl disable potemkin 2>/dev/null || true
fi

# 1.3 Remover immutable de arquivos criticos
info "Removendo protecao immutable..."
if command -v chattr &>/dev/null; then
    chattr -i "$HELPER_PATH" 2>/dev/null || true
    chattr -i "$SUDOERS_PATH" 2>/dev/null || true
    chattr -i "$SERVICE_PATH" 2>/dev/null || true
    chattr -i "$BIN_PATH" 2>/dev/null || true
fi

# 1.4 Limpar regras nftables do Potemkin
info "Limpando regras nftables do Potemkin..."
if command -v nft &>/dev/null; then
    # Usar helper se existir, senao limpar manualmente
    if [[ -x "$HELPER_PATH" ]]; then
        "$HELPER_PATH" cleanup nftables POTEMKIN 2>/dev/null || true
    else
        # Buscar handle do jump rule (|| true previne set -e com pipefail)
        HANDLE=$(nft -a list chain ip filter input 2>/dev/null | grep "jump POTEMKIN" | awk '{print $NF}') || true
        if [[ -n "$HANDLE" ]]; then
            nft "delete rule ip filter input handle ${HANDLE}" 2>/dev/null || true
        fi
        nft flush chain ip filter POTEMKIN 2>/dev/null || true
        nft delete chain ip filter POTEMKIN 2>/dev/null || true
        nft delete set ip filter POTEMKIN_blocked 2>/dev/null || true
    fi
    info "  nftables limpo."
fi

# 1.5 Limpar regras iptables do Potemkin
info "Limpando regras iptables do Potemkin..."
iptables -D INPUT -j POTEMKIN 2>/dev/null || true
iptables -F POTEMKIN 2>/dev/null || true
iptables -X POTEMKIN 2>/dev/null || true

# 1.6 Remover arquivos de servico
info "Removendo arquivos de servico..."
rm -f "$SERVICE_PATH"
rm -f "$SUDOERS_PATH"
rm -f "$HELPER_PATH"
rm -f "$RSYSLOG_CONF"

# 1.7 Remover instalacao anterior (binarios + config)
info "Removendo instalacao anterior..."
rm -rf "$INSTALL_DIR"
rm -rf "$CONFIG_DIR"
rm -rf "$LOG_DIR"
rm -rf "$RUN_DIR"

# 1.8 Recarregar systemd
systemctl daemon-reload 2>/dev/null || true

warn "Versao anterior completamente removida."
echo ""

#############################################
## FASE 2: VERIFICACAO DE DEPENDENCIAS
#############################################

echo ""
info "=== FASE 2: Verificacao de dependencias ==="
echo ""

if ! command -v python3 &>/dev/null; then
    error "Python3 nao encontrado. Instale com: apt install python3"
    exit 1
fi
info "Python3 encontrado."

if ! command -v sudo &>/dev/null; then
    error "sudo nao encontrado. Instale com: apt install sudo"
    exit 1
fi
info "sudo encontrado."

if command -v iptables &>/dev/null; then
    info "iptables encontrado."
    FW_BACKEND="iptables"
elif command -v nft &>/dev/null; then
    info "nftables encontrado."
    FW_BACKEND="nftables"
else
    warn "Nenhum firewall encontrado (iptables/nft). Bloqueio sera desabilitado."
    FW_BACKEND="none"
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
info "Python ${PYTHON_VERSION} detectado."

if [[ "$FW_BACKEND" != "none" ]]; then
    info "Firewall backend: ${FW_BACKEND}"
fi

echo ""

#############################################
## FASE 3: INSTALACAO
#############################################

echo ""
info "=== FASE 3: Instalacao ==="
echo ""

# 3.1 Criar usuario
info "Criando usuario potemkin..."
if id potemkin &>/dev/null; then
    warn "Usuario potemkin ja existe (mantido)."
else
    useradd \
        --system \
        --shell /usr/sbin/nologin \
        --home-dir /nonexistent \
        --no-create-home \
        --comment "Potemkin Honeypot" \
        potemkin
    info "Usuario potemkin criado."
fi

# 3.2 Criar diretorios
info "Criando diretorios..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$RUN_DIR"

# 3.3 Instalar binarios
info "Instalando binarios..."
install -m 0755 "${SCRIPT_DIR}/potemkin.py" "${BIN_PATH}"
install -m 0755 "${SCRIPT_DIR}/potemkin-firewall" "${HELPER_PATH}"

# 3.4 Instalar config (SEMPRE sobrescreve)
info "Instalando configuracao..."
install -m 0644 "${SCRIPT_DIR}/potemkin.conf" "${CONFIG_DIR}/potemkin.conf"

# 3.5 Permissoes
info "Aplicando permissoes..."
chown -R root:root "$INSTALL_DIR"
chmod -R 0755 "$INSTALL_DIR"
chown -R potemkin:potemkin "$LOG_DIR"
chmod 0750 "$LOG_DIR"
chown -R potemkin:potemkin "$RUN_DIR"
chmod 0750 "$RUN_DIR"
chown root:root "${CONFIG_DIR}/potemkin.conf"
chmod 0644 "${CONFIG_DIR}/potemkin.conf"

# 3.6 Sudoers
info "Configurando sudoers..."
install -m 0440 "${SCRIPT_DIR}/potemkin.sudoers" "${SUDOERS_PATH}"
if visudo -cf "${SUDOERS_PATH}" 2>/dev/null; then
    info "Sudoers validado."
else
    error "Erro no sudoers."
    exit 1
fi

# 3.7 Servico systemd
info "Instalando servico systemd..."
if [[ -f "${SCRIPT_DIR}/potemkin.service" ]]; then
    install -m 0644 "${SCRIPT_DIR}/potemkin.service" "${SERVICE_PATH}"
else
    error "potemkin.service nao encontrado no diretorio."
    exit 1
fi

# 3.8 Immutable
info "Protegendo arquivos criticos (immutable)..."
if command -v chattr &>/dev/null; then
    chattr +i "$HELPER_PATH" && info "  Helper: immutable"
    chattr +i "$SUDOERS_PATH" && info "  Sudoers: immutable"
else
    warn "  chattr nao disponivel. Protecao immutable ignorada."
fi

# 3.9 Rsyslog
info "Configurando rsyslog..."
cat > "${RSYSLOG_CONF}" <<EOF
# Potemkin Honeypot
local6.*    ${LOG_DIR}/syslog
& stop
EOF
chmod 0644 "${RSYSLOG_CONF}"
systemctl restart rsyslog || true

# 3.10 Systemd
info "Recarregando systemd..."
systemctl daemon-reload
systemctl enable potemkin

# 3.11 Validacao
info "Validacao..."
if [[ -x "$BIN_PATH" ]]; then
    info "  Binario OK: ${BIN_PATH}"
else
    error "  Binario nao executavel: ${BIN_PATH}"
fi

if [[ -x "$HELPER_PATH" ]]; then
    info "  Helper OK: ${HELPER_PATH}"
else
    error "  Helper nao executavel: ${HELPER_PATH}"
fi

if [[ -f "${CONFIG_DIR}/potemkin.conf" ]]; then
    info "  Config OK: ${CONFIG_DIR}/potemkin.conf"
else
    error "  Config ausente: ${CONFIG_DIR}/potemkin.conf"
fi

echo ""

#############################################
## FASE 4: RESUMO
#############################################

echo ""
echo "======================================================="
echo -e "${GREEN}Potemkin v2.1.1 instalado com sucesso!${NC}"
echo "======================================================="
echo ""
echo "  Instalacao:  ${INSTALL_DIR}"
echo "  Config:      ${CONFIG_DIR}/potemkin.conf"
echo "  Logs:        ${LOG_DIR}"
echo "  Firewall:    ${FW_BACKEND}"
echo ""
echo "Comandos:"
echo "  systemctl start potemkin"
echo "  systemctl stop potemkin"
echo "  systemctl restart potemkin"
echo "  systemctl status potemkin"
echo "  journalctl -u potemkin -f"
echo ""
echo "Firewall:"
echo "  iptables -L POTEMKIN -n -v --line-numbers"
echo ""
echo "Para remover completamente:"
echo "  chattr -i /usr/local/bin/potemkin-firewall /etc/sudoers.d/potemkin"
echo "  systemctl stop potemkin && systemctl disable potemkin"
echo "  rm -rf /opt/potemkin /etc/potemkin /var/log/potemkin /var/run/potemkin"
echo "  rm -f /usr/local/bin/potemkin-firewall /etc/systemd/system/potemkin.service"
echo "  rm -f /etc/sudoers.d/potemkin /etc/rsyslog.d/40-potemkin.conf"
echo "  systemctl daemon-reload"
echo ""

read -rp "Deseja iniciar agora? [s/N] " answer

if [[ "${answer,,}" == "s" || "${answer,,}" == "y" ]]; then
    systemctl start potemkin
    sleep 3
    echo ""
    systemctl status potemkin --no-pager || true
    echo ""
    echo "--- Chain POTEMKIN ---"
    if [[ "$FW_BACKEND" == "iptables" ]]; then
        iptables -L POTEMKIN -n --line-numbers 2>/dev/null || echo "(vazia)"
    elif [[ "$FW_BACKEND" == "nftables" ]]; then
        nft list chain ip filter POTEMKIN 2>/dev/null || echo "(vazia)"
    fi
fi
