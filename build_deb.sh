#!/bin/bash
set -euo pipefail

VERSION="3.0.0"
PKG_NAME="potemkin"
ARCH="all"
DEB_DIR="build_deb/${PKG_NAME}_${VERSION}-1_${ARCH}"

echo "Limpando build anterior..."
rm -rf build_deb
mkdir -p "${DEB_DIR}/DEBIAN"

echo "Criando arvore de diretorios..."
mkdir -p "${DEB_DIR}/opt/potemkin"
mkdir -p "${DEB_DIR}/etc/potemkin"
mkdir -p "${DEB_DIR}/usr/local/bin"
mkdir -p "${DEB_DIR}/etc/systemd/system"
mkdir -p "${DEB_DIR}/etc/sudoers.d"

echo "Copiando arquivos..."
cp potemkin.py "${DEB_DIR}/opt/potemkin/"
chmod 755 "${DEB_DIR}/opt/potemkin/potemkin.py"

cp potemkin-firewall "${DEB_DIR}/usr/local/bin/"
chmod 755 "${DEB_DIR}/usr/local/bin/potemkin-firewall"

cp potemkin.conf "${DEB_DIR}/etc/potemkin/"
chmod 644 "${DEB_DIR}/etc/potemkin/potemkin.conf"

cp potemkin.service "${DEB_DIR}/etc/systemd/system/"
chmod 644 "${DEB_DIR}/etc/systemd/system/potemkin.service"

cp potemkin.sudoers "${DEB_DIR}/etc/sudoers.d/potemkin"
chmod 440 "${DEB_DIR}/etc/sudoers.d/potemkin"

echo "Criando DEBIAN/control..."
cat << 'EOF' > "${DEB_DIR}/DEBIAN/control"
Package: potemkin
Version: 3.0.0-1
Section: net
Priority: optional
Architecture: all
Depends: python3, sudo, iptables, e2fsprogs, gawk
Maintainer: Maarckz <maarckz@localhost>
Description: Potemkin Honeypot
 Potemkin e um Honeypot portscan detector com banimento automatico
 usando iptables. Arquitetura de threads e sockets paralelos.
EOF

echo "Criando DEBIAN/preinst..."
cat << 'EOF' > "${DEB_DIR}/DEBIAN/preinst"
#!/bin/bash
set -e
if [ "$1" = "install" ] || [ "$1" = "upgrade" ]; then
    if ! id potemkin &>/dev/null; then
        useradd --system --shell /usr/sbin/nologin --home-dir /nonexistent --no-create-home --comment "Potemkin Honeypot" potemkin
    fi
fi
EOF
chmod 755 "${DEB_DIR}/DEBIAN/preinst"

echo "Criando DEBIAN/postinst..."
cat << 'EOF' > "${DEB_DIR}/DEBIAN/postinst"
#!/bin/bash
set -e

# Criar diretorios runtime e de logs
mkdir -p /var/log/potemkin
mkdir -p /var/run/potemkin
chown -R potemkin:potemkin /var/log/potemkin
chmod 0750 /var/log/potemkin
chown -R potemkin:potemkin /var/run/potemkin
chmod 0750 /var/run/potemkin
chown root:root /etc/potemkin/potemkin.conf
chown -R root:root /opt/potemkin

# Configurar rsyslog
cat > /etc/rsyslog.d/40-potemkin.conf <<'RCONFIG'
# Potemkin Honeypot
local6.*    /var/log/potemkin/syslog
& stop
RCONFIG
chmod 0644 /etc/rsyslog.d/40-potemkin.conf
systemctl restart rsyslog || true

# Configurar Imutabilidade
if command -v chattr &>/dev/null; then
    chattr +i /usr/local/bin/potemkin-firewall || true
    chattr +i /etc/sudoers.d/potemkin || true
fi

# Reload systemd e habilitar servico
systemctl daemon-reload
systemctl enable potemkin
systemctl start potemkin || true
EOF
chmod 755 "${DEB_DIR}/DEBIAN/postinst"

echo "Criando DEBIAN/prerm..."
cat << 'EOF' > "${DEB_DIR}/DEBIAN/prerm"
#!/bin/bash
set -e
if [ "$1" = "remove" ] || [ "$1" = "upgrade" ]; then
    systemctl stop potemkin || true
    systemctl disable potemkin || true

    # Remover imutabilidade para permitir delecao dos arquivos
    if command -v chattr &>/dev/null; then
        chattr -i /usr/local/bin/potemkin-firewall || true
        chattr -i /etc/sudoers.d/potemkin || true
    fi
    
    # Limpar regras do iptables se o firewall helper existir
    if [ -x /usr/local/bin/potemkin-firewall ]; then
        /usr/local/bin/potemkin-firewall cleanup iptables POTEMKIN 2>/dev/null || true
    else
        iptables -D INPUT -j POTEMKIN 2>/dev/null || true
        iptables -F POTEMKIN 2>/dev/null || true
        iptables -X POTEMKIN 2>/dev/null || true
    fi
fi
EOF
chmod 755 "${DEB_DIR}/DEBIAN/prerm"

echo "Criando DEBIAN/postrm..."
cat << 'EOF' > "${DEB_DIR}/DEBIAN/postrm"
#!/bin/bash
set -e
if [ "$1" = "purge" ] || [ "$1" = "remove" ]; then
    rm -rf /var/log/potemkin
    rm -rf /var/run/potemkin
    rm -f /etc/rsyslog.d/40-potemkin.conf
    systemctl restart rsyslog || true
    systemctl daemon-reload
fi
EOF
chmod 755 "${DEB_DIR}/DEBIAN/postrm"

echo "Construindo pacote .deb..."
dpkg-deb --root-owner-group --build "${DEB_DIR}"

echo "Concluido! Pacote gerado em: build_deb/${PKG_NAME}_${VERSION}-1_${ARCH}.deb"
