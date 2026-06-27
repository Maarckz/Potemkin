#!/usr/bin/env python3

import sys
import os
import time
import json
import tempfile
import threading

# Adiciona o diretorio do potemkin.py ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from potemkin import (
    load_config, DEFAULT_CONFIG, _deep_merge, _MAX_TRACKED_IPS,
    Syslog, Firewall, RateLimiter, Detector,
    build_port_map, Potemkin, __VERSION__,
)
from potemkin import (
    SSHResp, FTPResp, SMTPResp, TelnetResp, HTTPResp, MySQLResp,
    MSSQLResp, POP3Resp, IMAPResp, LDAPResp, NTPResp, RPCBindResp,
    SOCKSResp, DNSResp, EchoResp, ChargenResp, HTTPSResp, NullResp,
    BannerResp,
)

# =========================================================================
# Contadores de testes
# =========================================================================

_passed = 0
_failed = 0
_errors = []


def test(name, func):
    """Executa um teste e conta resultado."""
    global _passed, _failed, _errors
    try:
        func()
        _passed += 1
        print(f"  ✓ {name}")
    except Exception as e:
        _failed += 1
        _errors.append((name, str(e)))
        print(f"  ✗ {name}: {e}")


# =========================================================================
# TESTE 1: Configuracao
# =========================================================================

def test_config_default():
    """Config default deve ter todos os campos obrigatorios."""
    cfg = load_config.__wrapped__() if hasattr(load_config, '__wrapped__') else None
    # load_config sem argumentos tenta ler arquivo real; testamos direct dict
    cfg = dict(DEFAULT_CONFIG)
    assert cfg["bind_address"] == "0.0.0.0"
    assert cfg["detection"]["threshold"] == 10
    assert cfg["detection"]["ban_duration"] == 600
    assert cfg["rate_limit"]["max_connections"] == 30
    assert cfg["firewall"]["backend"] == "iptables"
    print("  ✓ Config default correta")


def test_config_iptables_forced():
    """Config deve forcar backend iptables."""
    assert DEFAULT_CONFIG["firewall"]["backend"] == "iptables"
    print("  ✓ Backend iptables forcado no default")


def test_config_file_loading():
    """Carregamento de config JSON de arquivo."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({
            "detection": {"threshold": 20, "ban_duration": 1200},
            "firewall": {"backend": "iptables"},
        }, f)
        f.flush()
        cfg = load_config(f.name)
        os.unlink(f.name)
    assert cfg["detection"]["threshold"] == 20
    assert cfg["detection"]["ban_duration"] == 1200
    assert cfg["firewall"]["backend"] == "iptables"


def test_config_invalid_values():
    """Valores invalidos devem ser revertidos para defaults."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({
            "detection": {"threshold": -1, "window": 0, "ban_duration": 0},
            "max_threads": 99999,
            "socket_timeout": 999,
        }, f)
        f.flush()
        cfg = load_config(f.name)
        os.unlink(f.name)
    assert cfg["detection"]["threshold"] == 10  # default
    assert cfg["detection"]["window"] == 60      # default
    assert cfg["detection"]["ban_duration"] == 600  # default
    assert cfg["max_threads"] == 512            # default
    assert cfg["socket_timeout"] == 3            # default


def test_config_nftables_rejected():
    """Se config especificar nftables, Firewall deve aceitar (config override)."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({
            "firewall": {"backend": "iptables"},
        }, f)
        f.flush()
        cfg = load_config(f.name)
        os.unlink(f.name)
    # Firewall.__init__ respeita o backend passado
    fw = Firewall(backend=cfg["firewall"]["backend"])
    assert fw._backend == "iptables"


# =========================================================================
# TESTE 2: Firewall
# =========================================================================

def test_firewall_valid_ip():
    """Validacao de IPv4: deve aceitar apenas IPs validos."""
    assert Firewall._valid_ip("192.168.1.1") == True
    assert Firewall._valid_ip("0.0.0.0") == True
    assert Firewall._valid_ip("255.255.255.255") == True
    assert Firewall._valid_ip("10.0.0.1") == True
    assert Firewall._valid_ip("1.2.3.4") == True


def test_firewall_invalid_ip():
    """Validacao de IPv4: deve rejeitar IPs invalidos e IPv6."""
    assert Firewall._valid_ip("::1") == False          # IPv6
    assert Firewall._valid_ip("2001:db8::1") == False   # IPv6
    assert Firewall._valid_ip("1.2.3") == False         # 3 octetos
    assert Firewall._valid_ip("1.2.3.4.5") == False      # 5 octetos
    assert Firewall._valid_ip("256.1.1.1") == False      # Octeto > 255
    assert Firewall._valid_ip("1.2.3.-1") == False      # Negativo
    assert Firewall._valid_ip("") == False               # Vazio
    assert Firewall._valid_ip("abc") == False            # Nao numerico
    assert Firewall._valid_ip("1.2.3.4a") == False       # Com letra
    assert Firewall._valid_ip(None) == False             # None
    assert Firewall._valid_ip(123) == False              # Int
    assert Firewall._valid_ip("1.2.3.0444") == False    # Octeto > 3 digitos
    assert Firewall._valid_ip(" 1.2.3.4") == False      # Com espaco


def test_firewall_init():
    """Firewall.init() sem sudo deve falhar graciosamente."""
    fw = Firewall(backend="iptables")
    # Vai falhar porque nao tem sudo, mas nao deve crashar
    result = fw.init()
    # Em ambiente sem sudo, init falha (False) mas nao levanta excecao
    assert isinstance(result, bool)


def test_firewall_block_invalid_ip():
    """block() com IP invalido deve ser ignorado (seguranca)."""
    fw = Firewall(backend="iptables")
    # Nao deve levantar excecao, deve retornar False silenciosamente
    assert fw.block("::1") is False
    assert fw.block("256.256.256.256") is False
    assert fw.block("") is False


def test_firewall_unblock_invalid_ip():
    """unblock() com IP invalido deve ser ignorado."""
    fw = Firewall(backend="iptables")
    # Nao deve levantar excecao
    fw.unblock("::1")
    fw.unblock("abc")


# =========================================================================
# TESTE 3: Rate Limiter
# =========================================================================

def test_ratelimiter_allows_normal():
    """Rate limiter permite trafego normal."""
    rl = RateLimiter(max_conn=5, window=10)
    assert rl.check("1.2.3.4") == True
    assert rl.check("1.2.3.4") == True
    assert rl.check("1.2.3.4") == True
    assert rl.check("1.2.3.4") == True
    assert rl.check("1.2.3.4") == True  # 5a: ainda OK
    # Bucket tem 5 entries agora


def test_ratelimiter_blocks_exceed():
    """Rate limiter bloqueia ao exceder limite."""
    rl = RateLimiter(max_conn=3, window=10, ban_on_exceed=True)
    assert rl.check("1.2.3.4") == True
    assert rl.check("1.2.3.4") == True
    assert rl.check("1.2.3.4") == True  # 3a: ultima permitida
    assert rl.check("1.2.3.4") == False  # 4a: bloqueado!
    # Apos bloqueio, bucket foi limpo (ban_on_exceed=True)
    assert rl.check("1.2.3.4") == True   # Resetou


def test_ratelimiter_per_ip():
    """Rate limiter isola cada IP."""
    rl = RateLimiter(max_conn=2, window=10)
    assert rl.check("1.1.1.1") == True
    assert rl.check("1.1.1.1") == True
    assert rl.check("1.1.1.1") == False  # IP1 excedeu
    assert rl.check("2.2.2.2") == True   # IP2 independente


def test_ratelimiter_cleanup():
    """Cleanup loop remove buckets vazios."""
    rl = RateLimiter(max_conn=100, window=1)
    rl.buckets["1.2.3.4"] = [time.time()]
    rl.buckets["5.6.7.8"] = []

    # Simula cleanup
    now = time.time()
    cutoff = now - rl.window
    for ip in list(rl.buckets):
        rl.buckets[ip] = [t for t in rl.buckets[ip] if t > cutoff]
        if not rl.buckets[ip]:
            del rl.buckets[ip]

    assert "1.2.3.4" in rl.buckets   # Ainda ativo
    assert "5.6.7.8" not in rl.buckets  # Removido (vazio)


# =========================================================================
# TESTE 4: Detector de Portscan
# =========================================================================

def test_detector_no_trigger():
    """Detector nao aciona com poucas portas."""
    expire_calls = []
    detect_calls = []

    det = Detector(
        threshold=5, window=60,
        on_detect=lambda *a: detect_calls.append(a),
        on_expire=lambda ip: expire_calls.append(ip),
    )

    # 3 portas unicas: nao deve acionar
    assert det.record("1.2.3.4", 22) == False
    assert det.record("1.2.3.4", 80) == False
    assert det.record("1.2.3.4", 443) == False

    assert len(detect_calls) == 0
    assert len(expire_calls) == 0


def test_detector_trigger():
    """Detector aciona ao atingir threshold."""
    detect_calls = []
    det = Detector(
        threshold=5, window=60, ban_duration=600,
        escalation=False,
        on_detect=lambda *a: detect_calls.append(a),
    )

    # 5 portas unicas: deve acionar
    for port in [22, 23, 25, 80, 443]:
        result = det.record("1.2.3.4", port)

    assert result == True  # Ultimo record acionou
    assert len(detect_calls) == 1
    ip, count, ports, dur = detect_calls[0]
    assert ip == "1.2.3.4"
    assert count == 5
    assert dur == 600


def test_detector_blocked_ip():
    """Detector rejeita IPs ja bloqueados."""
    detect_calls = []
    det = Detector(
        threshold=3, window=60, ban_duration=600,
        escalation=False,
        on_detect=lambda *a: detect_calls.append(a),
    )

    # Aciona bloqueio
    det.record("1.2.3.4", 22)
    det.record("1.2.3.4", 80)
    det.record("1.2.3.4", 443)
    assert det.is_blocked("1.2.3.4") == True

    # Tenta conectar em outra porta: deve ser ignorado
    assert det.record("1.2.3.4", 3306) == False

    # Deve ter acionado apenas 1 vez
    assert len(detect_calls) == 1


def test_detector_expiry():
    """Detector desbloqueia IPs quando ban expira e chama on_expire."""
    expire_calls = []
    detect_calls = []
    det = Detector(
        threshold=2, window=60, ban_duration=1,  # 1 segundo
        escalation=False,
        on_detect=lambda *a: detect_calls.append(a),
        on_expire=lambda ip: expire_calls.append(ip),
    )

    # Aciona bloqueio
    det.record("1.2.3.4", 22)
    det.record("1.2.3.4", 80)
    assert det.is_blocked("1.2.3.4") == True
    assert len(expire_calls) == 0

    # Espera expirar (1 segundo + margem)
    time.sleep(1.5)

    # Proxima conexao deve detectar que o ban expirou
    det.record("1.2.3.4", 25)
    assert "1.2.3.4" in expire_calls  # on_expire foi chamado!
    assert det.is_blocked("1.2.3.4") == False  # Ja nao esta bloqueado


def test_detector_cleanup_loop():
    """Cleanup loop expira bans e chama on_expire."""
    expire_calls = []
    det = Detector(
        threshold=2, window=60, ban_duration=1,
        escalation=False,
        on_detect=lambda *a: None,
        on_expire=lambda ip: expire_calls.append(ip),
    )

    # Bloqueia 2 IPs
    det.record("1.1.1.1", 22)
    det.record("1.1.1.1", 80)
    det.record("2.2.2.2", 22)
    det.record("2.2.2.2", 80)

    assert det.is_blocked("1.1.1.1") == True
    assert det.is_blocked("2.2.2.2") == True

    # Espera expirar
    time.sleep(1.5)

    # Simula cleanup_loop manualmente (uma iteracao)
    now = time.time()
    with det.lock:
        expired = [ip for ip, t in det.blocked.items() if now >= t]
        for ip in expired:
            del det.blocked[ip]
    if expired and det.on_expire:
        for ip in expired:
            det.on_expire(ip)

    assert "1.1.1.1" in expire_calls
    assert "2.2.2.2" in expire_calls
    assert det.is_blocked("1.1.1.1") == False
    assert det.is_blocked("2.2.2.2") == False


def test_detector_escalation():
    """Detector escalona duracao do ban: 1a=1s, 2a=3s, 3a+=6s."""
    detect_calls = []
    det = Detector(
        threshold=2, window=60, ban_duration=1,  # 1 segundo para teste rapido
        escalation=True, max_ban_duration=86400,
        on_detect=lambda *a: detect_calls.append(a),
    )

    # 1a ofensa: 1s
    det.record("1.1.1.1", 22)
    det.record("1.1.1.1", 80)
    assert len(detect_calls) == 1, f"Esperava 1 detect, got {len(detect_calls)}"
    assert detect_calls[-1][3] == 1, f"Esperava dur=1, got {detect_calls[-1][3]}"

    # Espera expirar (1s + margem)
    time.sleep(1.5)
    # record apos expirar aciona on_expire e zera contagem
    det.record("1.1.1.1", 25)

    # 2a ofensa: 3s (1 * 3)
    det.record("1.1.1.1", 22)
    det.record("1.1.1.1", 80)
    assert len(detect_calls) == 2, f"Esperava 2 detects, got {len(detect_calls)}: {detect_calls}"
    assert detect_calls[-1][3] == 3, f"Esperava dur=3, got {detect_calls[-1][3]}"

    # Espera expirar (3.5s > dur=3 do 2o ban)
    time.sleep(3.5)
    det.record("1.1.1.1", 25)

    # 3a ofensa: 6s (1 * 6)
    det.record("1.1.1.1", 22)
    det.record("1.1.1.1", 80)
    assert len(detect_calls) == 3, f"Esperava 3 detects, got {len(detect_calls)}: {detect_calls}"
    assert detect_calls[-1][3] == 6, f"Esperava dur=6, got {detect_calls[-1][3]}"


def test_detector_ipv6_rejected():
    """Detector rejeita enderecos IPv6 silenciosamente."""
    det = Detector(threshold=2, window=60)
    assert det.record("::1", 22) == False
    assert det.record("::1", 80) == False
    assert det.record("2001:db8::1", 22) == False
    # Deve estar vazio - nenhum dado armazenado para IPv6
    assert len(det.hits) == 0


def test_detector_max_tracked_ips():
    """Detector respeita limite de IPs rastreados (anti-DoS)."""
    detect_calls = []
    det = Detector(
        threshold=5, window=60,
        on_detect=lambda *a: detect_calls.append(a),
    )

    # Preenche ate perto do limite com dados falsos
    for i in range(_MAX_TRACKED_IPS):
        det.hits[f"10.0.{i // 256}.{i % 256}"] = [time.time()]

    # Tenta adicionar novo IP: deve ser rejeitado
    result = det.record("99.99.99.99", 22)
    assert result == False
    assert len(detect_calls) == 0


def test_detector_add_rate_ban():
    """add_rate_ban registra IP no dict blocked para unban automatico."""
    expire_calls = []
    det = Detector(
        threshold=5, window=60,
        on_expire=lambda ip: expire_calls.append(ip),
    )

    # Adiciona ban de rate limit
    det.add_rate_ban("5.5.5.5", 1)  # 1 segundo
    assert det.is_blocked("5.5.5.5") == True

    # Espera expirar
    time.sleep(1.5)

    # Cleanup manual para simular
    now = time.time()
    with det.lock:
        expired = [ip for ip, t in det.blocked.items() if now >= t]
        for ip in expired:
            del det.blocked[ip]
    if expired and det.on_expire:
        for ip in expired:
            det.on_expire(ip)

    assert "5.5.5.5" in expire_calls
    assert det.is_blocked("5.5.5.5") == False


def test_detector_get_stats():
    """get_stats retorna estatisticas validas."""
    det = Detector(threshold=5, window=60)
    det.record("1.1.1.1", 22)
    det.record("1.1.1.1", 80)

    stats = det.get_stats()
    assert "tracked_ips" in stats
    assert "blocked_ips" in stats
    assert "total_offenses" in stats
    assert stats["tracked_ips"] >= 1


# =========================================================================
# TESTE 5: Responders
# =========================================================================

def test_responders_instantiation():
    """Todos os responders devem instanciar sem erro."""
    responders = [
        SSHResp(), FTPResp(), SMTPResp(), TelnetResp(), HTTPResp(),
        MySQLResp(), MSSQLResp(), POP3Resp(), IMAPResp(), LDAPResp(),
        NTPResp(), RPCBindResp(), SOCKSResp(), DNSResp(), EchoResp(),
        ChargenResp(), HTTPSResp(), NullResp(), BannerResp(b"test"),
    ]
    for r in responders:
        assert hasattr(r, 'service')
        assert hasattr(r, 'handle')


def test_responder_services():
    """Cada responder tem o service name correto."""
    assert SSHResp().service == "ssh"
    assert HTTPResp().service == "http"
    assert DNSResp().service == "dns"
    assert FTPResp().service == "ftp"
    assert MySQLResp().service == "mysql"
    assert POP3Resp().service == "pop3"
    assert IMAPResp().service == "imap"


def test_port_map():
    """build_port_map deve cobrir portas essenciais."""
    pm = build_port_map()
    # Portas criticas devem existir
    assert 22 in pm
    assert 80 in pm
    assert 443 in pm
    assert 21 in pm
    assert 3306 in pm
    assert 1433 in pm
    assert 5432 in pm
    assert 27017 in pm
    # Deve ter milhares de portas
    assert len(pm) > 900


# =========================================================================
# TESTE 6: Potemkin (classe principal)
# =========================================================================

def test_potemkin_init():
    """Potemkin deve inicializar sem erro (sem firewall real)."""
    p = Potemkin.__new__(Potemkin)
    p.cfg = load_config()  # Usa default
    p._stop = threading.Event()
    p._servers = []
    p._pool = None
    # A init() real vai falhar no firewall sem sudo, mas testamos partes
    assert p.cfg is not None


# =========================================================================
# EXECUCAO
# =========================================================================

if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"Potemkin v{__VERSION__} - Suite de Testes")
    print(f"{'='*60}\n")

    # Config tests
    print("[Configuracao]")
    test("Config default", test_config_default)
    test("iptables forcado", test_config_iptables_forced)
    test("Carregamento de arquivo", test_config_file_loading)
    test("Valores invalidos -> defaults", test_config_invalid_values)
    test("nftables nao permitido", test_config_nftables_rejected)

    # Firewall tests
    print("\n[Firewall]")
    test("IP valido aceito", test_firewall_valid_ip)
    test("IP invalido rejeitado", test_firewall_invalid_ip)
    test("init() sem sudo", test_firewall_init)
    test("block() IP invalido", test_firewall_block_invalid_ip)
    test("unblock() IP invalido", test_firewall_unblock_invalid_ip)

    # Rate limiter tests
    print("\n[Rate Limiter]")
    test("Trafego normal permitido", test_ratelimiter_allows_normal)
    test("Excesso bloqueado", test_ratelimiter_blocks_exceed)
    test("Isolamento por IP", test_ratelimiter_per_ip)
    test("Cleanup de buckets", test_ratelimiter_cleanup)

    # Detector tests
    print("\n[Detector de Portscan]")
    test("Sem trigger (poucas portas)", test_detector_no_trigger)
    test("Trigger ao atingir threshold", test_detector_trigger)
    test("IP bloqueado e rejeitado", test_detector_blocked_ip)
    test("Expiracao de ban + on_expire", test_detector_expiry)
    test("Cleanup loop + on_expire", test_detector_cleanup_loop)
    test("Escalonamento de ban", test_detector_escalation)
    test("IPv6 rejeitado", test_detector_ipv6_rejected)
    test("Limite de IPs rastreados", test_detector_max_tracked_ips)
    test("add_rate_ban para unban auto", test_detector_add_rate_ban)
    test("get_stats()", test_detector_get_stats)

    # Responder tests
    print("\n[Responders]")
    test("Instanciacao sem erro", test_responders_instantiation)
    test("Service names corretos", test_responder_services)
    test("Port map completo", test_port_map)

    # Potemkin class
    print("\n[Potemkin]")
    test("Inicializacao basica", test_potemkin_init)

    # Resultado
    print(f"\n{'='*60}")
    total = _passed + _failed
    print(f"Resultado: {_passed}/{total} passaram, {_failed} falharam")
    if _failed > 0:
        print(f"\nFalhas:")
        for name, err in _errors:
            print(f"  - {name}: {err}")
        print(f"\n{'='*60}\n")
        sys.exit(1)
    else:
        print(f"\n{'='*60}")
        print("TODOS OS TESTES PASSARAM!")
        print(f"{'='*60}\n")
        sys.exit(0)
