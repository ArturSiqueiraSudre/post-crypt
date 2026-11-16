"""Correlação de rede: achados que só existem ao comparar os alvos entre si.

Tudo aqui é montado em memória: nenhuma conexão, nenhum arquivo além das
regras do pacote.
"""

import copy
import io
import json

import pytest
from rich.console import Console

from postcrypt.certs import CertificateInfo
from postcrypt.classify import HNDL, PQC, REVIEW, UNREACHABLE, Assessment, load_rules
from postcrypt.network import SEVERITY_WEIGHT, NetworkAssessment, analyze_network
from postcrypt.output import render_network, scan_report
from postcrypt.scanner import ScanResult, TargetResult
from postcrypt.scope import Authorization, Scope, Target
from postcrypt.tls.probe import TLSObservation

RULES = load_rules()
CA = "O=Lab,CN=CA Clássica"


def cert(
    cn, *, issuer=CA, position=0, algorithm="EC", detail="EC secp256r1", sig="ecdsa-with-SHA256"
):
    subject = f"O=Lab,CN={cn}"
    return CertificateInfo(
        position=position,
        subject=subject,
        issuer=issuer,
        serial="1",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-01-01T00:00:00+00:00",
        days_to_expiry=200,
        public_key_algorithm=algorithm,
        public_key_bits=256,
        public_key_detail=detail,
        signature_algorithm=sig,
        self_signed=subject == issuer,
        sha256_fingerprint=f"fp-{cn}",
    )


CA_CERT = cert("CA Clássica", position=1, detail="EC secp384r1")


def alvo(port, status=PQC, *, certs=None, owner="self", label=None, host="10.0.0.1"):
    target = Target(host, port, label=label or f"svc-{port}", owner=owner)
    unknown = {"status": "unknown", "detail": "Não observado."}
    assessment = Assessment(status, status, unknown, unknown, unknown, [])
    if status == UNREACHABLE:
        return TargetResult(target, False, 1, None, assessment, "recusado")
    obs = TLSObservation(tls13=True, certificates=list(certs or []))
    return TargetResult(target, True, 1, obs, assessment)


def varredura(*results):
    scope = Scope(Authorization("Teste", "2026-11-14"), tuple(r.target for r in results))
    return ScanResult(
        "id", "2026-11-14T00:00:00+00:00", "2026-11-14T00:00:01+00:00", scope, list(results)
    )


def achados(scan, rules=RULES):
    return {f.id: f for f in analyze_network(scan, rules).findings}


# ---------- caminho feliz: os quatro achados ----------


def test_ca_classica_compartilhada_e_ponto_unico_de_falha():
    scan = varredura(
        alvo(443, certs=[cert("a"), CA_CERT]),
        alvo(444, certs=[cert("b"), CA_CERT]),
        alvo(445, certs=[cert("c", issuer="O=Outra,CN=Outra CA")]),
    )
    f = achados(scan)["NET_SHARED_CLASSICAL_CA"]
    assert f.assets == ("10.0.0.1:443", "10.0.0.1:444")
    assert f.blast_radius == 2 and f.severity == "medium"
    assert f.priority == SEVERITY_WEIGHT["medium"] * 2
    assert f.evidence == {"ca_subject": CA, "ca_key": "EC secp384r1", "ca_observed": True}
    assert "CA Clássica" in f.detail and f.action


def test_certificado_identico_em_mais_de_um_alvo():
    mesmo = cert("compartilhado", issuer="O=Lab,CN=compartilhado")  # autoassinado
    scan = varredura(alvo(443, certs=[mesmo]), alvo(444, certs=[mesmo], owner="third_party"))
    encontrados = achados(scan)
    f = encontrados["NET_DUPLICATE_LEAF"]
    assert f.assets == ("10.0.0.1:443", "10.0.0.1:444") and f.severity == "low"
    assert f.evidence["sha256_fingerprint"] == "fp-compartilhado"
    assert "fornecedor" in f.detail
    assert "NET_SHARED_CLASSICAL_CA" not in encontrados  # autoassinado não tem CA a relacionar


@pytest.mark.parametrize(
    ("vulneraveis", "protegidos", "severidade"),
    [(1, 9, "low"), (1, 3, "medium"), (2, 2, "high"), (3, 0, "high")],
)
def test_exposicao_a_hndl_em_escala(vulneraveis, protegidos, severidade):
    results = [alvo(1000 + i, HNDL) for i in range(vulneraveis)]
    results += [alvo(2000 + i, PQC) for i in range(protegidos)]
    f = achados(varredura(*results))["NET_HNDL_EXPOSURE"]
    assert f.severity == severidade
    assert f.blast_radius == vulneraveis
    assert f.evidence["assessed"] == vulneraveis + protegidos
    assert set(f.assets) == {f"10.0.0.1:{1000 + i}" for i in range(vulneraveis)}


def test_exposicao_a_hndl_so_conta_ativos_proprios_avaliados():
    scan = varredura(
        alvo(1, HNDL),
        alvo(2, PQC),
        alvo(3, HNDL, owner="third_party"),  # de fornecedor: fora da conta
        alvo(4, UNREACHABLE),  # não avaliado: fora da conta
        alvo(5, REVIEW),  # inconclusivo: fora da conta
    )
    f = achados(scan)["NET_HNDL_EXPOSURE"]
    assert f.assets == ("10.0.0.1:1",)
    assert f.evidence == {"vulnerable": 1, "assessed": 2, "ratio": 0.5}


def test_lacunas_de_visibilidade_somam_terceiros_e_inalcancaveis():
    scan = varredura(
        alvo(1),
        alvo(2),
        alvo(3, UNREACHABLE),
        alvo(4, owner="third_party"),
        alvo(5, UNREACHABLE, owner="third_party"),  # conta uma vez só
        alvo(6),
        alvo(7),
        alvo(8),
    )
    f = achados(scan)["NET_VISIBILITY_GAP"]
    assert set(f.assets) == {"10.0.0.1:3", "10.0.0.1:4", "10.0.0.1:5"}
    assert f.severity == "medium"  # 3 de 8 = 37,5%
    assert f.evidence == {"unreachable": 2, "third_party": 2, "total": 8, "ratio": 0.38}


def test_achados_saem_ordenados_por_prioridade():
    scan = varredura(
        *[alvo(100 + i, HNDL, certs=[cert(f"s{i}"), CA_CERT]) for i in range(4)],
        alvo(200, UNREACHABLE),
    )
    prioridades = [f.priority for f in analyze_network(scan, RULES).findings]
    assert prioridades == sorted(prioridades, reverse=True)
    assert prioridades[0] == SEVERITY_WEIGHT["high"] * 4  # exposição a HNDL em 4 de 4


# ---------- limites ----------


def test_um_alvo_so_nao_gera_achado_de_rede():
    scan = varredura(alvo(443, HNDL, certs=[cert("a"), CA_CERT], owner="third_party"))
    assert analyze_network(scan, RULES) == NetworkAssessment(total_targets=1)


def test_varredura_vazia_nao_gera_achado():
    assert analyze_network(varredura(), RULES) == NetworkAssessment(total_targets=0)


def test_rede_saudavel_nao_gera_achado():
    scan = varredura(
        alvo(1, certs=[cert("a", issuer="O=A,CN=CA A")]),
        alvo(2, certs=[cert("b", issuer="O=B,CN=CA B")]),
    )
    assert analyze_network(scan, RULES).findings == ()


def test_ca_que_assina_um_alvo_so_nao_e_compartilhada():
    scan = varredura(alvo(1, certs=[cert("a"), CA_CERT]), alvo(2))
    assert "NET_SHARED_CLASSICAL_CA" not in achados(scan)


def test_limiares_ausentes_das_regras_usam_o_padrao():
    """Um --rules antigo, sem a seção network, não derruba a análise."""
    antigas = {k: v for k, v in RULES.items() if k not in ("network", "signature_families")}
    scan = varredura(
        alvo(1, HNDL, certs=[cert("a")]), alvo(2, HNDL, certs=[cert("b")]), alvo(3, UNREACHABLE)
    )
    encontrados = achados(scan, antigas)
    assert encontrados["NET_HNDL_EXPOSURE"].severity == "high"
    assert encontrados["NET_SHARED_CLASSICAL_CA"].evidence["ca_observed"] is False


# ---------- casos adversariais ----------


def test_alvos_sem_cadeia_nao_quebram_nem_sao_relacionados():
    scan = varredura(alvo(1, certs=[]), alvo(2, certs=[]), alvo(3, UNREACHABLE))
    encontrados = achados(scan)
    assert "NET_SHARED_CLASSICAL_CA" not in encontrados
    assert "NET_DUPLICATE_LEAF" not in encontrados


def test_cadeia_sem_o_certificado_da_ca_usa_a_assinatura_da_folha():
    scan = varredura(
        alvo(1, certs=[cert("a", sig="sha256WithRSAEncryption")]),
        alvo(2, certs=[cert("b", sig="sha256WithRSAEncryption")]),
    )
    f = achados(scan)["NET_SHARED_CLASSICAL_CA"]
    assert f.evidence["ca_observed"] is False
    assert f.evidence["ca_key"] == "assinatura sha256WithRSAEncryption"


@pytest.mark.parametrize(
    "assinatura", ["Unknown OID", "1.2.3.4.5", "", "<script>alert(1)</script>"]
)
def test_algoritmo_sem_regra_nao_vira_achado_classico(assinatura):
    """Sem regra não se afirma que a CA é vulnerável: o achado pede cadastro."""
    scan = varredura(
        alvo(1, certs=[cert("a", sig=assinatura)]), alvo(2, certs=[cert("b", sig=assinatura)])
    )
    encontrados = achados(scan)
    assert "NET_SHARED_CLASSICAL_CA" not in encontrados
    assert encontrados["NET_SHARED_CA_UNCLASSIFIED"].severity == "info"


def test_ca_na_cadeia_com_algoritmo_sem_regra():
    estranha = cert("CA Clássica", position=1, algorithm="1.2.3.4", detail="1.2.3.4")
    scan = varredura(alvo(1, certs=[cert("a"), estranha]), alvo(2, certs=[cert("b"), estranha]))
    assert set(achados(scan)) == {"NET_SHARED_CA_UNCLASSIFIED"}


def test_ca_pos_quantica_compartilhada_nao_e_achado():
    pq = cert("CA Clássica", position=1, algorithm="ML-DSA-65", detail="ML-DSA-65")
    scan = varredura(alvo(1, certs=[cert("a"), pq]), alvo(2, certs=[cert("b"), pq]))
    assert analyze_network(scan, RULES).findings == ()


def test_raio_de_impacto_muito_grande():
    n = 5000
    scan = varredura(*[alvo(i + 1, HNDL, certs=[cert(f"s{i}"), CA_CERT]) for i in range(n)])
    encontrados = achados(scan)
    ca = encontrados["NET_SHARED_CLASSICAL_CA"]
    assert ca.blast_radius == n and len(ca.assets) == n
    assert ca.priority == SEVERITY_WEIGHT["medium"] * n
    assert encontrados["NET_HNDL_EXPOSURE"].priority == SEVERITY_WEIGHT["high"] * n
    # No terminal a lista de alvos é cortada; o JSON continua completo.
    saida = io.StringIO()
    render_network(scan, analyze_network(scan, RULES), Console(file=saida, width=200))
    assert "e mais 4994" in saida.getvalue()


def test_regras_malformadas_nao_derrubam_a_analise():
    ruins = copy.deepcopy(RULES)
    ruins["network"] = "quebrado"
    ruins["signature_families"] = ["rsa"]
    ruins["public_keys"] = None
    scan = varredura(alvo(1, HNDL, certs=[cert("a")]), alvo(2, HNDL, certs=[cert("b")]))
    encontrados = achados(scan, ruins)
    assert "NET_HNDL_EXPOSURE" in encontrados
    assert "NET_SHARED_CA_UNCLASSIFIED" in encontrados  # sem public_keys, nada é dado como clássico


def test_limiar_que_nao_e_numero_e_ignorado():
    ruins = copy.deepcopy(RULES)
    ruins["network"]["hndl_exposure"] = {"high": "muito", "medium": True, "critical": None}
    scan = varredura(alvo(1, HNDL), alvo(2, HNDL))
    assert achados(scan, ruins)["NET_HNDL_EXPOSURE"].severity == "low"


def test_texto_hostil_do_certificado_sai_como_texto_no_terminal_e_no_json():
    hostil = "[bold red]x[/bold red]\x1b[2J<script>alert(1)</script>"
    scan = varredura(
        alvo(1, certs=[cert("a", issuer=f"CN={hostil}")], label="[link=http://x]a[/link]"),
        alvo(2, certs=[cert("b", issuer=f"CN={hostil}")]),
    )
    network = analyze_network(scan, RULES)
    saida = io.StringIO()
    render_network(scan, network, Console(file=saida, width=300, color_system=None))
    texto = saida.getvalue()
    assert "[bold red]x[/bold red]" in texto  # impresso literalmente, não interpretado
    assert "[link=http://x]a[/link]" in texto
    assert "\x1b" not in texto  # sequência de terminal não chega à tela
    relatorio = json.loads(json.dumps(scan_report(scan, network)))
    assert relatorio["network"]["findings"][0]["evidence"]["ca_subject"] == f"CN={hostil}"


# ---------- contrato com o painel ----------


def test_formato_exportado_e_o_que_o_painel_le():
    scan = varredura(alvo(1, HNDL, certs=[cert("a"), CA_CERT]), alvo(2, certs=[cert("b"), CA_CERT]))
    relatorio = scan_report(scan, analyze_network(scan, RULES))
    assert relatorio["network"]["total_targets"] == 2
    chaves_dos_alvos = {
        f"{r['target']['host']}:{r['target']['port']}" for r in relatorio["results"]
    }
    for f in relatorio["network"]["findings"]:
        assert set(f) == {
            "id", "severity", "title", "detail", "action",
            "assets", "blast_radius", "priority", "evidence",
        }  # fmt: skip
        assert f["severity"] in SEVERITY_WEIGHT and f["title"] and f["detail"] and f["action"]
        assert f["blast_radius"] == len(f["assets"]) >= 1
        assert f["priority"] == SEVERITY_WEIGHT[f["severity"]] * f["blast_radius"]
        assert (
            set(f["assets"]) <= chaves_dos_alvos
        )  # o painel liga o achado ao cartão por esta chave


def test_secao_de_rede_nao_aparece_no_terminal_com_um_alvo():
    scan = varredura(alvo(1, HNDL))
    saida = io.StringIO()
    render_network(scan, analyze_network(scan, RULES), Console(file=saida))
    assert saida.getvalue() == ""
