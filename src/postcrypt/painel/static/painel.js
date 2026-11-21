// Painel do Post-Crypt.
// Regra de segurança: nenhum dado vindo da varredura entra na página como HTML.
// Nomes de certificado vêm do servidor varrido, que pode ser hostil, então
// tudo é montado com textContent (função el abaixo). Não use innerHTML aqui.
//
// A página é uma casca fixa (barra lateral + área de trabalho). Cada etapa é
// uma "vista"; só uma aparece por vez. Quem decide se o escopo vale é sempre
// o servidor: a navegação por etapas é só interface.
"use strict";

const TOKEN = document.querySelector('meta[name="pc-token"]').content;
const $ = (sel) => document.querySelector(sel);

const SITUACOES = {
  pqc: {
    nome: "Protegido",
    explica: "Aceita troca de chave pós-quântica. O que trafega hoje continua sigiloso mesmo diante de um computador quântico.",
  },
  hndl_vulnerable: {
    nome: "Exposto no futuro",
    explica: "Não quer dizer que foi invadido. Quer dizer que quem gravar o tráfego hoje poderá abri-lo quando existir um computador quântico.",
  },
  review: {
    nome: "Revisar",
    explica: "O serviço respondeu, mas não deu para concluir. Peça a um técnico para conferir.",
  },
  unreachable: {
    nome: "Não verificado",
    explica: "Não respondeu. Isso não significa que está seguro: o serviço ficou fora da análise.",
  },
};
const ORDEM = ["hndl_vulnerable", "review", "unreachable", "pqc"];
const SEVERIDADES = ["critical", "high", "medium", "low", "info"];
const GRAVIDADE = { critical: "Urgente", high: "Importante", medium: "Atenção", low: "Planejar", info: "Nota" };
const DONOS = { self: "Da empresa", third_party: "De fornecedor" };
// Suporte do fabricante à versão encontrada (fingerprint, Estágio 2).
const SUPORTE = {
  unsupported: "Sem suporte",
  supported: "Com suporte",
  unknown: "Suporte não avaliado",
};

// Lista fechada de vistas: o nome que vem da URL só vale se estiver aqui.
const VISTAS = {
  autorizacao: { titulo: "Quem autorizou esta varredura", etapa: 1 },
  servicos: { titulo: "Quais serviços verificar", etapa: 2 },
  revisar: { titulo: "Revisar e varrer", etapa: 3 },
  resultado: { titulo: "Resultado da varredura", etapa: 4 },
  guia: { titulo: "Como montar o arquivo de escopo", etapa: null },
};
const ETAPAS = ["autorizacao", "servicos", "revisar", "resultado"];

let vistaAtual = "autorizacao";
let escopoConferido = null; // escopo já aceito pelo servidor; zera a cada edição
let ultimoResultado = null;
let ocupado = false;
const cartoesPorServico = new Map(); // "endereço:porta" -> cartão no resultado
let recursos = {}; // o que o servidor do painel sabe fazer (vem de /api/info)

// ---------- utilidades ----------

function el(tag, props = {}, ...filhos) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("data-") || k.startsWith("aria-") || k === "role" || k === "title" || k === "scope") n.setAttribute(k, v);
    else n[k] = v;
  }
  for (const f of filhos.flat()) {
    if (f === null || f === undefined || f === false) continue;
    n.append(f instanceof Node ? f : document.createTextNode(String(f)));
  }
  return n;
}

async function api(caminho, corpo) {
  const opcoes = { headers: { "X-Post-Crypt-Token": TOKEN } };
  if (corpo !== undefined) {
    opcoes.method = "POST";
    opcoes.headers["Content-Type"] = "application/json";
    opcoes.body = JSON.stringify(corpo);
  }
  let resp;
  try {
    resp = await fetch(caminho, opcoes);
  } catch {
    throw new Error("O painel parou de responder. Confira se a janela do Post-Crypt continua aberta.");
  }
  const dados = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const erro = new Error(traduzirErro(dados.erro || `erro ${resp.status}`));
    erro.original = dados.erro || "";
    throw erro;
  }
  return dados;
}

// As mensagens do escopo foram escritas para quem edita o YAML; aqui viram a língua do formulário.
function traduzirErro(msg) {
  const trocas = [
    [/authorization\.by e authorization\.date são obrigatórios.*/, "Preencha quem autorizou a varredura e a data da autorização."],
    [/authorization\.date deve estar no formato AAAA-MM-DD/, "A data da autorização está incompleta."],
    [/targets deve listar ao menos um serviço/, "Adicione pelo menos um serviço."],
    [/targets\[(\d+)\]/g, (_, i) => `Serviço ${Number(i) + 1}`],
    [/host e port são obrigatórios/, "preencha o endereço e a porta"],
    [/host inválido/, "endereço inválido"],
    [/parece faixa ou curinga; liste cada host/, "parece uma faixa ou um curinga; liste cada endereço separadamente"],
    [/alvo repetido/, "Serviço repetido"],
    [/porta inválida/, "porta inválida (use um número de 1 a 65535)"],
  ];
  let saida = String(msg);
  for (const [de, para] of trocas) saida = saida.replace(de, para);
  return saida.charAt(0).toUpperCase() + saida.slice(1);
}

function mostrarMensagem(texto, tipo = "erro") {
  const m = $("#mensagem");
  m.textContent = texto;
  m.dataset.tipo = tipo;
  m.hidden = !texto;
}

function definirEstado(texto) {
  $("#estado-texto").textContent = texto;
}

function baixar(nome, texto, tipo) {
  const url = URL.createObjectURL(new Blob([texto], { type: tipo }));
  const a = el("a", { href: url, download: nome });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function plural(n, um, varios) {
  return `${n} ${n === 1 ? um : varios}`;
}

function dataBrasileira(iso) {
  return String(iso).split("-").reverse().join("/");
}

function nomeDoAlvo(t) {
  return t.label || `${t.host}:${t.port}`;
}

// Mesma chave que o servidor usa em network.findings[].assets.
function chaveDoAlvo(t) {
  return `${t.host}:${t.port}`;
}

// Servidor sem o Estágio 2 recusa o campo http_fingerprint: só oferece quando ele declara.
function comFingerprint() {
  return recursos.http_fingerprint === true;
}

// Servidor sem o Estágio 3 recusa protocol: ssh. Mesma regra: só oferece quando ele declara.
function comSsh() {
  return recursos.ssh === true;
}

function ehSsh(t) {
  return Boolean(t) && t.protocol === "ssh";
}

// Num serviço SSH não há nome no certificado nem pedido HTTP: os campos ficam desligados.
function ajustarProtocolo(linha, { trocarPorta }) {
  const protocolo = linha.querySelector('[data-campo="protocol"]');
  const ssh = protocolo && protocolo.value === "ssh";
  const porta = linha.querySelector('[data-campo="port"]');
  if (trocarPorta) {
    if (ssh && (porta.value === "443" || porta.value === "")) porta.value = "22";
    if (!ssh && porta.value === "22") porta.value = "443";
  }
  const sni = linha.querySelector('[data-campo="sni"]');
  const caixa = linha.querySelector('[data-campo="http_fingerprint"]');
  sni.disabled = ssh;
  sni.placeholder = ssh ? "Não se aplica a SSH" : "Só se o endereço for um IP";
  if (ssh) sni.value = "";
  if (caixa) {
    caixa.disabled = ssh;
    if (ssh) caixa.checked = false;
  }
}

// ---------- navegação entre vistas ----------

function autorizacaoPreenchida() {
  const f = $("#form-escopo");
  return Boolean(f.by.value.trim() && f.date.value);
}

function etapaFeita(nome) {
  if (nome === "autorizacao") return autorizacaoPreenchida();
  if (nome === "servicos") return lerEscopo().targets.some((a) => a.host.trim());
  if (nome === "revisar") return Boolean(ultimoResultado);
  return false;
}

function vistaDoEndereco() {
  const alvo = location.hash.slice(1);
  if (Object.hasOwn(VISTAS, alvo)) return { vista: alvo, secao: null };
  // Âncoras do guia (#guia-campos etc.) abrem o guia naquela seção.
  if (/^guia-[a-z]+$/.test(alvo) && document.getElementById(alvo)) return { vista: "guia", secao: alvo };
  return { vista: "autorizacao", secao: null };
}

// Uma etapa só abre quando a anterior já produziu o que ela mostra.
function vistaPermitida(nome) {
  if (!Object.hasOwn(VISTAS, nome)) return "autorizacao";
  if (nome === "resultado" && !ultimoResultado) return vistaPermitida("revisar");
  if (nome === "revisar" && !escopoConferido) return autorizacaoPreenchida() ? "servicos" : "autorizacao";
  return nome;
}

function atualizarMenu() {
  for (const nome of Object.keys(VISTAS)) {
    const botao = document.getElementById(`nav-${nome}`);
    if (nome === vistaAtual) botao.setAttribute("aria-current", VISTAS[nome].etapa ? "step" : "page");
    else botao.removeAttribute("aria-current");
    botao.dataset.feita = String(etapaFeita(nome));
  }
  $("#nav-resultado").disabled = !ultimoResultado;
}

function atualizarAcoes() {
  const n = lerEscopo().targets.length;
  $("#acoes").hidden = vistaAtual === "guia";
  $("#voltar").hidden = !(vistaAtual === "servicos" || vistaAtual === "revisar");
  const continuar = $("#continuar");
  continuar.hidden = !(vistaAtual === "autorizacao" || vistaAtual === "servicos");
  continuar.textContent = vistaAtual === "servicos" ? "Revisar" : "Continuar";
  const varrerBotao = $("#varrer");
  varrerBotao.hidden = vistaAtual !== "revisar";
  varrerBotao.textContent = ocupado ? "Varrendo…" : n ? `Varrer ${plural(n, "serviço", "serviços")}` : "Varrer";
  varrerBotao.disabled = ocupado;
  const nova = $("#nova-varredura");
  nova.hidden = vistaAtual !== "resultado";
  nova.disabled = ocupado;
}

function mostrarVista(nome, { secao = null, focar = false, manterMensagem = false } = {}) {
  const vista = vistaPermitida(nome);
  vistaAtual = vista;
  for (const v of Object.keys(VISTAS)) document.getElementById(`vista-${v}`).hidden = v !== vista;
  const info = VISTAS[vista];
  $("#barra-titulo").textContent = info.titulo;
  $("#barra-etapa").textContent = info.etapa ? `Etapa ${info.etapa} de ${ETAPAS.length}` : "Ajuda";
  document.title = `${info.titulo} · Post-Crypt`;
  if (!manterMensagem) mostrarMensagem("");
  if (vista === "revisar") renderizarRevisao(escopoConferido);
  atualizarMenu();
  atualizarAcoes();
  const destino = vista === "guia" && secao ? document.getElementById(secao) : null;
  if (destino) destino.scrollIntoView();
  else {
    $("#conteudo").scrollTop = 0;
    window.scrollTo(0, 0);
  }
  if (focar) $("#barra-titulo").focus({ preventScroll: true });
  return vista;
}

function irPara(nome, opcoes = {}) {
  const vista = mostrarVista(nome, { focar: true, ...opcoes });
  const fragmento = vista === "autorizacao" ? "" : vista;
  if (location.hash.slice(1) !== fragmento) {
    history.pushState(null, "", fragmento ? `#${fragmento}` : location.pathname);
  }
  return vista;
}

// O servidor confere o escopo inteiro antes de a revisão aparecer.
async function conferirEscopo() {
  try {
    escopoConferido = await api("/api/escopo/validar", lerEscopo());
  } catch (e) {
    escopoConferido = null;
    mostrarMensagem(e.message);
    marcarErro(e.original || "escopo");
    return false;
  }
  marcarErro("");
  irPara("revisar");
  return true;
}

async function avancar() {
  if (vistaAtual === "autorizacao") {
    if (!autorizacaoPreenchida()) {
      mostrarMensagem("Preencha quem autorizou a varredura e a data da autorização.");
      marcarErro("authorization");
      return;
    }
    marcarErro("");
    irPara("servicos");
  } else if (vistaAtual === "servicos") {
    await conferirEscopo();
  }
}

function voltar() {
  if (vistaAtual === "revisar") irPara("servicos");
  else if (vistaAtual === "servicos") irPara("autorizacao");
}

function navegarPeloMenu(nome) {
  if (nome === "revisar" && !escopoConferido) conferirEscopo();
  else irPara(nome);
}

// ---------- formulário ----------

function escopoMudou() {
  escopoConferido = null;
  atualizarMenu();
  atualizarAcoes();
}

function adicionarAlvo(valores = {}) {
  const linha = $("#tpl-alvo").content.firstElementChild.cloneNode(true);
  for (const campo of linha.querySelectorAll("[data-campo]")) {
    const v = valores[campo.dataset.campo];
    if (campo.type === "checkbox") campo.checked = v === true;
    else if (v !== undefined && v !== null) campo.value = v;
  }
  linha.querySelector(".remover").addEventListener("click", () => {
    linha.remove();
    if (!$("#lista-alvos").children.length) adicionarAlvo();
    escopoMudou();
  });
  linha.addEventListener("input", () => linha.removeAttribute("data-erro"));
  linha.querySelector('[data-campo="protocol"]').addEventListener("change", () => ajustarProtocolo(linha, { trocarPorta: true }));
  ajustarProtocolo(linha, { trocarPorta: false });
  $("#lista-alvos").append(linha);
  escopoMudou();
  return linha;
}

function lerEscopo() {
  const f = $("#form-escopo");
  const alvos = [...document.querySelectorAll("#lista-alvos .alvo")]
    .map((linha) => {
      const alvo = {};
      for (const campo of linha.querySelectorAll("[data-campo]")) {
        if (campo.dataset.campo === "protocol") {
          // tls é o padrão: o campo só vai quando é SSH e o servidor conhece SSH.
          if (campo.value === "ssh" && comSsh()) alvo.protocol = "ssh";
        } else if (campo.type !== "checkbox") alvo[campo.dataset.campo] = campo.value;
        // O padrão é não pedir: o campo só vai quando a caixa está marcada.
        else if (campo.checked && !campo.disabled && comFingerprint()) alvo[campo.dataset.campo] = true;
      }
      return alvo;
    })
    .filter((a) => a.host.trim() || a.label.trim());
  return {
    authorization: { by: f.by.value, date: f.date.value, reference: f.reference.value },
    targets: alvos,
  };
}

function preencherEscopo(escopo) {
  const f = $("#form-escopo");
  f.by.value = escopo.authorization.by || "";
  f.date.value = escopo.authorization.date || "";
  f.reference.value = escopo.authorization.reference || "";
  $("#lista-alvos").replaceChildren();
  for (const t of escopo.targets) {
    // Mostra o nome no certificado só quando ele difere do endereço.
    adicionarAlvo({ ...t, sni: t.sni && t.sni !== t.host ? t.sni : "" });
  }
  if (!escopo.targets.length) adicionarAlvo();
  escopoMudou();
}

// Leva a pessoa até a etapa onde está o erro e destaca o campo.
function marcarErro(mensagemOriginal) {
  document.querySelectorAll("#lista-alvos .alvo").forEach((l) => l.removeAttribute("data-erro"));
  const f = $("#form-escopo");
  for (const nome of ["by", "date"]) f[nome].removeAttribute("aria-invalid");
  if (!mensagemOriginal) return;
  if (/authorization/.test(mensagemOriginal)) {
    irPara("autorizacao", { manterMensagem: true, focar: false });
    for (const nome of ["by", "date"]) if (!f[nome].value.trim()) f[nome].setAttribute("aria-invalid", "true");
    (f.by.value.trim() ? f.date : f.by).focus();
    return;
  }
  irPara("servicos", { manterMensagem: true, focar: false });
  const m = /targets\[(\d+)\]/.exec(mensagemOriginal);
  if (!m) return;
  const preenchidas = [...document.querySelectorAll("#lista-alvos .alvo")].filter(
    (l) => l.querySelector('[data-campo="host"]').value.trim() || l.querySelector('[data-campo="label"]').value.trim(),
  );
  const linha = preenchidas[Number(m[1])];
  if (linha) {
    linha.dataset.erro = "true";
    linha.querySelector('[data-campo="host"]').focus();
  }
}

// ---------- revisão ----------

function renderizarRevisao(escopo) {
  if (!escopo) return;
  const a = escopo.authorization;
  $("#revisao-autorizacao").replaceChildren(
    el("dt", { text: "Autorizado por" }),
    el("dd", { text: a.by }),
    el("dt", { text: "Data" }),
    el("dd", { text: dataBrasileira(a.date) }),
    el("dt", { text: "Referência" }),
    el("dd", { text: a.reference || "—" }),
  );
  $("#revisao-contagem").textContent = `(${escopo.targets.length})`;
  const colunas = ["Nome", "Endereço", "Porta"];
  if (comSsh()) colunas.push("Protocolo");
  colunas.push("De quem é", "Nome no certificado");
  if (comFingerprint()) colunas.push("Versão do software");
  $("#revisao-servicos").replaceChildren(
    el(
      "table",
      {},
      el("thead", {}, el("tr", {}, colunas.map((c) => el("th", { scope: "col", text: c })))),
      el(
        "tbody",
        {},
        escopo.targets.map((t) =>
          el(
            "tr",
            {},
            el("td", { text: t.label || "—" }),
            el("td", { text: t.host }),
            el("td", { text: String(t.port) }),
            comSsh() ? el("td", { text: ehSsh(t) ? "SSH" : "TLS" }) : null,
            el("td", { text: DONOS[t.owner] || t.owner }),
            el("td", { text: t.sni && t.sni !== t.host ? t.sni : "—" }),
            comFingerprint() ? el("td", { text: ehSsh(t) ? "Pelo banner SSH" : t.http_fingerprint === true ? "Identificar (1 pedido HTTP)" : "Não pedir" }) : null,
          ),
        ),
      ),
    ),
  );
}

// ---------- varredura ----------

function renderizarAndamento(parciais) {
  $("#andamento").replaceChildren(
    ...parciais.map((r) => {
      const st = r.assessment.status;
      const sit = SITUACOES[st];
      return el(
        "li",
        { class: `s-${st}` },
        el("span", { class: "andamento-nome", text: nomeDoAlvo(r.target) }),
        el("span", { class: "selo", text: sit ? sit.nome : st }),
      );
    }),
  );
}

function progresso(feitos, total, ultimo) {
  $("#progresso-barra").style.width = `${total ? (100 * feitos) / total : 0}%`;
  const texto =
    `${feitos} de ${plural(total, "serviço verificado", "serviços verificados")}` + (ultimo ? `. Último: ${ultimo}` : "");
  $("#progresso-texto").textContent = texto;
  definirEstado(`Varrendo: ${texto}.`);
}

async function varrer() {
  if (ocupado) return;
  mostrarMensagem("");
  const f = $("#form-escopo");
  const pedido = {
    escopo: lerEscopo(),
    timeout: Number(f.timeout.value) || 5,
    workers: Number(f.workers.value) || 8,
  };
  let job;
  try {
    job = await api("/api/varreduras", pedido);
  } catch (e) {
    mostrarMensagem(e.message);
    if (/authorization|targets|alvo/.test(e.original || "")) marcarErro(e.original);
    return;
  }
  ocupado = true;
  atualizarAcoes();
  renderizarAndamento([]);
  $("#progresso").hidden = false;
  progresso(0, job.total, "");

  let concluida = false;
  try {
    for (;;) {
      await new Promise((r) => setTimeout(r, 400));
      const estado = await api(`/api/varreduras/${job.id}`);
      const ultimo = estado.parciais.at(-1);
      renderizarAndamento(estado.parciais);
      progresso(estado.feitos, estado.total, ultimo ? nomeDoAlvo(ultimo.target) : "");
      if (estado.estado === "erro") throw new Error(estado.erro);
      if (estado.estado === "concluida") {
        renderizarResultado(estado.resultado);
        concluida = true;
        break;
      }
    }
  } catch (e) {
    mostrarMensagem(e.message);
    definirEstado("A varredura parou antes de terminar.");
  } finally {
    ocupado = false;
    $("#progresso").hidden = true;
    atualizarMenu();
    atualizarAcoes();
  }
  // Só troca de tela se a pessoa ainda estiver esperando na revisão.
  if (concluida && vistaAtual === "revisar") irPara("resultado");
}

// ---------- resultado ----------

function respostaTrafego(r) {
  const kx = r.assessment.key_exchange;
  if (kx.status === "pqc") return { classe: "bom", texto: "Continua sigiloso", obs: kx.groups.join(", ") };
  if (kx.status === "classical")
    return { classe: "ruim", texto: "Pode ser aberto no futuro", obs: kx.classical_group || "" };
  return { classe: "neutro", texto: "Não deu para saber", obs: "" };
}

function respostaCifra(r) {
  const s = r.assessment.symmetric;
  if (s.status === "ok") return { classe: "bom", texto: "Forte", obs: s.cipher };
  if (s.status === "weak") return { classe: "ruim", texto: "Fraca, trocar", obs: s.cipher };
  return { classe: "neutro", texto: "Não deu para saber", obs: s.cipher || "" };
}

function respostaChaveSsh(r) {
  const auth = r.assessment.authentication || {};
  const chaves = r.ssh && Array.isArray(r.ssh.host_key) ? r.ssh.host_key : [];
  const obs = chaves.slice(0, 2).join(", ") + (chaves.length > 2 ? " …" : "");
  if (auth.status === "pqc") return { classe: "bom", texto: "Chave pós-quântica", obs };
  if (auth.status === "quantum_vulnerable") return { classe: "neutro", texto: "Chave clássica, migrar até 2035", obs };
  return { classe: "neutro", texto: "Chave não lida", obs };
}

function respostaCertificado(r) {
  if (r.ssh) return respostaChaveSsh(r);
  const certs = r.tls && r.tls.certificates;
  if (!certs || !certs.length) return { classe: "neutro", texto: "Não lido", obs: "" };
  const c = certs[0];
  const d = c.days_to_expiry;
  if (d < 0) return { classe: "ruim", texto: `Vencido há ${plural(-d, "dia", "dias")}`, obs: c.public_key_detail };
  if (d <= 30) return { classe: "ruim", texto: `Vence em ${plural(d, "dia", "dias")}`, obs: c.public_key_detail };
  return { classe: "bom", texto: `Válido por ${plural(d, "dia", "dias")}`, obs: c.public_key_detail };
}

function celula(rotulo, resp) {
  return el(
    "div",
    { class: `resposta ${resp.classe}` },
    el("span", { class: "rotulo-movel", text: rotulo }),
    el("span", {}, el("b", { text: resp.texto }), resp.obs ? el("small", { text: resp.obs }) : null),
  );
}

function manchete(resultado) {
  const total = resultado.results.length;
  const c = resultado.summary;
  const expostos = c.hndl_vulnerable || 0;
  const protegidos = c.pqc || 0;
  if (expostos) return `${expostos} de ${plural(total, "serviço pode", "serviços podem")} ter o tráfego de hoje aberto no futuro`.replace(/^1 de 1 serviço pode/, "O serviço pode");
  if (protegidos === total) return total === 1 ? "O serviço já usa troca de chave pós-quântica" : `Os ${total} serviços já usam troca de chave pós-quântica`;
  if (protegidos) return `${protegidos} de ${plural(total, "serviço já está protegido", "serviços já estão protegidos")}`;
  return "Nenhum serviço pôde ser confirmado como protegido";
}

function detalheManchete(resultado) {
  let vencidos = 0;
  let vencendo = 0;
  for (const r of resultado.results) {
    const ids = r.assessment.findings.map((f) => f.id);
    if (ids.includes("CERT_EXPIRED")) vencidos++;
    else if (ids.includes("CERT_EXPIRING")) vencendo++;
  }
  const partes = [];
  if (vencidos) partes.push(`${plural(vencidos, "serviço tem", "serviços têm")} certificado vencido`);
  if (vencendo) partes.push(`${plural(vencendo, "certificado vence", "certificados vencem")} em menos de 30 dias`);
  const semSuporte = resultado.results.filter((r) => produtosSemSuporte(r).length).length;
  if (semSuporte) partes.push(`${plural(semSuporte, "serviço roda", "serviços rodam")} software sem suporte do fabricante`);
  const sem = resultado.summary.unreachable || 0;
  let texto = partes.length ? partes.join(" e ") + "." : "";
  if (sem) texto += `${texto ? " " : ""}${plural(sem, "serviço não respondeu e ficou", "serviços não responderam e ficaram")} fora da análise.`;
  if (!texto) texto = "Nenhum certificado vencido ou perto de vencer.";
  return texto.charAt(0).toUpperCase() + texto.slice(1);
}

function cartaoServico(r) {
  const st = r.assessment.status;
  const sit = SITUACOES[st];
  const t = r.target;

  const resumo = el(
    "summary",
    {},
    el(
      "div",
      { class: "nome" },
      el("strong", { text: nomeDoAlvo(t) }),
      el("small", { text: `${t.host}:${t.port}${ehSsh(t) ? " · SSH" : ""}` }),
      t.owner === "third_party" ? el("span", { class: "dono", text: "De fornecedor" }) : null,
      produtosSemSuporte(r).length ? el("span", { class: "versao-alerta", text: "Software sem suporte" }) : null,
    ),
    el("span", { class: "selo", text: sit.nome, title: r.assessment.status_label }),
    celula("Tráfego gravado hoje", respostaTrafego(r)),
    celula("Cifra", respostaCifra(r)),
    celula(r.ssh ? "Chave do servidor" : "Certificado", respostaCertificado(r)),
  );

  const achados = r.assessment.findings.length
    ? el(
        "ul",
        { class: "achados" },
        r.assessment.findings.map((f) =>
          el(
            "li",
            { class: "achado" },
            el("span", { class: "grav", "data-g": f.severity, text: GRAVIDADE[f.severity] || f.severity }),
            el("strong", { text: f.title }),
            el("p", { text: f.detail }),
          ),
        ),
      )
    : el("p", { text: "Nada a corrigir neste serviço." });

  const linhas = r.ssh ? linhasSsh(r) : linhasTls(r);
  if (r.error) linhas.push(["Erro", r.error]);
  linhas.push(...linhasDeFingerprint(r));

  const naRede = achadosDeRede(ultimoResultado).filter((f) => (f.assets || []).includes(chaveDoAlvo(t)));
  const blocoRede = naRede.length
    ? [
        el("h4", { class: "com-espaco", text: "Na rede" }),
        el(
          "ul",
          { class: "achados" },
          naRede.map((f) =>
            el(
              "li",
              { class: "achado" },
              el("span", { class: "grav", "data-g": f.severity, text: GRAVIDADE[f.severity] || f.severity }),
              el("strong", { text: f.title }),
              el("p", { text: `Junto com ${plural(f.assets.length - 1, "outro serviço", "outros serviços")}. Veja em A rede como um todo.` }),
            ),
          ),
        ),
      ]
    : [];

  const cartao = el(
    "details",
    { class: `servico s-${st}` },
    resumo,
    el(
      "div",
      { class: "detalhes" },
      el("div", {}, el("h4", { text: "O que isso significa" }), el("p", { class: "explicacao", text: sit.explica }), el("h4", { text: "O que fazer" }), achados, blocoRede, blocoVersao(r)),
      el("div", {}, el("h4", { text: "Dados técnicos" }), el("dl", { class: "tecnico" }, linhas.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: v })]))),
    ),
  );
  cartoesPorServico.set(chaveDoAlvo(t), cartao);
  return cartao;
}

function linhasTls(r) {
  const tls = r.tls || {};
  const cert = (tls.certificates || [])[0];
  return [
    ["Situação técnica", r.assessment.status_label],
    ["TLS 1.3", tls.tls13 === undefined ? "—" : tls.tls13 ? "Sim" : "Não"],
    ["Grupos pós-quânticos", (tls.pqc_groups || []).join(", ") || "Nenhum"],
    ["Troca clássica", tls.classical_group || tls.tls12_key_exchange || "—"],
    ["Cifra", tls.tls13_cipher_suite || tls.tls12_cipher_suite || "—"],
    ["Certificado", cert ? cert.subject : "—"],
    ["Emitido por", cert ? cert.issuer : "—"],
    ["Válido até", cert ? cert.not_after.slice(0, 10) : "—"],
    ["Assinatura", cert ? cert.signature_algorithm : "—"],
    ["Tempo da verificação", `${r.duration_ms} ms`],
  ];
}

// Listas vêm do servidor varrido: entram só como texto, e longas são cortadas para leitura.
function lista(valor, maximo = 8) {
  const itens = Array.isArray(valor) ? valor.map(String) : [];
  if (!itens.length) return "—";
  return itens.slice(0, maximo).join(", ") + (itens.length > maximo ? ` e mais ${itens.length - maximo}` : "");
}

function linhasSsh(r) {
  const ssh = r.ssh || {};
  const banner = [ssh.software, ssh.comments].filter(Boolean).join(" ");
  return [
    ["Situação técnica", r.assessment.status_label],
    ["Protocolo", ssh.protocol ? `SSH ${ssh.protocol}` : "—"],
    ["Software (banner)", banner || "—"],
    ["Troca de chave aceita", lista(ssh.kex)],
    ["Chaves do servidor", lista(ssh.host_key)],
    ["Cifras aceitas", lista(ssh.ciphers)],
    ["Proteção Terrapin (strict KEX)", ssh.strict_kex ? "Sim" : "Não"],
    ["Tempo da verificação", `${r.duration_ms} ms`],
  ];
}

// ---------- resultado: versão do software (fingerprint) ----------

// Resultado de servidor sem o Estágio 2 não traz "fingerprint": tudo aqui some.
function fingerprintDe(r) {
  const fp = r && r.fingerprint;
  return fp && typeof fp === "object" ? fp : null;
}

function produtosDe(r) {
  const fp = fingerprintDe(r);
  return fp && Array.isArray(fp.products) ? fp.products : [];
}

function produtosSemSuporte(r) {
  return produtosDe(r).filter((p) => p.support === "unsupported");
}

function nomeDoProduto(p) {
  return p.version ? `${p.name} ${p.version}` : `${p.name} (versão escondida pelo servidor)`;
}

function blocoVersao(r) {
  const fp = fingerprintDe(r);
  if (!fp) return [];
  const produtos = produtosDe(r);
  return [
    el("h4", { class: "com-espaco", text: "Versão do software" }),
    produtos.length
      ? el(
          "ul",
          { class: "versoes" },
          produtos.map((p) => {
            const s = Object.hasOwn(SUPORTE, p.support) ? p.support : "unknown";
            return el(
              "li",
              { class: "versao" },
              el("span", { class: "suporte", "data-s": s, text: SUPORTE[s] }),
              el("strong", { text: nomeDoProduto(p) }),
              p.note ? el("p", { text: p.note }) : null,
            );
          }),
        )
      : null,
    // Com produtos na lista, o resumo só repetiria; sem eles, o motivo é o que importa.
    !produtos.length && fp.detail ? el("p", { class: "explicacao versao-detalhe", text: fp.detail }) : null,
  ];
}

function linhasDeFingerprint(r) {
  const fp = fingerprintDe(r);
  if (!fp) return [];
  const http = fp.http && typeof fp.http === "object" ? fp.http : {};
  const cabecalhos = http.headers && typeof http.headers === "object" ? http.headers : {};
  const pilha = fp.tls_stack && typeof fp.tls_stack === "object" ? fp.tls_stack : {};
  // Em SSH a versão vem do banner, já listado nos dados técnicos: não há pedido HTTP.
  const linhas = r.ssh ? [] : [["Pedido HTTP", http.requested ? "1 (HEAD /)" : "Nenhum"]];
  if (cabecalhos.server) linhas.push(["Cabeçalho Server", cabecalhos.server]);
  if (cabecalhos["x-powered-by"]) linhas.push(["Cabeçalho X-Powered-By", cabecalhos["x-powered-by"]]);
  if (pilha.signature) {
    linhas.push(["Assinatura TLS (estimativa)", pilha.stack ? `${pilha.signature} · ${pilha.stack}` : `${pilha.signature} · pilha não identificada`]);
  }
  return linhas;
}

// ---------- resultado: a rede como um todo ----------

function achadosDeRede(resultado) {
  const rede = resultado && resultado.network;
  return rede && Array.isArray(rede.findings) ? rede.findings : [];
}

function abrirServico(chave) {
  const cartao = cartoesPorServico.get(chave);
  if (!cartao) return;
  cartao.open = true;
  cartao.scrollIntoView({ block: "start" });
  cartao.querySelector("summary").focus({ preventScroll: true });
}

function cartaoRede(f, nomes) {
  const afetados = f.assets || [];
  const grav = SEVERIDADES.includes(f.severity) ? f.severity : "info";
  const resumo = el(
    "summary",
    {},
    el("span", { class: "grav", "data-g": grav, text: GRAVIDADE[grav] }),
    el("strong", { class: "rede-nome", text: f.title }),
    el("span", { class: "rede-alcance", text: `Afeta ${plural(afetados.length, "serviço", "serviços")}` }),
  );
  const botoes = afetados.map((chave) =>
    el("li", {}, el("button", { type: "button", class: "botao botao-leve botao-servico", text: nomes.get(chave) || chave, title: `Abrir ${chave}`, onclick: () => abrirServico(chave) })),
  );
  return el(
    "details",
    { class: `servico rede-achado g-${grav}` },
    resumo,
    el(
      "div",
      { class: "detalhes" },
      el(
        "div",
        {},
        el("h4", { text: "O que isso significa" }),
        el("p", { class: "explicacao", text: f.detail }),
        f.action ? el("h4", { text: "O que fazer" }) : null,
        f.action ? el("p", { class: "explicacao", text: f.action }) : null,
      ),
      el(
        "div",
        {},
        el("h4", { text: "Serviços afetados" }),
        el("ul", { class: "rede-servicos" }, botoes),
        el("dl", { class: "tecnico" }, el("dt", { text: "Prioridade" }), el("dd", { text: `${f.priority} (peso da gravidade × ${plural(afetados.length, "serviço", "serviços")})` })),
      ),
    ),
  );
}

// Com um serviço só não há o que comparar: a seção nem aparece.
function renderizarRede(resultado) {
  const secao = $("#rede");
  const achados = [...achadosDeRede(resultado)].sort((a, b) => (b.priority || 0) - (a.priority || 0));
  secao.hidden = !resultado.network || resultado.results.length < 2;
  if (secao.hidden) return;
  const nomes = new Map(resultado.results.map((r) => [chaveDoAlvo(r.target), nomeDoAlvo(r.target)]));
  $("#rede-achados").replaceChildren(
    ...(achados.length
      ? achados.map((f) => cartaoRede(f, nomes))
      : [el("p", { class: "rede-vazia", text: "Comparando os serviços entre si, nada pede atenção: não há autoridade certificadora, certificado nem versão sem suporte repetidos que criem um risco em conjunto." })]),
  );
}

function renderizarResultado(resultado) {
  ultimoResultado = resultado;
  const total = resultado.results.length;
  const contagem = resultado.summary;

  $("#resultado-titulo").textContent = manchete(resultado);
  $("#resultado-detalhe").textContent = detalheManchete(resultado);

  const faixa = $("#faixa");
  faixa.replaceChildren(
    ...ORDEM.filter((s) => contagem[s]).map((s) => {
      const seg = el("span", { class: `s-${s}`, title: `${SITUACOES[s].nome}: ${contagem[s]}` });
      seg.style.flex = String(contagem[s]);
      return seg;
    }),
  );
  faixa.setAttribute(
    "aria-label",
    ORDEM.filter((s) => contagem[s]).map((s) => `${SITUACOES[s].nome}: ${contagem[s]} de ${total}`).join("; "),
  );

  $("#legenda").replaceChildren(
    ...ORDEM.filter((s) => contagem[s]).map((s) =>
      el(
        "li",
        { class: `s-${s}` },
        el("span", { class: `amostra s-${s}`, "aria-hidden": "true" }),
        el("span", {}, el("strong", { text: SITUACOES[s].nome }), " ", el("span", { class: "qtd", text: `(${contagem[s]})` })),
        el("p", { text: SITUACOES[s].explica }),
      ),
    ),
  );

  // O mais urgente primeiro: um certificado vencido derruba o serviço hoje,
  // mesmo que a troca de chave já seja pós-quântica.
  const pior = (r) => Math.min(...r.assessment.findings.map((f) => SEVERIDADES.indexOf(f.severity)), SEVERIDADES.length);
  const ordenados = [...resultado.results].sort(
    (a, b) => pior(a) - pior(b) || ORDEM.indexOf(a.assessment.status) - ORDEM.indexOf(b.assessment.status),
  );
  cartoesPorServico.clear();
  $("#servicos").replaceChildren(...ordenados.map(cartaoServico));
  const ultimaColuna = document.querySelector(".colunas-servicos span:last-child");
  ultimaColuna.textContent = resultado.results.some((r) => r.ssh) ? "Certificado ou chave" : "Certificado";
  renderizarRede(resultado);

  const quando = new Date(resultado.finished_at).toLocaleString("pt-BR");
  const auth = resultado.authorization;
  $("#carimbo").textContent =
    `Varredura ${resultado.scan_id.slice(0, 8)}, concluída em ${quando}. Autorizada por ${auth.by} em ${dataBrasileira(auth.date)}` +
    (auth.reference ? ` (${auth.reference})` : "") +
    `. Regras de ${resultado.rules_version}.`;
  definirEstado(`Varredura ${resultado.scan_id.slice(0, 8)} concluída em ${quando}: ${plural(total, "serviço", "serviços")}.`);
}

// ---------- arquivo e laboratório ----------

async function abrirArquivo(evento) {
  const arquivo = evento.target.files[0];
  evento.target.value = "";
  if (!arquivo) return;
  try {
    const escopo = await api("/api/escopo/importar", { texto: await arquivo.text() });
    preencherEscopo(escopo);
    mostrarMensagem(`Escopo carregado de ${arquivo.name}: ${plural(escopo.targets.length, "serviço", "serviços")}. Clique em Revisar para conferir.`, "info");
  } catch (e) {
    mostrarMensagem(`Não consegui abrir ${arquivo.name}. ${e.message}`);
  }
}

async function salvarEscopo() {
  try {
    const { texto } = await api("/api/escopo/yaml", lerEscopo());
    baixar("escopo.yaml", texto, "text/yaml;charset=utf-8");
    mostrarMensagem("");
  } catch (e) {
    mostrarMensagem(`Antes de salvar: ${e.message}`);
    marcarErro(e.original || "escopo");
  }
}

async function usarLaboratorio() {
  const botao = $("#usar-lab");
  botao.disabled = true;
  botao.textContent = "Ligando o laboratório…";
  try {
    const { escopo, aviso } = await api("/api/laboratorio/ligar", {});
    preencherEscopo(escopo);
    mostrarMensagem(
      // A contagem vem do escopo do laboratório: muda quando o laboratório ganha serviços.
      `Laboratório de teste ligado neste computador: ${plural(escopo.targets.length, "serviço", "serviços")} de exemplo, um deles desligado de propósito. Clique em Revisar e depois em Varrer.` +
        (aviso ? ` Aviso: ${aviso}` : ""),
      "info",
    );
  } catch (e) {
    mostrarMensagem(e.message);
  } finally {
    botao.disabled = false;
    botao.textContent = "Usar laboratório de teste";
  }
}

// ---------- guia ----------

function avisarNoGuia(texto) {
  const aviso = $("#guia-aviso");
  aviso.textContent = texto;
  aviso.hidden = !texto;
}

async function copiarModelo() {
  const texto = $("#guia-modelo").textContent;
  try {
    await navigator.clipboard.writeText(texto);
    avisarNoGuia("Modelo copiado. Cole no Bloco de Notas e salve como escopo.yaml.");
  } catch {
    avisarNoGuia("Não consegui copiar automaticamente. Selecione o texto do modelo e copie, ou use Baixar modelo.");
  }
}

function baixarModelo() {
  baixar("escopo-modelo.yaml", $("#guia-modelo").textContent, "text/yaml;charset=utf-8");
  avisarNoGuia("Modelo baixado como escopo-modelo.yaml. Troque os exemplos pelos seus dados antes de usar.");
}

// ---------- início ----------

function ligarEventos() {
  for (const nome of Object.keys(VISTAS)) {
    document.getElementById(`nav-${nome}`).addEventListener("click", () => navegarPeloMenu(nome));
  }
  for (const link of document.querySelectorAll("[data-ir-para]")) {
    link.addEventListener("click", (evento) => {
      evento.preventDefault();
      irPara(link.dataset.irPara);
    });
  }
  window.addEventListener("hashchange", () => {
    const { vista, secao } = vistaDoEndereco();
    mostrarVista(vista, { secao });
  });

  const form = $("#form-escopo");
  form.addEventListener("submit", (evento) => {
    evento.preventDefault();
    if (vistaAtual === "revisar") varrer();
    else avancar();
  });
  for (const id of ["#vista-autorizacao", "#vista-servicos"]) {
    $(id).addEventListener("input", (evento) => {
      if (evento.target.name === "by" || evento.target.name === "date") evento.target.removeAttribute("aria-invalid");
      escopoMudou();
    });
  }
  $("#continuar").addEventListener("click", avancar);
  $("#voltar").addEventListener("click", voltar);
  $("#nova-varredura").addEventListener("click", () => irPara("servicos"));
  $("#adicionar-alvo").addEventListener("click", () => adicionarAlvo().querySelector("input").focus());
  $("#arquivo-escopo").addEventListener("change", abrirArquivo);
  $("#salvar-escopo").addEventListener("click", salvarEscopo);
  $("#usar-lab").addEventListener("click", usarLaboratorio);
  $("#baixar-json").addEventListener("click", () => {
    if (!ultimoResultado) return;
    const dia = ultimoResultado.finished_at.slice(0, 10);
    baixar(`resultado-${dia}.json`, JSON.stringify(ultimoResultado, null, 2) + "\n", "application/json");
  });
  $("#copiar-modelo").addEventListener("click", copiarModelo);
  $("#baixar-modelo").addEventListener("click", baixarModelo);
}

async function iniciar() {
  adicionarAlvo();
  ligarEventos();
  const { vista, secao } = vistaDoEndereco();
  mostrarVista(vista, { secao });

  try {
    const info = await api("/api/info");
    recursos = info.recursos && typeof info.recursos === "object" ? info.recursos : {};
    document.body.classList.toggle("com-fingerprint", comFingerprint());
    document.body.classList.toggle("com-ssh", comSsh());
    $("#form-escopo").date.value = info.hoje;
    $("#usar-lab").hidden = !info.laboratorio.disponivel;
    $("#estado-info").textContent = `Regras de ${info.regras} · versão ${info.versao}`;
    atualizarMenu();
  } catch (e) {
    mostrarMensagem(e.message);
  }
}

iniciar();
