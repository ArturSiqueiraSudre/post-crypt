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
    if (v !== undefined && v !== null) campo.value = v;
  }
  linha.querySelector(".remover").addEventListener("click", () => {
    linha.remove();
    if (!$("#lista-alvos").children.length) adicionarAlvo();
    escopoMudou();
  });
  linha.addEventListener("input", () => linha.removeAttribute("data-erro"));
  $("#lista-alvos").append(linha);
  escopoMudou();
  return linha;
}

function lerEscopo() {
  const f = $("#form-escopo");
  const alvos = [...document.querySelectorAll("#lista-alvos .alvo")]
    .map((linha) => {
      const alvo = {};
      for (const campo of linha.querySelectorAll("[data-campo]")) alvo[campo.dataset.campo] = campo.value;
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
  const colunas = ["Nome", "Endereço", "Porta", "De quem é", "Nome no certificado"];
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
            el("td", { text: DONOS[t.owner] || t.owner }),
            el("td", { text: t.sni && t.sni !== t.host ? t.sni : "—" }),
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

function respostaCertificado(r) {
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
      el("small", { text: `${t.host}:${t.port}` }),
      t.owner === "third_party" ? el("span", { class: "dono", text: "De fornecedor" }) : null,
    ),
    el("span", { class: "selo", text: sit.nome, title: r.assessment.status_label }),
    celula("Tráfego gravado hoje", respostaTrafego(r)),
    celula("Cifra", respostaCifra(r)),
    celula("Certificado", respostaCertificado(r)),
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

  const tls = r.tls || {};
  const cert = (tls.certificates || [])[0];
  const linhas = [
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
  if (r.error) linhas.push(["Erro", r.error]);

  return el(
    "details",
    { class: `servico s-${st}` },
    resumo,
    el(
      "div",
      { class: "detalhes" },
      el("div", {}, el("h4", { text: "O que isso significa" }), el("p", { class: "explicacao", text: sit.explica }), el("h4", { text: "O que fazer" }), achados),
      el("div", {}, el("h4", { text: "Dados técnicos" }), el("dl", { class: "tecnico" }, linhas.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: v })]))),
    ),
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
  $("#servicos").replaceChildren(...ordenados.map(cartaoServico));

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
      "Laboratório de teste ligado neste computador: 6 serviços de exemplo, um deles desligado de propósito. Clique em Revisar e depois em Varrer." +
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
    $("#form-escopo").date.value = info.hoje;
    $("#usar-lab").hidden = !info.laboratorio.disponivel;
    $("#estado-info").textContent = `Regras de ${info.regras} · versão ${info.versao}`;
    atualizarMenu();
  } catch (e) {
    mostrarMensagem(e.message);
  }
}

iniciar();
