// Painel do Post-Crypt.
// Regra de segurança: nenhum dado vindo da varredura entra na página como HTML.
// Nomes de certificado vêm do servidor varrido, que pode ser hostil, então
// tudo é montado com textContent (função el abaixo). Não use innerHTML aqui.
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

let ultimoResultado = null;
let ocupado = false;

// ---------- utilidades ----------

function el(tag, props = {}, ...filhos) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("data-") || k.startsWith("aria-") || k === "role" || k === "title") n.setAttribute(k, v);
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

// ---------- formulário ----------

function adicionarAlvo(valores = {}) {
  const linha = $("#tpl-alvo").content.firstElementChild.cloneNode(true);
  for (const campo of linha.querySelectorAll("[data-campo]")) {
    const v = valores[campo.dataset.campo];
    if (v !== undefined && v !== null) campo.value = v;
  }
  linha.querySelector(".remover").addEventListener("click", () => {
    linha.remove();
    if (!$("#lista-alvos").children.length) adicionarAlvo();
    atualizarBotao();
  });
  linha.addEventListener("input", () => {
    linha.removeAttribute("data-erro");
    atualizarBotao();
  });
  $("#lista-alvos").append(linha);
  atualizarBotao();
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
}

function marcarErro(mensagemOriginal) {
  document.querySelectorAll("#lista-alvos .alvo").forEach((l) => l.removeAttribute("data-erro"));
  for (const nome of ["by", "date"]) $("#form-escopo")[nome].removeAttribute("aria-invalid");
  const m = /targets\[(\d+)\]/.exec(mensagemOriginal || "");
  if (m) {
    const preenchidas = [...document.querySelectorAll("#lista-alvos .alvo")].filter(
      (l) => l.querySelector('[data-campo="host"]').value.trim() || l.querySelector('[data-campo="label"]').value.trim(),
    );
    const linha = preenchidas[Number(m[1])];
    if (linha) {
      linha.dataset.erro = "true";
      linha.querySelector('[data-campo="host"]').focus();
    }
  } else if (/authorization/.test(mensagemOriginal || "")) {
    const f = $("#form-escopo");
    for (const nome of ["by", "date"]) if (!f[nome].value.trim()) f[nome].setAttribute("aria-invalid", "true");
    f.by.focus();
  }
}

function atualizarBotao() {
  const n = lerEscopo().targets.length;
  const botao = $("#varrer");
  botao.textContent = ocupado ? "Varrendo…" : n ? `Varrer ${plural(n, "serviço", "serviços")}` : "Varrer";
  botao.disabled = ocupado;
}

// ---------- varredura ----------

async function varrer(evento) {
  evento.preventDefault();
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
    marcarErro(e.original);
    return;
  }
  marcarErro("");
  ocupado = true;
  atualizarBotao();
  $("#progresso").hidden = false;
  progresso(0, job.total, "");

  try {
    for (;;) {
      await new Promise((r) => setTimeout(r, 400));
      const estado = await api(`/api/varreduras/${job.id}`);
      const ultimo = estado.parciais.at(-1);
      progresso(estado.feitos, estado.total, ultimo ? ultimo.target.label || `${ultimo.target.host}:${ultimo.target.port}` : "");
      if (estado.estado === "erro") throw new Error(estado.erro);
      if (estado.estado === "concluida") {
        mostrarResultado(estado.resultado);
        break;
      }
    }
  } catch (e) {
    mostrarMensagem(e.message);
  } finally {
    ocupado = false;
    $("#progresso").hidden = true;
    atualizarBotao();
  }
}

function progresso(feitos, total, ultimo) {
  $("#progresso-barra").style.width = `${total ? (100 * feitos) / total : 0}%`;
  $("#progresso-texto").textContent =
    `${feitos} de ${plural(total, "serviço verificado", "serviços verificados")}` + (ultimo ? `. Último: ${ultimo}` : "");
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
  const nome = t.label || `${t.host}:${t.port}`;

  const resumo = el(
    "summary",
    {},
    el(
      "div",
      { class: "nome" },
      el("strong", { text: nome }),
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

function mostrarResultado(resultado) {
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
    `Varredura ${resultado.scan_id.slice(0, 8)}, concluída em ${quando}. Autorizada por ${auth.by} em ${auth.date.split("-").reverse().join("/")}` +
    (auth.reference ? ` (${auth.reference})` : "") +
    `. Regras de ${resultado.rules_version}.`;

  const secao = $("#resultado");
  secao.hidden = false;
  secao.focus({ preventScroll: true });
  secao.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
}

// ---------- arquivo e laboratório ----------

async function abrirArquivo(evento) {
  const arquivo = evento.target.files[0];
  evento.target.value = "";
  if (!arquivo) return;
  try {
    const escopo = await api("/api/escopo/importar", { texto: await arquivo.text() });
    preencherEscopo(escopo);
    mostrarMensagem(`Escopo carregado de ${arquivo.name}: ${plural(escopo.targets.length, "serviço", "serviços")}.`, "info");
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
    marcarErro(e.original);
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
      "Laboratório de teste ligado neste computador: 6 serviços de exemplo, um deles desligado de propósito. Agora é só clicar em Varrer." +
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

// ---------- abas e guia ----------

const ABAS = ["varredura", "guia"];

function abaDoEndereco() {
  const alvo = location.hash.slice(1);
  if (ABAS.includes(alvo)) return { aba: alvo, secao: null };
  // Âncoras do guia (#guia-campos etc.) abrem o guia naquela seção.
  if (/^guia-[a-z]+$/.test(alvo) && document.getElementById(alvo)) return { aba: "guia", secao: alvo };
  return { aba: "varredura", secao: null };
}

function mostrarAba(nome, { focar = false, secao = null } = {}) {
  const escolhida = ABAS.includes(nome) ? nome : "varredura";
  for (const aba of ABAS) {
    const ativa = aba === escolhida;
    const botao = document.getElementById(`aba-${aba}`);
    botao.setAttribute("aria-selected", String(ativa));
    botao.tabIndex = ativa ? 0 : -1;
    document.getElementById(`painel-${aba}`).hidden = !ativa;
  }
  const destino = secao ? document.getElementById(secao) : null;
  if (destino) destino.scrollIntoView();
  else if (focar) {
    window.scrollTo(0, 0);
    document.getElementById(`painel-${escolhida}`).focus({ preventScroll: true });
  }
}

function irParaAba(nome, opcoes) {
  history.replaceState(null, "", nome === "varredura" ? location.pathname : `#${nome}`);
  mostrarAba(nome, opcoes);
}

function teclaNasAbas(evento) {
  const atual = ABAS.indexOf(evento.target.dataset.aba);
  if (atual < 0) return;
  let proxima = null;
  if (evento.key === "ArrowRight") proxima = (atual + 1) % ABAS.length;
  else if (evento.key === "ArrowLeft") proxima = (atual - 1 + ABAS.length) % ABAS.length;
  else if (evento.key === "Home") proxima = 0;
  else if (evento.key === "End") proxima = ABAS.length - 1;
  if (proxima === null) return;
  evento.preventDefault();
  irParaAba(ABAS[proxima]);
  document.getElementById(`aba-${ABAS[proxima]}`).focus();
}

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

function iniciarAbas() {
  for (const aba of ABAS) {
    const botao = document.getElementById(`aba-${aba}`);
    botao.addEventListener("click", () => irParaAba(aba));
    botao.addEventListener("keydown", teclaNasAbas);
  }
  for (const link of document.querySelectorAll("[data-ir-para]")) {
    link.addEventListener("click", (evento) => {
      evento.preventDefault();
      irParaAba(link.dataset.irPara, { focar: true });
    });
  }
  window.addEventListener("hashchange", () => {
    const { aba, secao } = abaDoEndereco();
    mostrarAba(aba, { secao });
  });
  $("#copiar-modelo").addEventListener("click", copiarModelo);
  $("#baixar-modelo").addEventListener("click", baixarModelo);
  const { aba, secao } = abaDoEndereco();
  mostrarAba(aba, { secao });
}

// ---------- início ----------

async function iniciar() {
  iniciarAbas();
  adicionarAlvo();
  $("#adicionar-alvo").addEventListener("click", () => adicionarAlvo().querySelector("input").focus());
  $("#form-escopo").addEventListener("submit", varrer);
  $("#form-escopo").addEventListener("input", (e) => {
    if (e.target.name === "by" || e.target.name === "date") e.target.removeAttribute("aria-invalid");
  });
  $("#arquivo-escopo").addEventListener("change", abrirArquivo);
  $("#salvar-escopo").addEventListener("click", salvarEscopo);
  $("#usar-lab").addEventListener("click", usarLaboratorio);
  $("#baixar-json").addEventListener("click", () => {
    if (!ultimoResultado) return;
    const dia = ultimoResultado.finished_at.slice(0, 10);
    baixar(`resultado-${dia}.json`, JSON.stringify(ultimoResultado, null, 2) + "\n", "application/json");
  });

  try {
    const info = await api("/api/info");
    $("#form-escopo").date.value = info.hoje;
    $("#usar-lab").hidden = !info.laboratorio.disponivel;
  } catch (e) {
    mostrarMensagem(e.message);
  }
}

iniciar();
