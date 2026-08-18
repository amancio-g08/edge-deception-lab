<h1 align="center">Edge Deception Lab</h1>

<p align="center">
  Um honeypot que responde a pergunta que nenhum console de WAF responde direito:<br />
  <strong>quem está de fato batendo nessa aplicação, e como eu teria classificado cada um?</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/testes-33%20passando-0ca30c?style=flat-square" alt="33 testes passando" />
  <img src="https://img.shields.io/badge/licença-MIT-4A4A55?style=flat-square" alt="MIT" />
</p>

<p align="center">
  <strong>Português</strong> · <a href="README.en.md">English</a>
</p>

---

## O que é isso

Um sensor autocontido que fica atrás de uma camada de edge, serve uma aplicação-isca
inerte e classifica cada requisição que chega até ele por **comportamento**, não por
identidade declarada.

É o mecanismo por trás de um produto comercial de bot management, reconstruído pequeno
o suficiente para ser lido de uma sentada: fingerprint de requisição, verificação de
crawler por DNS reverso confirmado, agregação de velocity, scoring ponderado e um
veredicto explicável para cada requisição.

Eu opero ambientes Akamai profissionalmente — tuning de WAF, exceções de bot, Site
Shield, troubleshooting entre borda e origin. Operar um console ensina *o que* a
plataforma decidiu. Construir o mecanismo ensina *por quê*, e onde ele falha. Este
repositório é a segunda coisa.

![Dashboard](docs/dashboard.png)

---

## A ideia que define o projeto

A maioria dos projetos de honeypot desemboca numa única pergunta: "isso é um bot?".
Sozinha, essa pergunta não serve — a resposta é quase sempre sim, e ela funde duas
decisões com consequências muito diferentes.

Este classificador mantém as duas separadas:

| Eixo | Pergunta | Evidência |
|------|----------|-----------|
| **Automação** | Tem um humano dirigindo isso? | Propriedades do client stack: conjunto de headers, ordem dos headers, metadados `Sec-Fetch-*`, Client Hints |
| **Intenção** | O que ele está tentando fazer? | Comportamento ao longo do tempo: enumeração de paths, payloads com forma de exploit, rotação de usuários, iteração de catálogo |

Um monitor de uptime pontua alto em automação e não tem intenção hostil nenhuma. Um
credential stuffing vindo de um pool de proxies residenciais pode parecer quase um
navegador e ainda assim ser um ataque. Colapsar os dois num score só produz exatamente
a classe de falso positivo que faz uma política de bot voltar para modo alerta — então
os dois são pontuados em separado, e é o eixo de intenção que decide o veredicto.

### Veredictos

| Veredicto | Significado | Equivalente em produção |
|-----------|-------------|-------------------------|
| `verified_crawler` | Identidade provada por rDNS confirmado | Allowlist — nunca desafiar |
| `vuln_scanner` | Enumerando artefatos ou enviando payloads com forma de exploit | Bloquear |
| `credential_attack` | Tentativas de autenticação com rotação de usuários | Bloquear + rate limit |
| `content_scraper` | Iteração sistemática de conteúdo, ou impersonação de crawler | Desafiar ou tarpit |
| `recon_probe` | Tocando superfície administrativa sem padrão claro ainda | Monitorar |
| `unclassified_automation` | Automatizado, intenção ainda ilegível | **Somente alerta** |
| `likely_human` | Fingerprint de navegador consistente, baixa velocity | Permitir |

`unclassified_automation` é deliberadamente um balde de espera, e não um concorrente
dos veredictos de intenção. Mover uma regra de alerta para bloqueio é uma decisão que
exige evidência, e essa é a fila onde a evidência se acumula.

### Todo veredicto carrega sua evidência

Nenhum score é emitido sem os sinais que o produziram. Isso não é um detalhe: um
veredicto que você não consegue explicar é um veredicto que você não consegue defender
quando o cliente abre um chamado perguntando por que a integração dele foi bloqueada.

```json
{
  "verdict": "vuln_scanner",
  "confidence": 0.83,
  "automation_score": 7.0,
  "human_score": 0.0,
  "signals": [
    {"name": "sensitive_artifact_request", "weight": 4.0, "detail": "/.env"},
    {"name": "path_enumeration",           "weight": 4.0, "detail": "70 paths"},
    {"name": "high_404_ratio",             "weight": 2.5, "detail": "95%"},
    {"name": "automation_user_agent",      "weight": 3.5, "detail": "nikto"}
  ]
}
```

---

## Arquitetura

```
                    ┌──────────────────────────────────────────┐
   internet ───────▶│  edge (nginx)                            │
                    │  · define X-Edge-Client-IP sem exceção   │
                    │  · aplica rate limit                     │
                    │  · devolve 404 para /_edl/*              │
                    └───────────────────┬──────────────────────┘
                                        │
                    ┌───────────────────▼──────────────────────┐
                    │  sensor (FastAPI)                        │
                    │                                          │
                    │  decoys ──▶ respostas estáticas inertes  │
                    │  fingerprint ──▶ sinais do client stack  │
                    │  enrich ──▶ rDNS confirmado              │
                    │  storage ──▶ agregados de velocity       │
                    │  classifier ──▶ veredicto explicável     │
                    └───────────────────┬──────────────────────┘
                                        │
                              SQLite (WAL) ──▶ /_edl/dashboard
```

As notas completas de design, incluindo o threat model do próprio sensor, estão em
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Rodando

```bash
git clone https://github.com/amancio-g08/edge-deception-lab.git
cd edge-deception-lab

cp .env.example .env          # defina EDL_CREDENTIAL_SALT com um valor único
docker compose up --build -d

# gera tráfego sintético para haver o que analisar
python tools/simulate_traffic.py --rounds 20 --simulate-edge

# dashboard (ligado ao loopback por design)
open http://127.0.0.1:8081/_edl/dashboard
```

`--simulate-edge` atribui a cada perfil de cliente um endereço de origem sintético,
tirado das faixas de documentação da RFC 5737. Sem ele todos os perfis compartilham um
endereço só e os agregados de velocity colapsam num único cliente — o que, aliás, é uma
boa demonstração do problema de IP compartilhado que o classificador precisa suportar.

### Sem Docker

Tudo exceto a camada de edge nginx roda só com Python:

```bash
pip install -r honeypot/requirements.txt
EDL_DB_PATH=./data/events.db python -m uvicorn honeypot.app.main:app --port 8080
python tools/simulate_traffic.py --target http://127.0.0.1:8080 --rounds 20 --simulate-edge
pytest -q
```

Depois abra `http://127.0.0.1:8080/_edl/dashboard`. Rodar o sensor direto significa não
ter camada de edge na frente, então `X-Edge-Client-IP` não é sobrescrito — o que serve
para trabalho local, nunca para algo exposto.

### Configuração

| Variável | Padrão | Para que serve |
|----------|--------|----------------|
| `EDL_DB_PATH` | `/data/events.db` | Localização do SQLite |
| `EDL_CREDENTIAL_SALT` | `edge-deception-lab` | **Troque isso.** Salt de todos os digests armazenados |
| `EDL_VERIFY_BOT_RDNS` | `true` | rDNS confirmado para verificação de crawler |
| `EDL_VELOCITY_WINDOW` | `300` | Janela deslizante, em segundos, dos sinais de velocity |
| `EDL_STORE_IP_RAW` | `true` | Use `false` para guardar apenas o hash salgado dos IPs de origem |
| `EDL_PUBLIC_BIND` | `127.0.0.1` | Endereço de bind do edge — mude apenas ao expor deliberadamente |

---

## Segurança

Isto é um sensor, não um alvo. Três propriedades são garantidas em código e travadas
por testes:

**Nada explorável.** Toda resposta-isca é uma string estática. Sem renderização de
template com entrada do usuário, sem leitura de arquivo dirigida pelo path, sem
desserialização. O formulário de login sempre falha — um honeypot que concede acesso
convida o atacante a gastar esforço real dentro dele, o que é passivo e não sinal.

**Nenhuma credencial em texto claro.** Senhas, tokens, cookies e headers
`Authorization` são reduzidos a um digest SHA-256 salgado antes de qualquer
armazenamento. Tentativas repetidas continuam se correlacionando; o operador nunca fica
com uma credencial utilizável colhida de terceiros. Veja `tests/test_redact.py` — se
esses testes falharem, o laboratório não é seguro para rodar.

**A análise é invisível.** O veredicto nunca aparece em header de resposta, em timing
ou em status code. Um cliente capaz de detectar que está sendo perfilado muda de
comportamento, e o sensor deixa de ser sensor.

> **Antes de expor isso à internet:** rode num host isolado, sem acesso lateral a nada
> que importe, defina um `EDL_CREDENTIAL_SALT` único e verifique a política de abuso do
> seu provedor. Capturar tráfego enviado à sua própria infraestrutura é uma coisa; onde
> você hospeda, e o que faz com os dados depois, é responsabilidade sua — inclusive
> perante a LGPD, já que IP de origem é dado pessoal. `EDL_STORE_IP_RAW=false` mantém
> apenas hashes salgados.

---

## Limitações conhecidas

Ditas às claras, porque uma ferramenta de segurança que esconde os próprios pontos
cegos é pior do que uma que não os tem.

- **IP é uma identidade fraca.** Os agregados de velocity são chaveados pelo endereço
  de origem, então um CGNAT ou saída corporativa mistura muitos usuários num perfil só.
  O gate de rotação de usuários mitiga o pior caso; identidade construída sobre o
  fingerprint do cliente está no roadmap.
- **Ainda sem fingerprint de TLS.** JA4/JA3 vive abaixo do proxy reverso e é o sinal de
  automação mais forte disponível. Até isso existir, um cliente que reproduz headers de
  navegador perfeitamente não é distinguível de um navegador.
- **Os limiares são ajustados à mão.** Os pesos vêm de raciocínio sobre como esses
  clientes se comportam, validados contra perfis sintéticos e uma suíte de regressão de
  falsos positivos — não de um corpus rotulado.
- **A verificação de rDNS é best-effort.** As consultas são cacheadas e limitadas no
  tempo; falha de resolver rebaixa um crawler legítimo para não verificado, em vez de
  liberar por omissão.

---

## Testes

```
33 passed
```

A suíte é dividida pelo que cada parte protege:

| Arquivo | Protege |
|---------|---------|
| `test_classifier.py` | Os veredictos para comportamento sabidamente hostil |
| `test_false_positives.py` | Clientes legítimos que regras ingênuas marcariam |
| `test_redact.py` | Que nenhuma credencial seja armazenada em texto claro |
| `test_capture.py` | A captura ponta a ponta, e que a análise siga invisível |

---

## Roadmap

O desenvolvimento segue uma branch por capacidade — veja [`ROADMAP.md`](ROADMAP.md)
para o que está planejado e por quê.

---

## Nota sobre idioma

A documentação está em português; **o código, os comentários e as mensagens de commit
estão em inglês**, por ser o padrão em projetos de segurança e o que torna o
repositório legível para quem chega de fora. A versão em inglês deste README está em
[`README.en.md`](README.en.md).

---

## Licença

MIT — veja [`LICENSE`](LICENSE).
