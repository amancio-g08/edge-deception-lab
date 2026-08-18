# Edge Deception Lab

![ci](https://github.com/amancio-g08/edge-deception-lab/actions/workflows/ci.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![license](https://img.shields.io/badge/license-MIT-4A4A55?style=flat-square)

Português · [English](README.en.md)

Honeypot que classifica quem bate nele pelo comportamento, e não pelo que o cliente
diz ser.

Eu trabalho com Akamai, ou seja, a console mostra o que a plataforma decidiu. Não mostra por quê,
nem onde ela erra. Montei isso pra entender o mecanismo por fora.

O que saiu foi um sensor que serve uma aplicação falsa, captura tudo que chega e emite
um veredicto explicado pra cada requisição.

![Dashboard](docs/dashboard.png)

## A ideia

Os projetos de honeypot que eu olhei respondem uma pergunta só: isso é um bot? Ajuda
pouco, porque a resposta é quase sempre sim.

O que interessa são duas perguntas separadas.

A primeira é se tem alguém dirigindo. Dá pra ver no client-side: quais headers vieram,
em que ordem, se tem `Sec-Fetch-*`, se tem Client Hints. Navegador é muito previsível
nisso. qlqr curl, requests e a maioria dos scanners não são, e essa diferença sobrevive a um
User-Agent falsificado.

A segunda é o que o cliente quer. Isso só aparece no comportamento de longo prazo...

Quantos paths distintos ele varreu?
Mandou um payload com cara de exploit? 


Monitor realtime sempre pontua alto na primeira pergunta e zero na segunda. Credential
stuffing saindo de proxy residencial passa quase liso na primeira e é ataque na
segunda. Juntar as duas num score só cria exatamente o falso positivo que faz o cliente
pedir pra voltar a política toda pra modo alerta.

Então são dois scores. Quem decide o veredicto é o de intenção.

### Veredictos

| Veredicto | O que significa | O que eu faria em produção |
|-----------|-----------------|----------------------------|
| `verified_crawler` | Identidade provada por rDNS confirmado | Allowlist, nunca desafiar |
| `vuln_scanner` | Varrendo artefato ou mandando payload de exploit | Bloquear |
| `credential_attack` | Login com rotação de usuário | Bloquear e limitar |
| `content_scraper` | Iteração sistemática de conteúdo, ou crawler falso | Desafio ou tarpit |
| `recon_probe` | Encostando em superfície administrativa, sem padrão ainda | Monitorar |
| `unclassified_automation` | Automatizado, intenção ilegível | Só alerta |
| `likely_human` | Fingerprint de navegador coerente, pouca velocity | Liberar |

`unclassified_automation` não compete com os outros. Tirar uma regra
do alerta e botar em bloqueio precisa de evidência.

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

O nginx estabelece o IP de origem que o sensor confia, sobrescrevendo o header sem perguntar.

Ps: Não tem como um Honeypot acreditar no`X-Forwarded-For` que veio do fio, isso só da o dado controlado pelo atacante dentro dos próprios
agregados.

Detalhe de design e threat model do sensor em [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). {tmj!}

## Rodando

```bash
git clone https://github.com/amancio-g08/edge-deception-lab.git
cd edge-deception-lab

cp .env.example .env          # troque o EDL_CREDENTIAL_SALT
docker compose up --build -d

python tools/simulate_traffic.py --rounds 20 --simulate-edge
```

Dashboard em `http://127.0.0.1:8081/_edl/dashboard`.

O `--simulate-edge` dá pra cada perfil um IP de origem sintético, das faixas de
documentação da RFC 5737. Sem ele todo mundo sai do mesmo endereço e os agregados de
velocity viram um cliente só.

### Sem Docker

Só o nginx precisa de container. O resto roda com Python:

```bash
pip install -r honeypot/requirements.txt
EDL_DB_PATH=./data/events.db python -m uvicorn honeypot.app.main:app --port 8080
python tools/simulate_traffic.py --target http://127.0.0.1:8080 --rounds 20 --simulate-edge
pytest -q
```

Dashboard em `http://127.0.0.1:8080/_edl/dashboard`. Rodando assim não tem edge na
frente, então o `X-Edge-Client-IP` não é sobrescrito.

### Configuração

| Variável | Padrão | Para que serve |
|----------|--------|----------------|
| `EDL_DB_PATH` | `/data/events.db` | Onde fica o SQLite |
| `EDL_CREDENTIAL_SALT` | `edge-deception-lab` | Salt de todos os digests. Troque |
| `EDL_VERIFY_BOT_RDNS` | `true` | rDNS confirmado pra verificar crawler |
| `EDL_VELOCITY_WINDOW` | `300` | Janela de velocity, em segundos |
| `EDL_STORE_IP_RAW` | `true` | `false` guarda só o hash do IP |
| `EDL_PUBLIC_BIND` | `127.0.0.1` | Bind do edge. Só mude ao expor de propósito |

## Cuidados

O sensor existe pra apanhar, então ele mesmo precisa ser chato de atacar.

Não tem nada executável ali dentro. Toda resposta-isca é uma string estática e sem template, O login sempre falha.

Senha não é gravada. Tudo vira hash SHA-256 antes de chegar no banco. Tentativa repetida continua se correlacionando,
Eu nunca fico com credencial de terceiro utilizável na mão. Está em
`tests/test_redact.py`, e se aquilo quebrar o laboratório não é seguro de rodar.

O cliente também nunca descobre que foi classificado. O veredicto não sai em header,
nem em status. Quem percebe que está sendo "adjetivado" muda de comportamento, e aí o sensor não mede mais nada.

## O que ainda não funciona bem [Juro que vou trabalhar nesse cara]

Velocity é chaveada por IP, então CGNAT e saída corporativa misturam gente. Descobri
isso rodando o simulador local, onde todo perfil sai de `127.0.0.1`: um `GET /admin`
voltou como `credential_attack`, porque a rotação de usuário de outro perfil tinha
contaminado o agregado. Hoje tem um gate que só conta rotação de usuário em tentativa
de autenticação de verdade, e um teste travando isso nos dois sentidos. A correção real
é identidade por fingerprint, que está no roadmap.

Não tem fingerprint de TLS. JA4 fica abaixo do proxy reverso e é o sinal de automação
mais forte que existe. Enquanto não tiver, um cliente que reproduza headers de navegador
direitinho passa como navegador.

## Testes

```
33 passed
```

| Arquivo | O que protege |
|---------|---------------|
| `test_classifier.py` | Veredicto pra comportamento hostil conhecido |
| `test_false_positives.py` | Cliente legítimo que regra gulosa marcaria |
| `test_redact.py` | Que nenhuma credencial vá pro banco em claro |
| `test_capture.py` | Captura ponta a ponta, e que a análise siga invisível |

## Roadmap

Uma branch por capacidade. O que vem por ai, e por quê, está no [`ROADMAP.md`](ROADMAP.md).

## Licença

MIT.
