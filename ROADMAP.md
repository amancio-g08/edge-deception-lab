# Roadmap

One branch per capability, merged with `--no-ff` so the history keeps the shape of the
work. Nothing here blocks anything else; the lab already runs without all of it.

Naming: `feat/`, `fix/`, `docs/`, `chore/`.

## Já feito

Superfície-isca inerte, fingerprint de requisição, verificação de crawler por rDNS
confirmado, classificador de dois eixos com sinais explicáveis, persistência em SQLite,
dashboard, camada nginx, Docker Compose, fingerprint de TLS, identidade por fingerprint e 61 testes.

Branches: `feat/decoy-surface`, `feat/fingerprinting`, `feat/classifier`,
`feat/storage`, `feat/sensor`, `feat/edge-layer`, `feat/dashboard`,
`feat/traffic-simulator`, `fix/shared-ip-false-positives`.

E o `tlsfront`: terminação TLS em Go que lê o ClientHello antes do handshake, calcula
o JA4 e repassa no header. Com ele, header forjado deixa de funcionar. Branch
`feat/ja4-fingerprinting`.

E identidade por fingerprint: a velocity deixou de ser chaveada por IP e passou a ser
chaveada por uma identidade montada da forma da requisição (ordem de header + JA4 +
Accept-Language + família de UA). Dois clientes atrás do mesmo IP viram dois baldes, e o
falso positivo de NAT que a fase 1 remendava sumiu de vez. Branch `feat/fingerprint-identity`.

## `feat/asn-enrichment`

Saber de qual provedor veio o endereço muda a linha de base. Faixa residencial,
datacenter e pool de proxy conhecido têm expectativas diferentes, e "fingerprint de
navegador saindo de ASN de nuvem" é contradição fácil de pegar.

Base MaxMind GeoLite2 ASN offline, carregada no boot, sem chamada de API em runtime.

Pronto quando: evento carrega ASN e país, e navegador saindo de datacenter sobe o score
de automação.

## `feat/waf-simulation`

É aqui que o projeto encosta de volta no trabalho. Depois de classificar o tráfego, a
pergunta natural é o que uma política real teria feito com aquilo, e quantas requisições
legítimas ela teria pego junto.

Avaliar o tráfego capturado contra um subconjunto de regras no estilo OWASP CRS, em
cada nível de paranoia, e reportar cobertura de detecção contra falso positivo no mesmo
corpus. É a visão que falta pra decidir se dá pra tirar uma regra do alerta.

Pronto quando: sai um relatório dizendo "no nível 2 essa política bloqueia N
requisições hostis e M legítimas", a partir de tráfego real capturado.

## `feat/reporting`

O resultado de uma análise é um documento que alguém lê e age, não um dashboard que
alguém olha de passagem.

Geração agendada: origens mais ativas, agrupamento de campanha por fingerprint, sinais
novos desde a última rodada, mudanças de regra sugeridas com a evidência anexada.
Markdown e PDF.

Pronto quando: `make report` produz algo que dá pra mandar pro cliente sem editar.

## `feat/multi-sensor`

Um sensor enxerga um ponto de vista. Correlacionar o mesmo fingerprint em regiões
diferentes separa campanha direcionada de ruído de fundo da internet.

Sensores empurram evento pra um coletor, correlação de identidade entre eles,
primeiro-visto e último-visto por fingerprint.

Pronto quando: o mesmo cliente sintético batendo em dois sensores aparece como um ator
só.

## O que não vai entrar

Resposta ativa. Nada de bloquear, tarpitar ou escanear de volta. Instrumento de
observação que age no tráfego vira participante, com a exposição jurídica que vem
junto.

Software vulnerável de verdade. Nada de CMS desatualizado ou serviço explorável. A
isca continua inerte, pelos motivos da seção de cuidados do README.
