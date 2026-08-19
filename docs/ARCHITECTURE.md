# Arquitetura

## O caminho de uma requisição

```
0. tlsfront (Go, só no caminho HTTPS)
   ├─ lê o primeiro registro TLS antes do handshake tocar nele
   ├─ parseia o ClientHello e calcula o JA4
   ├─ repõe os bytes lidos e deixa o handshake seguir normal
   └─ encaminha com X-Edge-JA4, apagando o que o cliente mandou nesse nome

1. edge (nginx)
   ├─ sobrescreve X-Edge-Client-IP com $remote_addr
   ├─ limit_req (30 r/s, burst 60)
   └─ 404 em /_edl/*

2. sensor (FastAPI, rota catch-all)
   ├─ captura    corpo (truncado), headers, e a ORDEM dos headers
   ├─ enriquece  rDNS confirmado, com cache e timeout
   ├─ fingerprint  sinais de client stack
   ├─ isca       lookup estático da resposta
   ├─ velocity   agregados da janela deslizante pra essa origem
   ├─ classifica scoring ponderado, veredicto e sinais
   ├─ redige     credencial vira digest salgado
   └─ grava      SQLite em WAL

3. resposta
   └─ corpo estático, Server: nginx, nada do veredicto vazando
```

A classificação acontece antes da resposta sair, mas não influencia ela em nada. Isso é
de propósito. Se o cliente conseguir inferir a própria classificação por header, status
ou diferença de tempo, ele adapta o comportamento, e aí o sensor não mede mais nada
real.

## Por que cada peça está aí

**nginx.** É ele que garante a única propriedade da qual toda a captura depende: o
endereço de origem que o sensor confia foi escrito por infraestrutura que o cliente não
controla. O `proxy_set_header X-Edge-Client-IP $remote_addr` sobrescreve o que tiver
chegado com esse nome. Honeypot que acredita no `X-Forwarded-For` do fio tem dado
controlado por atacante dentro dos próprios agregados de velocity, e aí nenhum número
vale nada.

**tlsfront em Go.** O ClientHello é consumido pelo handshake: depois que o `ssl` do
Python pega o socket, aqueles bytes já foram. Ler primeiro significa ler antes de
qualquer outra coisa tocar na conexão, e isso pede um processo que fique na frente.

Go entrou porque compila pra binário estático e porque o `crypto/tls` deixa você
entregar um `net.Conn` seu. O truque é um wrapper que devolve os bytes já lidos antes
de repassar o resto: o fingerprint sai antes do handshake, e o handshake continua sem
saber que alguém leu na frente. Zero dependência externa, só biblioteca padrão, então
`go build` funciona em máquina que nunca viu o repositório.

Só o JA4 de TLS está implementado. O resto da suíte JA4+ está sob FoxIO License 1.1,
que proíbe monetização; o JA4 puro é BSD 3-Clause e serve num projeto MIT.

**SQLite em WAL.** O laboratório tem que clonar e rodar com um comando. WAL evita que a
leitura do dashboard trave a escrita da captura, e o dataset inteiro é um arquivo que dá
pra copiar da máquina e analisar offline. Um escritor só dá conta: o sensor não é
gargalo em nenhum volume que um honeypot recebe.

**FastAPI com docs desligado.** `docs_url`, `redoc_url` e `openapi_url` todos em `None`.
Isca que anuncia FastAPI não está imitando aplicação nenhuma, e o banner de framework é
das primeiras coisas que um scanner anota.

## Modelo de dados

Uma linha por requisição, desnormalizada de propósito. As consultas de análise são
agregação sobre uma tabela só, e um esquema estrela não compraria nada nessa escala
enquanto deixaria o SQL mais chato de ler num repositório cuja graça é ser legível.

Os índices cobrem os quatro padrões de acesso: janela de tempo, origem mais tempo
(velocity), veredicto (breakdown) e path (mais visados).

Duas colunas derivadas carregam quase toda a análise:

`header_order_hash` é o digest dos nomes de header na ordem em que chegaram. Isso é
propriedade da implementação do cliente HTTP, não do conteúdo da requisição. Duas
requisições com o mesmo hash quase certamente saíram da mesma stack, mesmo com
User-Agent diferente.

`src_ip_hash` é o digest salgado do endereço, sempre preenchido. O endereço em claro é
opcional (`EDL_STORE_IP_RAW=false`), então dá pra rodar sem reter dado pessoal e manter
toda a correlação funcionando.

`client_id` é a identidade que não depende do endereço: digest de ordem de header + JA4
+ Accept-Language + família de UA. É o que a velocity usa como chave. Nenhuma dessas
partes sozinha identifica ninguém, mas juntas separam dois clientes atrás do mesmo IP
muito melhor do que o IP separa. Não é pessoa, é assinatura de forma de requisição, e
nunca é tratada como pessoa.

## Dentro do classificador

Sinal é uma tupla `(nome, peso, veredicto, detalhe)`, produzida por cinco extratores
independentes:

| Extrator | Lê | Produz |
|----------|----|--------|
| `_path_signals` | método, path, query | intenção: artefato, forma de exploit, post de login |
| `_fingerprint_signals` | client stack | automação, verificação de crawler |
| `_tls_signals` | JA4 do handshake | stack real do cliente, contradição com o que ele diz ser |
| `_velocity_signals` | janela deslizante por `client_id` | enumeração, rotação, volume |
| `_human_signals` | client stack e janela | evidência contra automação |

Os pesos somam por veredicto. Depois:

Crawler verificado ganha na hora. Provou identidade por rDNS confirmado, nenhum score
de comportamento derruba. É a semântica de allowlist de um bot manager de verdade: um
Googlebot varrendo agressivamente continua sendo Googlebot.

Os veredictos de intenção competem entre si, e `unclassified_automation` fica fora dessa
disputa. Automação é eixo separado. Deixar um fingerprint barulhento vencer um padrão de
ataque inequívoco é o falso negativo que importa.

A confiança mistura três coisas: margem sobre o segundo colocado, magnitude absoluta da
evidência, e um bônus pequeno quando o cliente também parece automatizado. Um 10 contra
9 não pode reportar a mesma certeza de um 10 contra 0.

Se nada de intenção pontuou: automatizado sem intenção legível vira
`unclassified_automation`, e o resto vira `likely_human`.

### Header é alegação, ClientHello é evidência

Quando o JA4 diz que o handshake saiu do OpenSSL e o User-Agent diz Chrome, os sinais
humanos derivados de header não são descontados: eles são **descartados**. `human_score`
vai a zero.

A alternativa seria somar os dois e torcer pro peso do TLS ganhar. Isso faz o resultado
depender de quantos headers o atacante teve paciência de copiar, que é exatamente a
variável sob controle dele. Um cliente com dez headers forjados passaria; com cinco,
não. Descartar remove essa alavanca.

O inverso não vale: fingerprint TLS desconhecido não gera sinal nenhum, nem a favor nem
contra. Não conhecer um cliente é falta de informação, não evidência contra ele.

### O problema de IP compartilhado, remendado e depois resolvido

Apareceu na primeira rodada local, onde todo perfil sintético saía de `127.0.0.1`: um
`GET /admin` voltou marcado como `credential_attack`, porque a rotação de usuário de
outro perfil no mesmo IP tinha contaminado o agregado.

O primeiro remendo foi um gate: rotação de usuário só conta quando a requisição é ela
mesma uma tentativa de autenticação. Isso parou o pior caso, mas a velocity ainda era um
balde por IP, então um scanner e um browser atrás da mesma saída corporativa continuavam
dividindo perfil.

A correção de verdade é a `client_id`: a velocity passou a ser chaveada pela identidade
do cliente, não pelo endereço. O IP ainda estreita a janela (mesmo cliente de um IP novo
é contexto novo, então botnet que roda IP não colapsa num balde só), mas dois clientes
distintos atrás de um IP ganham dois baldes. O gate continua lá como segunda linha, e o
done-when está travado em `test_two_clients_behind_one_ip_have_independent_velocity`.

## Ameaças contra o próprio sensor

O sensor foi feito pra receber tráfego hostil, então é tratado como infraestrutura
não confiável.

| Ameaça | O que impede |
|--------|--------------|
| RCE pela superfície-isca | Nada é avaliado dinamicamente. `decoys.resolve()` é lookup puro de dicionário: sem filesystem, sem template com entrada do usuário, sem desserialização |
| Sensor virar destino de upload | `client_max_body_size 64k` no edge, corpo truncado em `EDL_MAX_BODY_BYTES` antes de gravar |
| Estouro de disco | Rate limit no edge, truncamento de corpo, e o SQLite é o único caminho de escrita |
| Passivo de credencial | Só digest salgado, garantido por `tests/test_redact.py` |
| Atacante perceber o honeypot | Banner de framework desligado, veredicto nunca vaza, `Server: nginx` fixo |
| Container comprometido virar pivô | UID 10001 não-root, código da aplicação somente leitura, só `/data` gravável, dashboard preso no loopback |
| Dado de origem envenenado | Header de IP confiável escrito pelo edge sem exceção |
| JA4 forjado via header | `tlsfront` apaga `X-Edge-JA4*` do cliente antes de escrever o seu |
| Socket aberto e mudo | Deadline de 10s pra ler o ClientHello, registro limitado a 16 KB |

## O que ficou de fora

Resposta ativa. O sensor não bloqueia, não tarpita e não escaneia de volta. Instrumento
de observação que age no tráfego vira participante, com a exposição jurídica que vem
junto.

Software vulnerável de verdade. Nada de CMS desatualizado ou serviço explorável. O valor
está no classificador, e host genuinamente explorável é ponto de apoio de atacante numa
máquina sua.

Machine learning. Com peso ajustado à mão, todo veredicto é rastreável até a regra que
produziu ele. Modelo precisaria de corpus rotulado que esse laboratório não tem, e
trocaria a explicabilidade que torna a saída defensável por uma acurácia que ainda não
dá pra demonstrar.
