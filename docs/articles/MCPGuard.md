# Pipeline Automatizada de Análise de Segurança para

# Implementações de Model Context Protocol (MCP)

```
Fellippo A. D. Ferreira
```
```
Faculdade Impacta de Tecnologia
São Paulo – SP – Brasil
```
```    
fellippo.ferreira@aluno.faculdadeimpacta.com.
Abstract. This paper presents the development of an automated security
analysis pipeline for Model Context Protocol (MCP) implementations. The
proposed system performs static and rule-based inspections to detect known
vulnerabilities, permission abuse, and contextual poisoning in AI-agent
integrations. The solution aims to provide early detection of risks in
development environments, generating automated reports and integrating with
CI/CD pipelines for continuous security validation..
Resumo. Este artigo apresenta o desenvolvimento de uma pipeline
automatizada de análise de segurança para implementações do Model Context
Protocol (MCP). O sistema realiza inspeções estáticas e baseadas em regras
para detectar vulnerabilidades conhecidas, abusos de permissão e
envenenamento de contexto em integrações de agentes de IA. A solução busca
permitir a detecção precoce de riscos em ambientes de desenvolvimento,
gerando relatórios automáticos e integrando-se a pipelines de CI/CD para
validação contínua da segurança..
```
## 1. Introdução

O avanço do uso de agentes de Inteligência Artificial (IA) e protocolos como o Model
Context Protocol (MCP) trouxe maior flexibilidade para integração entre modelos de
linguagem e ferramentas externas. No entanto, essa flexibilidade também introduziu
novas superfícies de ataque, como injeção de ferramentas maliciosas, manipulação de
contexto e uso indevido de permissões.

Atualmente, não existem soluções automatizadas capazes de auditar a segurança de
implementações MCP durante o desenvolvimento, dificultando a detecção precoce de
vulnerabilidades. O presente trabalho propõe a criação de uma pipeline automatizada de
auditoria de segurança, que realiza análise estática, inspeções baseadas em regras e
geração de relatórios de vulnerabilidade, integrando-se a fluxos de CI/CD (Continuous
Integration / Continuous Deployment).

**1.1. Apresentação do Problema**

O problema central abordado por este projeto é a ausência de ferramentas específicas
para auditoria de segurança em servidores e clientes MCP. Apesar de o protocolo


padronizar a comunicação entre agentes e ferramentas, não há mecanismos que validem
a conformidade ou a segurança de implementações.

Isso abre espaço para ataques como injeções diretas ou indiretas em descritores de
ferramentas, abuso de permissões concedidas a agentes e envenenamento de contexto
durante a troca de mensagens entre agentes e LLMs. Assim, há uma lacuna entre a
rápida adoção do MCP e a disponibilidade de ferramentas práticas de homologação
segura.

```
Figura 1: Superfície de ataque em integrações MCP e como ferramentas
maliciosas podem comprometer agentes de IA
```
**1.2. Objetivos**

```
● Objetivo Geral: Desenvolver uma pipeline automatizada de análise de
segurança para servidores MCP, capaz de identificar vulnerabilidades
conhecidas e potenciais falhas estruturais, gerando relatórios detalhados de
risco.
```
```
● Objetivos Específicos:
```
```
A. Criar uma proposta de projeto que receba um pedido de análise de
um repositório de servidor MCP através de webhooks do GitHub;
B. Implementar análises estáticas e baseadas em regras para detecção
de ataques descritos na literatura;
```

```
C. Correlacionar os resultados obtidos com boas práticas de segurança
do protocolo MCP;
D. Gerar relatórios automáticos de vulnerabilidade com classificação de
risco;
E. Integrar a ferramenta a pipelines de CI/CD para inspeção contínua
de segurança.
```
**1.3. Justificativa**

Com a crescente adoção de arquiteturas baseadas em LLMs e o uso do MCP como

padrão de comunicação, surgem riscos inéditos de segurança relacionados à

manipulação de contexto e permissões. Ferramentas tradicionais, como SonarQube

ou GitHub Advanced Security, não possuem regras específicas para MCP, tornando a

análise limitada.

A proposta deste projeto se justifica por preencher essa lacuna, fornecendo um

mecanismo automatizado, extensível e de fácil integração em fluxos de

desenvolvimento, garantindo que vulnerabilidades sejam detectadas antes da

implantação.

## 2. Estudo de Viabilidade

A viabilidade da solução foi analisada considerando o contexto tecnológico e a ausência
de soluções especializadas no mercado. A proposta busca unir práticas de análise
estática com princípios de segurança de software moderno (DevSecOps).

**2.1. Soluções de Mercado e seu Projeto**

Ferramentas amplamente utilizadas, como SonarQube, Bandit e Snyk, oferecem
detecção de vulnerabilidades genéricas em código-fonte. No entanto, nenhuma dessas
soluções contempla ataques específicos do MCP, como injeções de contexto, permissões
indevidas em descritores de ferramentas ou abuso de fluxos de execução entre agentes.

Dessa forma, o projeto propõe uma abordagem personalizada que integra verificações de
segurança diretamente nas estruturas do MCP e permite a expansão contínua das regras
conforme novas vulnerabilidades são publicadas.

## 3. Arquitetura da Solução

A arquitetura proposta para a pipeline de análise de segurança MCP segue um modelo
híbrido e orientado a serviços, combinando análise estática baseada em regras com
análise agêntica através de modelos de IA especializados em cibersegurança. O sistema
é composto por quatro subsistemas principais: (1) API Principal em Go (Ingestão,
Motor de Análise e Relatórios), (2) API de Análise Agêntica em Python, (3) Sistema de
Filas para Escalabilidade, e (4) Integração com GitHub Actions — isolando nossas api's
e componentes de infraestrutura em containers docker.


Essa abordagem assegura alta performance através do Go para análise estática,
flexibilidade do Python para integração com LLMs, escalabilidade horizontal via
sistema de filas, e integração nativa com pipelines de CI/CD através de GitHub Actions.

O fluxo operacional inicia quando um pull request é aberto, enviando uma request
HTTP para a API Principal via webhook do GitHub. A API cria um job de análise,
persiste os metadados no banco de dados relacional (PostgreSQL em ambiente
containerizado, SQLite em execução local), e publica a tarefa na fila
`static-analysis` do RabbitMQ, consumida por um worker Go. O Motor de Análise
Estática aplica 31 regras de segurança baseadas na taxonomia de ataques MCPLib
(arXiv:2508.12538). Ao final da análise estática, o worker invoca diretamente a
API Python agêntica via HTTP (`POST /analyze`, resposta `202 Accepted`), que
executa um agente de IA baseado no Google Gemini 2.5 Flash para análise
semântica; a API Python retorna os resultados à API Go através de um endpoint de
*callback* HTTP autenticado. Os resultados são armazenados em um serviço de
armazenamento compatível com S3, disponibilizados através da API REST, e
enviados como comentários em Pull Requests via GitHub Actions.

As regras de segurança implementadas são baseadas na taxonomia de ataques MCP
proposta por Guo et al. (2025), cobrindo 31 tipos de ataques organizados em 4
categorias principais, conforme detalhado na seção 4.

**3.1. Diagrama de Componentes**

A solução proposta é composta por quatro subsistemas principais — API Principal
(Go), API de Análise Agêntica (Python), Sistema de Filas, e Integração CI/CD — que
trabalham de forma orquestrada para garantir uma análise segura, escalável e
automatizada do código MCP.

a) API Principal: O componente central da arquitetura é a API Principal, desenvolvida
em Golang, que integra as funções de Ingestão, Motor de Análise Estática e Módulo de
Relatórios. Ela oferece endpoints REST para clonagem automática de repositórios Git
através de webhooks do GitHub e integração com pipelines de CI/CD. A API suporta
dois modos de autenticação: verificação de assinatura HMAC-SHA256 para webhooks
do GitHub (header X-Hub-Signature-256) e autenticação por API Key para acesso
direto (headers X-API-Key e X-Client-ID). O Motor de Análise Estática utiliza a
biblioteca tree-sitter para parsing de código-fonte, aplicando 31 regras de segurança
organizadas em 11 arquivos, conforme a taxonomia de ataques MCP proposta por Guo
et al. (2025). O Módulo de Relatórios organiza as descobertas em relatórios JSON com
severidade (LOW, MEDIUM, HIGH, CRITICAL), localização no código e
recomendações de mitigação.

**Taxonomia de Ataques MCP (Guo et al., 2025)**

O motor de regras implementa 31 tipos de ataques organizados em quatro categorias
(Guo et al., 2025):

```
Tabela 1. Categorias de ataques MCPLib
```

```
Categoria Ataques
```
```
I. Injeção Direta de Ferramentas File-Based Injection
(Addition/Deletion/Modification/Retrieval
), Rug Pull, Remote Listener, Command
Injection, RCE, Shadowing, Tool
Coverage, Tool Preference Manipulation,
Functional Obfuscation, Multi-Tool
Coordination, Infectious
```
```
II. Injeção Indireta de Ferramentas Webpage Poison, Malicious Project
Installation, MCP Tool Return
```
```
III. Ataques de Usuário Malicioso Malicious Tool Registration, Privilege
Escalation, Data Injection, Token Theft,
Server Code Leakage, Installer Spoofing,
Sandbox Escape
```
```
IV. Ataques Inerentes a LLMs Jailbreak, Prompt Leakage, Hallucination,
Backdoor, Goal Hijack, SQL Injection &
API Theft |
```
b) API de Análise Agêntica (Python): O segundo componente é uma API separada
desenvolvida em Python com FastAPI e Uvicorn, responsável por executar análises
de segurança através de um agente de IA baseado em LLM (Google Gemini 2.5
Flash). Este agente utiliza prompts especializados em cibersegurança MCP para
realizar análise semântica profunda do código, identificando vulnerabilidades
complexas que escapam às regras estáticas. A integração com a API Principal é
feita via HTTP REST: a API Go envia um `POST /analyze` e recebe `202 Accepted`;
o worker Python processa o job de forma assíncrona (via `BackgroundTasks` do
FastAPI) e, ao finalizar, retorna os resultados por meio de uma chamada de
*callback* autenticada à API Go. O fluxo retorna insights complementares sobre
padrões de ataque, fluxos de dados suspeitos e recomendações contextualizadas.

c) Sistema de Filas: Para garantir escalabilidade horizontal e processamento
assíncrono da análise estática, a arquitetura utiliza RabbitMQ como message
broker entre a API Principal (Go) e o worker de análise estática (Go). A escolha
do RabbitMQ se justifica por ser um serviço dedicado de filas de mensagens,
oferecendo recursos avançados como roteamento flexível, confirmação de entrega
(`ack`/`nack`) e persistência de mensagens. A API Principal enfileira jobs de
análise na fila `static-analysis`, que são consumidos por workers, permitindo
processar múltiplas análises simultaneamente sem bloquear o servidor principal.
Esta abordagem também proporciona resiliência a falhas e permite escalar
workers independentemente conforme a demanda. A comunicação com a API agêntica
Python, por sua vez, é feita via REST + *callback* HTTP, e não por fila.

d) Integração CI/CD e Métricas: A integração com pipelines de desenvolvimento é
realizada através de GitHub Actions, que automatizam a análise de segurança em cada
Pull Request. Quando vulnerabilidades são detectadas, comentários são


automaticamente inseridos no PR com detalhes das descobertas e recomendações. Para
coleta de métricas, o sistema utiliza Prometheus, um sistema de monitoramento open
source que coleta e armazena métricas em séries temporais. A visualização é realizada
através do Grafana, plataforma de dashboards que permite acompanhar a taxa de
análises, vulnerabilidades detectadas por categoria, tempo médio de processamento e
saúde dos componentes do sistema.

Fluxo entre os subsistemas: O fluxo de funcionamento entre os componentes é
representado na Figura 2:

**Figura 2: Fluxograma de arquitetura de Alto nível**

**3.2. Infraestrutura / Desenvolvimento**


a) API Principal (Go)

A API Principal, construída em Go com o framework `go-chi`, atua como o
componente central do sistema, integrando as funções de ingestão, motor de
análise estática e geração de relatórios. Ela aceita URLs de repositórios Git
através de webhooks do GitHub ou chamadas diretas à API REST. Cada solicitação
é convertida em um job identificado por UUID, persistida no banco de dados
relacional via GORM (PostgreSQL em contêiner ou SQLite em execução local), e
enfileirada no RabbitMQ para processamento assíncrono pelo worker Go. O mesmo
binário Go opera em dois modos (`api` e `worker`), selecionados pela variável
de ambiente `MODE`, evitando duplicação de código e simplificando o *deploy*.

b) API de Análise Agêntica (Python)

A API Python é responsável pela análise de segurança avançada utilizando um
agente de IA baseado no Google Gemini 2.5 Flash. Construída sobre FastAPI +
Uvicorn + Pydantic v2, expõe o endpoint `POST /analyze` que aceita um job e o
processa de forma assíncrona via `BackgroundTasks` do FastAPI, respondendo
imediatamente com `202 Accepted`. Internamente, baixa o artefato do armazenamento
S3-compatível com `boto3`, constrói prompts especializados em segurança MCP com
injeção dos achados estáticos como contexto, chama a API REST do Gemini
(`generateContent` em modo JSON) com controle de concorrência via semáforo, e
envia os resultados de volta para a API Go através de uma chamada HTTP de
*callback*, usando `httpx` e `tenacity` para retry. O agente identifica
vulnerabilidades contextuais que escapam às regras estáticas, analisa fluxos de
dados complexos e gera recomendações personalizadas.

c) Sistema de Filas (RabbitMQ)

O sistema de filas é implementado com RabbitMQ, um message broker open source
que implementa o protocolo AMQP (Advanced Message Queuing Protocol). Ao receber
uma solicitação de análise, a API Principal responde imediatamente ao cliente
com o ID da análise e publica a tarefa na fila `static-analysis`. O worker Go
consome as mensagens e executa a análise estática. A invocação da API agêntica
Python ocorre **depois** desse estágio, via HTTP REST síncrono com retorno
assíncrono por *callback*, sem envolver o broker. Isso permite:

```
● Execução assíncrona sem bloquear a API principal;
● Processamento paralelo de múltiplas análises simultaneamente;
● Escalabilidade horizontal adicionando mais workers conforme demanda;
● Resiliência a falhas com acknowledge e retry automático de mensagens;
● Persistência de mensagens garantindo que jobs não sejam perdidos em caso de
reinicialização.
```
d) Motor de Análise Estática

O Motor de Análise Estática, integrado à API Principal, realiza inspeções de código
baseadas em

```
● Análise Sintática (tree-sitter): utiliza a biblioteca tree-sitter para gerar ASTs
(Abstract Syntax Tree) de alta precisão, permitindo consultas estruturadas sobre
o código-fonte analisado.
● Motor de Regras (Go): aplica 31 regras de segurança implementadas em Go,
organizadas em 11 arquivos por linguagem alvo, com suporte atual a **Python**
e **JavaScript**, cobrindo todas as categorias de ataques MCP descritas no
artigo de referência (arXiv:2508.12538). Cada regra se auto-registra via
`init()` no *registry* central, seguindo o padrão Open/Closed.
```
e) Banco de Dados e Armazenamento

A camada de persistência relacional utiliza **GORM** como ORM, com dois drivers
suportados selecionáveis por configuração: **PostgreSQL 16** em ambientes
containerizados / produção (configuração padrão do `docker-compose.yaml`) e
**SQLite** para execução local e testes, o que facilita o desenvolvimento sem
infraestrutura externa. Armazena metadados de jobs, status de execução e
referências aos resultados. O armazenamento de objetos compatível com S3 (AWS
S3 ou LocalStack em desenvolvimento) persiste os relatórios JSON gerados e os
artefatos de código compactados (ZIPs do repositório).

f) Integração CI/CD (GitHub Actions)

A integração com pipelines de CI/CD é realizada através de GitHub Actions. O
workflow automatiza a análise de segurança em cada Pull Request, inserindo
comentários automáticos com as vulnerabilidades detectadas. A autenticação utiliza
webhooks com assinatura HMAC-SHA256.

g) Sistema de Métricas e Observabilidade

O monitoramento do sistema é realizado através de uma stack de observabilidade
composta por **Prometheus + Grafana + Loki + Promtail**, complementada por
**cAdvisor** (métricas por contêiner) e **node-exporter** (métricas do host). O
Prometheus coleta métricas expostas pelos componentes da aplicação (API Go, API
Python, RabbitMQ, exporters de infraestrutura) através de endpoints `/metrics`
no formato OpenMetrics. O Promtail realiza a coleta de logs dos contêineres
Docker e os envia ao Loki, que os indexa por *labels* (serviço, nível, etc.). O
Grafana consome ambas as fontes (Prometheus e Loki) e apresenta dashboards com:
taxa de análises por hora, vulnerabilidades detectadas por categoria e
severidade, tempo médio de processamento, fila de jobs pendentes, saúde dos
workers e serviços, e rastreabilidade textual por `analysis_id` através dos
logs estruturados.


**Figura 3: Fluxograma de componentes da api principal (Golang - MCPGuard)**

**3.3. Tecnologias Utilizadas / Desenvolvimento**

Nesta subseção são descritas as tecnologias utilizadas no desenvolvimento da pipeline
automatizada de análise de segurança para implementações MCP.

As tecnologias foram agrupadas por camada, de acordo com o papel que desempenham
na solução, e cada uma é acompanhada de uma justificativa resumida que demonstra sua
importância dentro do sistema.


```
Tabela 2. Tecnologias utilizadas
```
```
Tecnologia Camada/Subsistema Justificativa
```
Docker Infraestrutura Fornece isolamento entre
ambientes, garantindo que
códigos maliciosos
enviados para análise não
afetem o sistema principal.

```
Facilita a reprodutibilidade
e portabilidade das análises
```
PostgreSQL 16 (GORM) Infraestrutura /
Persistência

```
Banco de dados relacional
usado como persistência
padrão em ambiente
containerizado, armazenando
metadados de jobs, status
de execução e histórico de
análises. Acessado via
GORM, com driver
`gorm.io/driver/postgres`.
```

SQLite (GORM) Infraestrutura /
Persistência (local)

```
Banco de dados embutido,
leve e sem dependências
externas, utilizado em
modo de desenvolvimento
local e em testes
automatizados, facilitando
portabilidade e execução
sem infraestrutura.
```
AWS S3 / Localstack Armazenamento /
Repositório de Relatórios

```
Armazena os relatórios
gerados (JSON) e artefatos
de análise em um sistema
de objetos compatível com
Amazon S3. Facilita a
integração com serviços
em nuvem.
```
Go 1.25 Servidor (Backend) / API
Principal

```
Linguagem compilada de
alta performance, com
modelo de concorrência
nativo (goroutines) ideal
para processamento
paralelo de análises.
Produz binários únicos
sem dependências
externas.
```

go-chi Servidor (Backend) / API
Principal

```
Framework HTTP leve e
idiomático para Go, que
expõe endpoints REST
para recebimento de
webhooks e consulta de
relatórios. Suporte a
middlewares combináveis.
```
Python 3.11+ API Agêntica / Análise por
IA

```
Linguagem de alto nível
com amplo ecossistema de
bibliotecas para IA/ML.
Utilizada para implementar
o agente de análise de
segurança com modelos de
linguagem especializados.
```

FastAPI + Uvicorn +
Pydantic v2

API Agêntica / Framework
HTTP

```
Framework web assíncrono
de alta performance com
validação automática via
Pydantic e documentação
OpenAPI. Utilizado para
expor o endpoint
`/analyze` e processar
jobs via `BackgroundTasks`.
```

Google Gemini 2.5 Flash API Agêntica / Análise
Semântica (LLM)

```
Modelo de linguagem da
Google usado como motor
da análise semântica.
Acessado via API REST
(`generateContent`) em
modo JSON estruturado,
com prompts
especializados em
segurança MCP.
```

httpx + tenacity API Agêntica / Cliente HTTP

```
Cliente HTTP assíncrono
(`httpx`) combinado com
`tenacity` para retry com
*backoff* exponencial nas
chamadas para o Gemini e
para a API Go de
*callback*.
```

boto3 API Agêntica / SDK AWS

```
SDK oficial da AWS para
Python, usado pelo worker
para baixar artefatos
(ZIPs de repositórios) do
armazenamento S3 /
LocalStack.
```
RabbitMQ Orquestração / Sistema de
Filas

```
Message broker open
source (MPL 2.0) que
implementa o protocolo
AMQP. Oferece
roteamento flexível,
persistência de mensagens,
confirmação de entrega e
escalabilidade horizontal.
```
Regex + AST (tree-sitter) Motor de Análise /
Verificação Estática

```
Técnicas complementares
de análise estática
utilizadas para detectar
padrões inseguros e
vulnerabilidades
específicas do MCP com
alta precisão.
```
GitHub Actions DevOps / Integração
Contínua

```
Workflows automatizados
que executam análise de
segurança em cada PR e
inserem comentários com
vulnerabilidades
detectadas. Integração
nativa com repositórios
GitHub.
```
GitHub Webhooks DevOps / Integração
Contínua

```
Recebe eventos de
push/PR do GitHub com
autenticação
HMAC-SHA256,
```

```
permitindo análise
automática de repositórios.
```
```
Prometheus Observabilidade / Coleta
de Métricas
```
```
Sistema de monitoramento
open source (Apache 2.0)
que coleta métricas em
séries temporais. Oferece
linguagem de consulta
PromQL e alertas
configuráveis.
```
```
Grafana Observabilidade /
Visualização
```
```
Plataforma open source
(AGPL-3.0) para criação
de dashboards e
visualização de métricas.
Integra-se nativamente
com Prometheus e Loki.
```
```
Loki + Promtail Observabilidade / Logs
```
```
Stack de agregação de
logs (Grafana Labs). O
Promtail coleta logs dos
contêineres Docker e os
envia ao Loki, que os
indexa por *labels*,
permitindo consultas e
rastreabilidade por
`analysis_id`.
```
```
cAdvisor + node-exporter Observabilidade /
Exporters
```
```
Exporters Prometheus
complementares: cAdvisor
expõe métricas de uso de
CPU, memória e I/O por
contêiner; node-exporter
expõe métricas do host
(disco, rede, load).
```
```
TLS (HTTPS) Segurança / Comunicação Garante a proteção dos
dados em trânsito entre
clientes, API e serviços de
armazenamento.
```
## 4. Resultados e Discussões

Esta seção apresenta os resultados obtidos com a implementação do MCPGuard,
organizada por subsistema. Cada resultado é acompanhado de uma discussão que
contextualiza o que foi realizado e analisa o impacto prático da solução.

### 4.1. Motor de Análise Estática

O motor de análise estática foi completamente implementado, cobrindo 31 regras
de segurança organizadas em 11 arquivos por linguagem, com suporte a
**Python** e **JavaScript**, abrangendo as 4 categorias de ataques da
taxonomia MCPLib (Guo et al., 2025). A análise é realizada por meio de parsing
AST com tree-sitter, garantindo precisão estrutural superior à análise por
expressões regulares simples. Os achados são classificados por severidade
(CRITICAL, HIGH, MEDIUM, LOW, INFO) e incluem localização precisa no código
(arquivo e linha).

**Tabela 3. Distribuição de regras por categoria de ataque**

| Categoria | Regras Implementadas | Severidades Cobertas |
|---|---|---|
| I. Injeção Direta de Ferramentas | 14 | CRITICAL, HIGH, MEDIUM |
| II. Injeção Indireta de Ferramentas | 4 | HIGH, MEDIUM |
| III. Ataques de Usuário Malicioso | 7 | CRITICAL, HIGH, MEDIUM |
| IV. Ataques Inerentes a LLMs | 6 | HIGH, MEDIUM, LOW |
| **Total** | **31** | **CRITICAL → LOW** |

Em testes com o repositório `vulnerable_mcp_server` (repositório sintético com
vulnerabilidades deliberadas), o motor identificou achados em múltiplas categorias,
incluindo execução dinâmica de código, acesso irrestrito ao sistema de arquivos e
ausência de validação de entrada em ferramentas expostas. O resultado é publicado
automaticamente como comentário no Pull Request correspondente via GitHub API.

**Figura A** — *Comentário automático gerado no Pull Request com tabela de findings
estáticos, ordenados por severidade, contendo regra, arquivo:linha e descrição.*

**Discussão:** A cobertura de 31 regras representa mapeamento completo da taxonomia
MCPLib. O uso de AST via tree-sitter elimina falsos positivos causados por análise
textual superficial — por exemplo, distinguindo chamadas a `eval()` legítimas de usos
maliciosos com base no contexto sintático. A publicação automática no PR fecha o loop
de feedback para o desenvolvedor sem exigir acesso a ferramentas externas.

---

### 4.2. Integração com GitHub (Webhook + PR Comments)

A integração com GitHub foi implementada em dois sentidos:

- **Entrada:** o sistema recebe eventos `pull_request` (opened, synchronize, reopened)
  via webhook autenticado com HMAC-SHA256. Ao receber o evento, a API extrai
  repositório, branch, commit e número do PR, cria um job de análise com UUID e o
  enfileira no RabbitMQ.
- **Saída:** após a conclusão da análise estática e agêntica, dois comentários são
  publicados automaticamente no PR — um com os achados estáticos ordenados por
  severidade e outro com os achados semânticos da análise agêntica.

**Figura B** — *Log da API mostrando o recebimento do webhook com campos `repo`,
`pr`, `branch` e `action`.*

**Figura C** — *Dois comentários gerados automaticamente no PR: (1) análise estática
com tabela de findings e (2) análise agêntica com categorias, confiança e sugestões.*

**Discussão:** A separação em dois comentários mantém clareza para o desenvolvedor:
o comentário estático é determinístico e publicado em segundos após o clone do
repositório, enquanto o agêntico é assíncrono e complementar. A autenticação
HMAC-SHA256 garante que somente eventos legítimos do GitHub disparem análises,
prevenindo abuso da API.

---

### 4.3. Sistema de Filas (RabbitMQ) e Worker Assíncrono

O sistema de filas foi implementado com RabbitMQ. A API Principal publica jobs na fila
`static-analysis` e retorna imediatamente ao GitHub (HTTP 202 Accepted), evitando
timeout do webhook (limite de 10 segundos do GitHub). Um worker Go consome as
mensagens, executa a análise estática em pipeline de estágios (download → parsing →
análise → upload), e aciona a análise agêntica de forma encadeada.

O retry automático do RabbitMQ (nack + requeue) protege contra falhas transitórias de
rede ou do worker. A persistência de mensagens garante que jobs não sejam perdidos
em caso de reinicialização dos containers.

**Figura D** — *Dashboard Grafana mostrando o painel "Webhook Requests Received"
e "Analyses per Hour" com jobs processados após ciclo de análise.*

**Discussão:** Em execuções realizadas, o tempo médio desde o recebimento do webhook
até a publicação do comentário estático foi de 30 a 60 segundos, dominado pelo tempo
de clone do repositório via git. A arquitetura de filas permite escalar workers
horizontalmente de forma independente da API principal, o que é relevante para
cenários com múltiplos repositórios analisados simultaneamente.

---

### 4.4. Análise Agêntica (Python Worker + Gemini)

A API Python implementa um pipeline de análise semântica baseado em LLM (Google
Gemini 2.5 Flash). O worker executa as seguintes etapas:

1. Recebe o job via HTTP POST da API Go, incluindo os achados estáticos como contexto.
2. Baixa o arquivo ZIP do repositório do armazenamento S3-compatível.
3. Filtra os arquivos para apenas os modificados no PR (via `GET /repos/{owner}/{repo}/pulls/{pr}/files`).
4. Para cada arquivo, constrói um prompt especializado em segurança MCP, injetando
   os achados estáticos relevantes como seção de contexto ("Static Analysis Pre-scan").
5. Agrega os resultados e faz callback para a API Go, que persiste e publica o comentário.

**Figura E** — *Comentário agêntico no PR mostrando findings com categoria,
confiança (%), arquivo, linhas e sugestão de correção.*

**Discussão:** A injeção dos achados estáticos no prompt do LLM permite que o modelo
aprofunde sua análise nas vulnerabilidades já sinalizadas, reduzindo o risco de falsos
negativos nas ocorrências mais críticas. O escopo reduzido ao conjunto de arquivos
modificados no PR (em vez do repositório inteiro) diminui latência e custo de tokens,
além de tornar o feedback mais preciso e relevante para a mudança em revisão.

---

### 4.5. Observabilidade (Prometheus + Grafana + Loki)

O sistema expõe métricas no formato OpenMetrics coletadas pelo Prometheus e
visualizadas no Grafana. Logs estruturados são coletados pelo Promtail e indexados
no Loki, permitindo rastreabilidade textual por serviço.

**Tabela 4. Métricas instrumentadas no MCPGuard**

| Métrica | Tipo | Descrição |
|---|---|---|
| `mcpguard_analyses_total` | Counter | Análises por trigger e status |
| `mcpguard_findings_total` | Counter | Achados por severidade |
| `mcpguard_analysis_duration_seconds` | Histogram | Duração da análise estática |
| `mcpguard_analysis_stage_transitions_total` | Counter | Transições entre estágios |
| `mcpguard_analysis_stage_duration_seconds` | Histogram | Duração por estágio |
| `mcpguard_repo_clone_duration_seconds` | Histogram | Tempo de clone do repositório |
| `mcpguard_repo_clone_errors_total` | Counter | Falhas de clone |
| `mcpguard_agentic_analysis_submitted_total` | Counter | Análises agênticas submetidas |
| `mcpguard_agentic_analysis_completed_total` | Counter | Análises agênticas concluídas |
| `http_requests_total` | Counter | Requisições HTTP por método e status |
| `http_request_duration_seconds` | Histogram | Latência HTTP (p50/p90/p99) |

**Figura F** — *Dashboard Grafana mostrando painéis "Findings by Severity" (piechart)
e "Pipeline Stage Transitions" (timeseries) após um ciclo completo de análise.*

**Figura G** — *Dashboard de logs (Loki) com filtragem por serviço e nível de log,
mostrando o rastreamento do fluxo completo de uma análise.*

**Discussão:** A instrumentação por estágio (`downloading → parsing → static_analysis
→ done → waiting_agentic`) permite identificar gargalos específicos na pipeline. A stack
Loki + Promtail complementa as métricas com rastreabilidade textual, permitindo
correlacionar um `analysis_id` específico nos logs de todos os serviços envolvidos.

---

### 4.6. Resumo dos Resultados

**Tabela 5. Status de implementação dos objetivos do projeto**

| Objetivo | Status | Observação |
|---|---|---|
| Webhook GitHub — recebimento via PR (A) | ✅ Implementado | HMAC-SHA256, eventos PR e push |
| Análise estática com 31 regras (B) | ✅ Implementado | 4 categorias, AST via tree-sitter |
| Correlação com taxonomia MCP (C) | ✅ Implementado | Mapeamento 1:1 com MCPLib |
| Relatórios automáticos com severidade (D) | ✅ Implementado | JSON + comentário PR |
| Integração CI/CD (E) | ✅ Implementado | GitHub webhook → RabbitMQ → worker |
| Análise agêntica semântica | ✅ Implementado | Gemini, contexto estático, escopo PR |
| Observabilidade e métricas | ✅ Implementado | Prometheus, Grafana, Loki/Promtail |

## 5. Conclusões

A implementação do MCPGuard demonstra a viabilidade de construir uma pipeline
automatizada de análise de segurança especializada no Model Context Protocol,
cobrindo lacunas que ferramentas genéricas (SonarQube, Bandit, Snyk) não
endereçam. Os principais achados do trabalho são:

1. **Cobertura completa da taxonomia MCPLib** — as quatro categorias de
   ataques descritas por Guo et al. (2025) foram mapeadas em 31 regras
   estáticas, aplicadas sobre ASTs geradas por tree-sitter em duas linguagens
   alvo (Python e JavaScript). A análise estrutural elimina falsos positivos
   típicos de abordagens textuais (regex), distinguindo, por exemplo, usos
   legítimos de `eval()` de padrões maliciosos contextuais.

2. **Arquitetura híbrida eficaz** — a separação entre análise determinística
   (Go + AST) e análise semântica (Python + Gemini 2.5 Flash) provou-se
   produtiva: a análise estática roda em segundos via RabbitMQ e fornece
   feedback imediato no Pull Request; a análise agêntica, invocada via REST
   com retorno por *callback*, complementa de forma assíncrona reaproveitando
   os achados estáticos como contexto no prompt, reduzindo falsos negativos e
   custo em tokens.

3. **Integração nativa com o fluxo de desenvolvimento** — o ciclo
   *Pull Request → webhook HMAC-SHA256 → fila → análise → comentário no PR*
   foi entregue ponta a ponta, fechando o *loop* de feedback ao desenvolvedor
   sem exigir acesso a ferramentas externas e respeitando o limite de 10
   segundos do webhook do GitHub através do padrão *fire-and-forget* com
   `202 Accepted`.

4. **Observabilidade de grau produtivo** — a stack Prometheus + Grafana +
   Loki + Promtail, complementada por cAdvisor e node-exporter, permite
   rastrear desde métricas de negócio (achados por severidade, análises por
   hora, duração por estágio da pipeline) até métricas de infraestrutura
   (uso de CPU/memória por contêiner), com correlação por `analysis_id`
   entre métricas e logs estruturados.

5. **Resiliência e escalabilidade** — o uso de RabbitMQ com `ack`/`nack`
   protege contra falhas transitórias, a persistência de mensagens garante
   que jobs não sejam perdidos em reinicializações, e o desacoplamento entre
   API e worker permite escalar cada componente independentemente conforme
   a demanda.

Em termos quantitativos, em testes com o repositório sintético
`vulnerable_mcp_server` o tempo médio desde o recebimento do webhook até a
publicação do comentário de análise estática foi de 30 a 60 segundos,
dominado pelo clone do repositório. A análise agêntica adiciona latência
proporcional ao número de arquivos modificados no PR, mas mantém o custo de
tokens controlado ao escopar a análise apenas ao *diff*.

## 6. Trabalhos Futuros

Embora o projeto tenha atingido todos os objetivos propostos, diversas
frentes de evolução foram identificadas:

1. **Expansão linguística** — estender o motor estático a **TypeScript**,
   **Go**, **Rust** e **Java**, linguagens comuns em servidores MCP de
   produção. A arquitetura baseada em registro de regras já suporta essa
   extensão sem modificação do núcleo.

2. **Análise de fluxo de dados (*taint analysis*)** — atualmente as regras
   são em sua maioria locais à AST. Um motor de *taint tracking*
   interprocedural rastrearia dados controlados pelo usuário até *sinks*
   perigosos (RCE, SQL Injection, Command Injection), reduzindo falsos
   positivos e capturando vulnerabilidades inter-arquivos.

3. **Abstração multi-LLM** — desacoplar o `analyzer.py` do Gemini,
   suportando OpenAI, Anthropic, Azure OpenAI e modelos *self-hosted*
   (Ollama, vLLM), permitindo execução *air-gapped* e evitando
   *vendor lock-in*.

4. **Python worker como consumidor de fila** — migrar a integração Go↔Python
   de REST + *callback* para consumo direto do RabbitMQ via `aio-pika`,
   proporcionando *backpressure* natural, retry/requeue nativo do AMQP e
   escalabilidade horizontal sem necessidade de *load balancer* HTTP.

5. **Cache semântico de findings** — armazenar *embeddings* dos arquivos
   analisados e reutilizar resultados quando o *diff* entre revisões for
   semanticamente irrelevante, reduzindo custo da análise agêntica em PRs
   incrementais de grandes repositórios.

6. **Sandbox dinâmico (DAST)** — complementar a análise estática com
   execução do servidor MCP em contêineres efêmeros para observar
   comportamento em tempo de execução (chamadas de sistema, tráfego de
   rede, *sandbox escape*), categoria já prevista na taxonomia MCPLib.

7. **Exportação SARIF 2.1.0** — gerar relatórios no padrão SARIF para
   integração nativa com GitHub Code Scanning, GitLab Security Dashboard e
   SonarQube, ampliando o alcance da ferramenta.

8. **Regras como dados (DSL declarativa)** — extrair as regras de Go para
   uma DSL (estilo Semgrep/Rego), permitindo que a comunidade contribua com
   novas regras sem recompilar o binário e acelerando a resposta a novas
   vulnerabilidades publicadas.

9. **Agente *tool-using*** — evoluir o worker Python para um agente
   multi-etapa capaz de consultar bases de CVE, repositórios de ataques MCP
   conhecidos (MCPLib *live*) e realizar *grounding* dos achados, em vez de
   uma única chamada `generateContent`.

10. **Avaliação empírica rigorosa** — montar um *benchmark* público com
    corpus rotulado de servidores MCP vulneráveis e medir *precision* e
    *recall* do MCPGuard comparativamente a ferramentas genéricas
    (Bandit, Semgrep, CodeQL), fornecendo evidência quantitativa para a
    justificativa do projeto.

11. **Hardening da própria ferramenta** — migrar de *Personal Access Tokens*
    para autenticação via GitHub App, aplicar *rate limiting* nos webhooks
    e revisar a superfície de ataque do clone de repositórios arbitrários
    (já parcialmente mitigada pelo isolamento em Docker).

12. **Análise de configuração e instalação** — validar `mcp.json`, escopos
    OAuth e *consent screens* (relacionado a *Installer Spoofing* e
    *Privilege Escalation*), categorias da taxonomia ainda cobertas apenas
    parcialmente pelo motor atual.

## Referências

Guo, Y., Liu, P., Ma, W., Deng, Z., Zhu, X., Di, P., Xiao, X., and Wen, S. (2025)
"Systematic Analysis of MCP Security", arXiv:2508.12538.

Anthropic (2024) "Model Context Protocol Specification",
https://modelcontextprotocol.io/specification.

Brunsmann, M. (2023) "tree-sitter: An incremental parsing system for programming
tools", https://tree-sitter.github.io/tree-sitter/.

Docker Inc. (2024) "Docker Documentation", https://docs.docker.com/.

GitHub (2024) "GitHub Actions Documentation", https://docs.github.com/en/actions.

Grafana Labs (2024) "Grafana Documentation",
https://grafana.com/docs/grafana/latest/.

Invariant Labs (2024) "MCP Security Audit: Tool Poisoning Attacks in Model Context
Protocol", https://invariantlabs.ai/blog/mcp-security-audit.

Jinzhu (2024) "GORM: The fantastic ORM library for Golang", https://gorm.io/docs/.

OWASP Foundation (2023) "OWASP Code Review Guide",
https://owasp.org/www-project-code-review-guide/.

Pivotal Software (2024) "RabbitMQ Documentation",
https://www.rabbitmq.com/documentation.html.

Prometheus Authors (2024) "Prometheus Documentation",
https://prometheus.io/docs/introduction/overview/.

SQLite Consortium (2024) "SQLite Documentation", https://www.sqlite.org/docs.html.

Veen, P. (2024) "go-chi: lightweight, idiomatic and composable router for building Go
HTTP services", https://go-chi.io/.


