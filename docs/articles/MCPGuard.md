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
persiste os metadados no banco de dados SQLite, e publica a tarefa na fila do
RabbitMQ. O Motor de Análise Estática aplica 31 regras de segurança baseadas na
taxonomia de ataques MCPLib (arXiv:2508.12538). Paralelamente, a API Python
executa um agente de IA customizado para análise semântica. Os resultados são
armazenados em um serviço de armazenamento compatível com S3, disponibilizados
através da API REST, e enviados como comentários em Pull Requests via GitHub
Actions.

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
desenvolvida em Python, responsável por executar análises de segurança através de um
agente de IA customizado. Este agente utiliza modelos de linguagem especializados em
cibersegurança para realizar análise semântica profunda do código, identificando
vulnerabilidades complexas que escapam às regras estáticas. A API Python recebe
requisições da API Principal via sistema de filas e retorna insights complementares
sobre padrões de ataque, fluxos de dados suspeitos e recomendações contextualizadas.

c) Sistema de Filas: Para garantir escalabilidade horizontal e processamento assíncrono,
a arquitetura utiliza RabbitMQ como message broker. A escolha do RabbitMQ se
justifica por ser um serviço dedicado de filas de mensagens, oferecendo recursos
avançados como roteamento flexível, confirmação de entrega e persistência de
mensagens. A API Principal enfileira jobs de análise que são consumidos pelos workers,
permitindo processar múltiplas análises simultaneamente sem bloquear o servidor
principal. Esta abordagem também proporciona resiliência a falhas e permite escalar
workers independentemente conforme a demanda.

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

A API Principal, construída em Go, atua como o componente central do sistema,
integrando as funções de ingestão, motor de análise estática e geração de relatórios. Ela
aceita URLs de repositórios Git através de webhooks do GitHub ou chamadas diretas à
API REST. Cada solicitação é convertida em um job identificado por UUID, persistida
no banco de dados SQLite, e enfileirada para processamento assíncrono.

b) API de Análise Agêntica (Python)

A API Python é responsável pela análise de segurança avançada utilizando um agente de
IA customizado. Este componente recebe tarefas do sistema de filas e executa análise
semântica profunda utilizando modelos de linguagem especializados em cibersegurança.
O agente é capaz de identificar vulnerabilidades contextuais que escapam às regras
estáticas, analisar fluxos de dados complexos e gerar recomendações personalizadas.

c) Sistema de Filas (RabbitMQ)

O sistema de filas é implementado com RabbitMQ, um message broker open source que
implementa o protocolo AMQP (Advanced Message Queuing Protocol). Ao receber
uma solicitação de análise, a API Principal responde imediatamente ao cliente com o ID
da análise e publica a tarefa em uma fila do RabbitMQ. Workers consomem as
mensagens da fila e executam as análises. Isso permite:

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
organizadas em 11 arquivos de regras que cobrem todas as categorias de ataques
MCP descritas no artigo de referência (arXiv:2508.12538).
```
e) Banco de Dados e Armazenamento


O SQLite (via GORM, ferramenta de orm) armazena metadados de jobs, status de
execução e referências aos resultados. O armazenamento compatível com S3 (AWS S
ou MinIO) persiste os relatórios JSON gerados e os artefatos de código compactados.

f) Integração CI/CD (GitHub Actions)

A integração com pipelines de CI/CD é realizada através de GitHub Actions. O
workflow automatiza a análise de segurança em cada Pull Request, inserindo
comentários automáticos com as vulnerabilidades detectadas. A autenticação utiliza
webhooks com assinatura HMAC-SHA256.

g) Sistema de Métricas e Observabilidade

O monitoramento do sistema é realizado através da stack Prometheus + Grafana. O
Prometheus coleta métricas expostas pelos componentes da aplicação (API Go, API
Python, RabbitMQ) através de endpoints /metrics no formato OpenMetrics. O Grafana
consome essas métricas e apresenta dashboards com: taxa de análises por hora,
vulnerabilidades detectadas por categoria e severidade, tempo médio de processamento,
fila de jobs pendentes, e saúde dos workers e serviços.


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
SQLite (GORM) Infraestrutura /
Persistência

```
Banco de dados embutido,
leve e sem dependências
externas, utilizado para
persistir metadados de jobs
e status de execução.
Facilita implantação local
e portabilidade.
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
Python 3.11+ Servidor (Backend) /
Motor de Análise

```
Linguagem principal do
projeto, amplamente usada
em segurança e
automação, com excelente
suporte para análise
estática e manipulação de
código.
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
com Prometheus.
```
```
TLS (HTTPS) Segurança / Comunicação Garante a proteção dos
dados em trânsito entre
clientes, API e serviços de
armazenamento.
```
## 4. Resultados Obtidos

O projeto MCPGuard encontra-se em fase de desenvolvimento ativo. Foram
implementados:

```
● API Principal (Go): Endpoints REST para recebimento de webhooks, início de
análises, consulta de status e resultados, com autenticação via HMAC-SHA256 e
API Key com suporte para repositórios apenas em Python.
● Motor de Análise Estática: 11 arquivos de regras cobrindo as 4 categorias de
ataques MCP (Injeção Direta, Injeção Indireta, Usuário Malicioso e Ataques
LLM) com suporte à linguagem Python.
● Testes Unitários: Cobertura de testes para todas as regras implementadas.
```
Componentes em Desenvolvimento:

```
● Suporte para outras linguagens além de python
● Sistema de Filas (RabbitMQ)
● API de Análise Agêntica (Python)
● Integração com GitHub Actions
● Sistema de Métricas (Prometheus/Grafana)
```

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


