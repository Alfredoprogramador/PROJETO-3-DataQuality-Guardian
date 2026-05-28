# ✅ PROJETO-3: DataQuality Guardian

Sistema Centralizado de Governança, Catálogo e Qualidade de Dados.

## 1) Problema que resolve
Grandes empresas possuem dados distribuídos em múltiplas fontes, com baixa qualidade, pouca governança e baixa rastreabilidade de linhagem. Isso reduz a confiabilidade de analytics, IA e compliance (LGPD/GDPR).

## 2) Objetivo do projeto
Construir uma plataforma enterprise de **Data Quality + Governance + Catalog** para:
- Avaliação automática da qualidade dos dados
- Linhagem end-to-end
- Catálogo centralizado com busca
- Políticas de governança como código
- Compliance regulatório
- Integração com ferramentas modernas de dados

## 3) Stack tecnológica (alvo)
- **Frontend:** Next.js 15 (App Router), TypeScript, Tailwind, shadcn/ui, React Flow, TanStack Table
- **Backend:** Python + FastAPI
- **Data Quality:** Great Expectations + Soda + regras customizadas com IA
- **Orquestração:** Airflow + dbt Core
- **Armazenamento:** PostgreSQL (metadados), Iceberg (data lake), MinIO (S3 compatível)
- **Busca:** Weaviate/Qdrant + Elasticsearch
- **IA/ML:** LangChain + Llama 3/Mixtral
- **Infra:** Kubernetes + Terraform + Argo Workflows
- **Observabilidade:** OpenTelemetry + Prometheus + Grafana + Metabase

## 4) Arquitetura de alto nível
- **Ingestão:** conectores para Snowflake, BigQuery, PostgreSQL, S3, Salesforce etc.
- **Qualidade:** execução de expectativas e regras inteligentes
- **Linhagem:** OpenLineage + tracking customizado
- **Catálogo:** metadata repository com busca semântica
- **Governança:** políticas como código + aprovação de workflows
- **Ação:** cleansing automático, alertas e data contracts

## 5) Funcionalidades por fase
### MVP (Fase 1)
- Conexão com principais fontes
- Regras de qualidade: completude, unicidade, validade, consistência
- Dashboard de score por tabela/base
- Catálogo básico com busca
- Alertas (Slack/Email)
- Relatórios de qualidade

### Fase 2
- Linhagem automática completa
- Busca semântica no catálogo
- Sugestões de IA para regras
- Data Contracts
- Cleansing/enriquecimento com IA
- Integração com dbt tests + lineage

### Fase 3
- Multi-tenant + RBAC granular
- Módulo de privacy/compliance (PII detection)
- Data Product Catalog (Data Mesh)
- Workflow de aprovação (governança)
- Auditoria completa e histórico
- Integrações com Collibra/Alation/Purview

## 6) Estrutura do monorepo
```bash
dataquality-guardian/
├── apps/
│   ├── frontend/
│   ├── backend/
│   └── quality-engine/
├── packages/
│   ├── shared/
│   ├── connectors/
│   ├── lineage/
│   └── ai-governance/
├── infra/
│   ├── terraform/
│   └── kubernetes/
├── dbt/
├── great_expectations/
├── docs/
├── docker-compose.yml
└── .github/workflows/
```

## 7) Desenvolvimento com VS Code
1. Inicialize o monorepo com Turborepo
2. Desenvolva conectores e regras de qualidade
3. Evolua pipelines Airflow + dbt
4. Implemente visualizações de linhagem com React Flow

Extensões recomendadas:
- Python + Pylance
- dbt Power User
- ESLint + Prettier
- Docker + Kubernetes
- GitLens + GraphQL

---

## Estado atual do repositório
Este repositório foi inicializado com a estrutura base do monorepo, diretórios principais e placeholders para evolução das fases MVP/Fase 2/Fase 3.
