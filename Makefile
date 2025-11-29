.PHONY: help db-create db-drop db-reset migrate run build test test-unit test-hurl test-all clean dev setup superadmin sqlx-prepare check lint

# Variáveis
DATABASE_URL ?= postgres://postgres_user:pass123@localhost:5432/keyrunes
ADMIN_EMAIL ?= admin@example.com
ADMIN_USERNAME ?= admin
ADMIN_PASSWORD ?= Admin123

help:
	@echo "Commands available:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Variáveis de ambiente:"
	@echo "  DATABASE_URL=$(DATABASE_URL)"
	@echo "  ADMIN_EMAIL=$(ADMIN_EMAIL)"
	@echo "  ADMIN_USERNAME=$(ADMIN_USERNAME)"

## Database
db-create: ## Cria o banco de dados
	@echo "📦 Criando banco de dados..."
	sqlx database create

db-drop: ## Remove o banco de dados (CUIDADO: apaga todos os dados!)
	@echo "🗑️  Removendo banco de dados..."
	sqlx database drop -y

db-reset: db-drop db-create migrate ## Reseta o banco (drop + create + migrate)
	@echo "✅ Banco resetado com sucesso!"

migrate: ## Roda as migrations
	@echo "🔄 Rodando migrations..."
	sqlx migrate run
	@echo "✅ Migrations aplicadas!"

migrate-revert: ## Reverte a última migration
	@echo "↩️  Revertendo última migration..."
	sqlx migrate revert

## Build & Run
build: ## Compila o projeto
	@echo "🔨 Compilando..."
	cargo build

build-release: ## Compila em modo release
	@echo "🔨 Compilando release..."
	cargo build --release

run: ## Roda o servidor
	@echo "🚀 Iniciando servidor..."
	cargo run

run-release: ## Roda o servidor em modo release
	@echo "🚀 Iniciando servidor (release)..."
	cargo run --release

dev: ## Roda o servidor com auto-reload (requer cargo-watch)
	@echo "🔥 Modo desenvolvimento com hot-reload..."
	cargo watch -x run

## CLI
cli-superadmin: ## Cria o primeiro superadmin
	@echo "👤 Criando superadmin..."
	cargo run --bin cli -- create-superadmin \
		--email $(ADMIN_EMAIL) \
		--username $(ADMIN_USERNAME) \
		--password $(ADMIN_PASSWORD)
	@echo "✅ Superadmin criado!"

cli-list-groups: ## Lista todos os grupos
	@echo "📋 Listando grupos..."
	cargo run --bin cli -- list-groups

cli-create-group: ## Cria um grupo (uso: make cli-create-group NAME=developers DESC="Dev team")
	@echo "➕ Criando grupo $(NAME)..."
	cargo run --bin cli -- create-group --name $(NAME) --description "$(DESC)"

## Tests
test: ## Roda todos os testes Rust
	@echo "🧪 Rodando testes Rust..."
	cargo test

test-unit: ## Roda apenas testes unitários
	@echo "🧪 Rodando testes unitários..."
	cargo test --lib

test-integration: ## Roda apenas testes de integração
	@echo "🧪 Rodando testes de integração..."
	cargo test --test '*'

test-hurl: ## Roda testes Hurl (requer servidor rodando)
	@echo "🧪 Rodando testes Hurl..."
	@if ! curl -s http://localhost:3000/api/health > /dev/null 2>&1; then \
		echo "❌ Servidor não está rodando! Execute 'make run' primeiro."; \
		exit 1; \
	fi
	./run_hurl_tests.sh

test-hurl-verbose: ## Roda testes Hurl em modo verbose
	@echo "🧪 Rodando testes Hurl (verbose)..."
	./run_hurl_tests.sh --verbose

test-all: test test-hurl ## Roda todos os testes (Rust + Hurl)

## SQLx
sqlx-prepare: ## Prepara SQLx metadata offline
	@echo "📝 Preparando SQLx metadata..."
	cargo sqlx prepare

sqlx-check: ## Verifica se as queries SQLx estão corretas
	@echo "🔍 Verificando queries SQLx..."
	cargo sqlx prepare --check

## Setup completo
setup: db-create migrate cli-superadmin ## Setup completo (cria DB, migrations, superadmin)
	@echo ""
	@echo "✨ Setup completo!"
	@echo ""
	@echo "Próximos passos:"
	@echo "  1. Inicie o servidor: make run"
	@echo "  2. Acesse: http://127.0.0.1:3000/login"
	@echo "  3. Login: $(ADMIN_USERNAME) / $(ADMIN_PASSWORD)"
	@echo "  4. Admin: http://127.0.0.1:3000/admin"
	@echo ""

## Development
check: ## Verifica o código sem compilar
	@echo "🔍 Verificando código..."
	cargo check --all-targets

lint: ## Roda clippy (linter)
	@echo "🧹 Rodando linter..."
	cargo clippy -- -D warnings

fmt: ## Formata o código
	@echo "✨ Formatando código..."
	cargo fmt

fmt-check: ## Verifica formatação sem alterar
	@echo "🔍 Verificando formatação..."
	cargo fmt -- --check

clean: ## Limpa arquivos de build
	@echo "🧹 Limpando..."
	cargo clean

## Docker
docker-up: ## Sobe o Postgres via docker-compose
	@echo "🐳 Subindo Docker..."
	docker-compose up -d
	@echo "⏳ Aguardando Postgres iniciar..."
	@sleep 3
	@echo "✅ Postgres rodando!"

docker-down: ## Para o Postgres
	@echo "🛑 Parando Docker..."
	docker-compose down

docker-reset: docker-down docker-up ## Reseta containers Docker
	@echo "✅ Docker resetado!"

docker-logs: ## Mostra logs do Postgres
	docker-compose logs -f postgres

## Quick commands
fresh-start: docker-reset db-reset setup ## Começa do zero (Docker + DB + Setup)
	@echo ""
	@echo "🎉 Ambiente pronto para desenvolvimento!"
	@echo "Execute: make run"

restart: docker-down docker-up migrate ## Reinicia ambiente de desenvolvimento
	@echo "✅ Ambiente reiniciado!"

## Info
env: ## Mostra variáveis de ambiente
	@echo "DATABASE_URL: $(DATABASE_URL)"
	@echo "ADMIN_EMAIL: $(ADMIN_EMAIL)"
	@echo "ADMIN_USERNAME: $(ADMIN_USERNAME)"
	@echo "ADMIN_PASSWORD: $(ADMIN_PASSWORD)"

status: ## Mostra status do ambiente
	@echo "📊 Status do Ambiente"
	@echo ""
	@echo "Docker:"
	@docker-compose ps 2>/dev/null || echo "  ⚠️  Docker não está rodando"
	@echo ""
	@echo "Servidor:"
	@if curl -s http://localhost:3000/api/health > /dev/null 2>&1; then \
		echo "  ✅ Servidor rodando (http://localhost:3000)"; \
	else \
		echo "  ⚠️  Servidor não está rodando"; \
	fi
	@echo ""
	@echo "Database:"
	@if psql $(DATABASE_URL) -c "SELECT 1" > /dev/null 2>&1; then \
		echo "  ✅ Conectado"; \
	else \
		echo "  ⚠️  Não conectado"; \
	fi
