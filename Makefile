.PHONY: build up down logs restart clean

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=100

restart:
	docker compose restart

clean:
	docker compose down -v
	rm -rf data/users.db data/sub.b64 data/sub_plain.txt data/last_update.txt

setup:
	@test -f .env || cp .env.example .env
	@echo "Отредактируй .env, затем: make build && make up"
