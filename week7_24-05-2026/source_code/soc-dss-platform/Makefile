.PHONY: up down logs backend frontend build wazuh-lab-up wazuh-lab-down wazuh-lab-export wazuh-lab-import clean

up:
	docker compose -f deploy/production/docker-compose.yml up --build -d

down:
	docker compose -f deploy/production/docker-compose.yml down

logs:
	docker compose -f deploy/production/docker-compose.yml logs -f

backend:
	cd backend && mvn spring-boot:run

frontend:
	cd frontend && npm run dev

build:
	cd backend && mvn clean package -DskipTests
	cd frontend && npm install && npm run build

wazuh-lab-up:
	./scripts/wazuh-lab-up.sh

wazuh-lab-down:
	./scripts/wazuh-lab-down.sh

wazuh-lab-export:
	./scripts/wazuh-export-alerts.sh

wazuh-lab-import:
	./scripts/wazuh-import-alerts.sh

clean:
	rm -rf backend/target frontend/dist frontend/node_modules
