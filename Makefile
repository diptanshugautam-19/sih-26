.PHONY: help install verify dev dev-backend dev-frontend test docker-build docker-up lint clean generate-data infer-sample

help:
	@echo "Predictive Cyber Defence World Model - Developer Commands"
	@echo "  make install        Install Python dependencies and Frontend node modules"
	@echo "  make verify         Run comprehensive environment & model diagnostic"
	@echo "  make dev            Run frontend UI and API server concurrently"
	@echo "  make dev-backend    Start FastAPI backend server on port 8000"
	@echo "  make dev-frontend   Start Vite/React frontend dashboard on port 3000"
	@echo "  make docker-up      Start containerized stack with Docker Compose"
	@echo "  make test           Run test suite with pytest"
	@echo "  make generate-data  Generate synthetic multi-stage enterprise attack PCAP"
	@echo "  make infer-sample   Run PCAP inference on generated sample"
	@echo "  make clean          Clean build artifacts and caches"

install:
	python -m pip install -r requirements.txt
	cd frontend && npm install

verify:
	python scripts/verify_env.py

dev:
	cd frontend && npm run dev

dev-backend:
	python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload

dev-frontend:
	cd frontend && npm run dev

docker-build:
	docker compose build

docker-up:
	docker compose up

test:
	pytest tests/ -v

generate-data:
	python scripts/generate_enterprise_attack_200mb.py

infer-sample:
	python scripts/infer_pcap.py --pcap data/pcaps_sample/enterprise_multi_stage_apt_attack_200mb.pcap

clean:
	rm -rf dist frontend/dist __pycache__ src/**/__pycache__ tests/**/__pycache__
