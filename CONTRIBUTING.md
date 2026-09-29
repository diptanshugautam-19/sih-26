# Contributing to Predictive Cyber Defence World Model

Thank you for your interest in contributing to the **Predictive Cyber Defence World Model** project! We welcome contributions from researchers, machine learning practitioners, and security analysts.

---

## 🛠️ Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/diptanshugautam-19/sih-26.git
   cd sih-26
   ```

2. **Set up Python environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Verify environment and neural models:**
   ```bash
   python scripts/verify_env.py
   ```

4. **Install frontend dependencies:**
   ```bash
   cd frontend
   npm install
   cd ..
   ```

---

## 🧪 Testing Guidelines

Before opening a pull request, ensure all tests pass:

```bash
# Run backend pytest suite
pytest tests/ -v

# Run frontend build check
cd frontend
npm run build
cd ..
```

---

## 📋 Pull Request Process

1. Create a feature branch (`git checkout -b feat/your-feature-name`).
2. Adhere to clean code and architectural boundaries:
   - Keep temporal/spatial modeling intact (do not regress to stateless per-packet classifications).
   - Ensure the anti-leakage target window invariant is preserved.
3. Commit your changes with conventional commit messages (`feat: ...`, `fix: ...`, `docs: ...`).
4. Push to your branch and submit a Pull Request against `main`.
