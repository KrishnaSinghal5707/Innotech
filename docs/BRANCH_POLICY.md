# 🛡️ Q-SHIELD Branch & Release Policy

This document defines the official branch lifecycle, pull request flow, integration quality gates, and release tagging policy for the Q-SHIELD 5-member engineering team.

---

## 🌳 Branch Hierarchy & Architecture

```
[ remote / origin ]
       ▲
       │  (Only verified release PRs merged by Project Lead)
┌──────┴────────────────────────────────────────────────────────┐
│  main (Protected: Stable Judge-Demo / Release Branch)         │
└──────▲────────────────────────────────────────────────────────┘
       │  (Release Pull Request + Full Regression Pass)
┌──────┴────────────────────────────────────────────────────────┐
│  integration (Protected: Staging & Review Branch)             │
└──────▲────────────▲──────────────▲─────────────▲──────────────┘
       │            │              │             │              │
       │ (Feature PR)              │             │              │ (Lead PR)
┌──────┴──────┐ ┌───┴──────────┐ ┌─┴───────────┐ ┌┴───────────┐ ┌┴───────────┐
│ member/cli  │ │member/qa-docs│ │member/crypto│ │member/     │ │member/lead  │
│ (Member 1)  │ │(Member 2)    │ │-rules (M3)  │ │product(M4) │ │(Member 5)   │
└─────────────┘ └──────────────┘ └─────────────┘ └────────────┘ └─────────────┘
```

### 1. `main` Branch (Production / Judge Demo)
- **Purpose**: Stable release branch presented to hackathon judges.
- **Rule**: Contains **only** fully tested, production-ready code.
- **Access Control**: **STRICTLY PROTECTED**. Direct pushes and force pushes are blocked.
- **Merge Source**: Only accepts Pull Requests from `integration` authored/approved by the Project Lead.
- **Guarantees**: Running `python main.py --demo` or `python main.py --dashboard` on `main` must ALWAYS succeed without errors.

### 2. `integration` Branch (Shared Staging)
- **Purpose**: Central integration and staging branch where all member features coalesce.
- **Rule**: All member work is reviewed, combined, and tested here first.
- **Access Control**: **PROTECTED**. Direct pushes to `integration` are prohibited.
- **Merge Source**: Pull Requests from individual `member/*` branches.
- **Requirement**: Automated CI checks (`qshield-ci.yml`) must pass before merging.

### 3. Member Feature Branches (`member/*`)
- **`member/cli`** (Member 1): Orchestrator (`main.py`), TLS scanner (`tls_scanner.py`), AST code scanner (`code_scanner.py`).
- **`member/qa-docs`** (Member 2): Test suites (`test_*.py`), mock vulnerable applications (`sample_vulnerable_app/`), QA and user documentation.
- **`member/crypto-rules`** (Member 3): Cryptographic rule definitions (`rules.json`), risk quantification engine (`risk_engine.py`), PQC/classical track modeling.
- **`member/product`** (Member 4): Browser dashboard (`dashboard.py`, `web/index.html`), data adapters (`adapters.py`), demo automation (`demo_workflow.py`, `demo.sh`).
- **`member/lead`** (Member 5 - Project Lead): CI/CD workflows (`.github/`), repository governance, branch protection configuration, release coordination.

---

## 🔄 End-to-End Workflow

### Step 1: Feature Work in Isolated Member Branch
Each member works strictly in their assigned branch:
```bash
# Example for Member 1:
git checkout member/cli
# Make atomic commits
git add main.py
git commit -m "feat(cli): add detailed verbose telemetry flags"
```

### Step 2: Keep Branch Synchronized with `integration`
Before creating a PR, always pull the latest changes from `integration`:
```bash
git fetch origin
git merge origin/integration
# Run local test suite to confirm no regressions
python -m unittest discover -s . -p "test_*.py" -v
```

### Step 3: Open PR Targeting `integration`
Push your branch to GitHub and open a Pull Request:
```bash
git push -u origin member/cli
```
- In GitHub, set **Base branch: `integration`** (NEVER `main`).
- Fill out `.github/PULL_REQUEST_TEMPLATE.md`.
- Ensure automated GitHub Actions CI passes.
- Request review from CODEOWNERS and Project Lead.

### Step 4: Lead Review & Integration
- Project Lead reviews code, verifies test results, and confirms no unintended cross-module edits occurred.
- Lead merges the PR into `integration`.

### Step 5: Release Candidate & Demo Verification
When ready for a judge release or competition milestone:
1. Lead pulls latest `integration` locally:
   ```bash
   git checkout integration
   git pull origin integration
   ```
2. Lead executes full end-to-end regression validation:
   ```bash
   python -m py_compile main.py tls_scanner.py code_scanner.py risk_engine.py adapters.py dashboard.py demo_workflow.py test_integration.py test_risk_engine.py
   python -m unittest discover -s . -p "test_*.py" -v
   python main.py --demo
   ```
3. Lead opens a release PR from `integration` into `main`.
4. Once CI passes and peer review is approved, Lead merges into `main`.

### Step 6: Tagging a Verified Release
Every judge demo or milestone commit on `main` is tagged with a semantic release version:
```bash
git checkout main
git pull origin main
git tag -a v1.0.0-judge-demo -m "Q-SHIELD v1.0.0: Verified judge demonstration release"
git push origin v1.0.0-judge-demo
```

---

## 🚫 Cardinal Rules (Zero-Tolerance)
1. **Never commit directly to `main`**: All code on `main` must come through an `integration` PR.
2. **Never push force (`--force` / `+`)**: Force pushes destroy team commit history.
3. **Never modify files owned by another member without prior agreement**: Check `.github/CODEOWNERS` before making edits.
4. **Never commit sensitive assets**: No API keys, credentials, machine-specific paths, or `.env` files.
5. **No Broken Windows**: The automated test suite (`unittest discover`) must be 100% green at all times on `integration` and `main`.
