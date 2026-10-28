# 🤝 Contributing to Q-SHIELD

Welcome to the Q-SHIELD team! This guide explains our branch model, day-to-day Git operations, coding standards, conflict recovery procedures, and member ownership areas.

---

## 👥 Five-Member Team Responsibilities

| Role | Branch | Lead / Members | Primary Ownership & Deliverables |
| :--- | :--- | :--- | :--- |
| **Member 1: CLI & Discovery** | `member/cli` | `@kartikDevS` | CLI orchestrator (`main.py`), TLS network scanner (`tls_scanner.py`), static source code AST scanner (`code_scanner.py`), input parameter validation. |
| **Member 2: QA & Docs** | `member/qa-docs` | `@member2-qa-docs` / `@KrishnaSinghal5707` | Unit and integration tests (`test_*.py`), mock vulnerable applications (`sample_vulnerable_app/`), user documentation, benchmark verification. |
| **Member 3: Crypto & Rules** | `member/crypto-rules` | `@Shubh-rai14` | Risk engine algorithms (`risk_engine.py`), cryptographic rule definitions (`rules.json`), Mosca theorem calculation, PQC vs. classical track separation. |
| **Member 4: Product & Web** | `member/product` | `@member4-product` / `@kartikDevS` | Interactive browser dashboard (`dashboard.py`, `web/index.html`), data adapters (`adapters.py`), automated demo scripts (`demo_workflow.py`, `demo.sh`). |
| **Member 5: Project Lead** | `member/lead` | `@KrishnaSinghal5707` | Architectural integrity, CI/CD pipeline (`.github/`), branch protection, PR approvals into `integration`, release candidate verification and merging to `main`. |

---

## 🌿 Branch Naming & Architecture

The repository maintains two permanent protected branches and five dedicated development branches:

- **`main`**: The judge-demo release branch. **Strictly protected**. Never commit directly here.
- **`integration`**: Staging branch for integrated feature testing. All member PRs target this branch.
- **`member/cli`**: Member 1 development branch.
- **`member/qa-docs`**: Member 2 development branch.
- **`member/crypto-rules`**: Member 3 development branch.
- **`member/product`**: Member 4 development branch.
- **`member/lead`**: Member 5 development branch.

> [!IMPORTANT]
> **Branch Isolation Notice**: Branches isolate commits in local git clones, but branches **do not by themselves restrict write access or prevent direct pushes on GitHub**. Enforcing write boundaries requires GitHub Branch Protection Rules configured by the repository administrator (see [Branch Policy](docs/BRANCH_POLICY.md)).

---

## 🚀 Daily Workflow Guide

### 1. Creating and Checking Out Your Branch
If you are starting work or cloning on a fresh machine:
```bash
# Ensure local branches know about remote branches
git fetch origin

# Switch to your assigned development branch (example for Member 1):
git checkout -b member/cli origin/main
# (If the branch already exists on origin, simply run: git checkout member/cli)
```

### 2. Syncing Your Branch with Upstream Integration
Before beginning new work, sync your branch non-destructively:
```bash
# 1. Fetch latest commits from remote without modifying working tree
git fetch origin

# 2. Merge latest integration staging into your local branch
git merge origin/integration
```

### 3. Writing Code and Making Commits
Keep your commits atomic, focused, and well-described:
```bash
# Stage only files related to your task
git add risk_engine.py rules.json

# Commit with a clear conventional message
git commit -m "feat(risk_engine): adjust Mosca theorem threshold for conservative scenario"
```
Rules for commits:
- Never commit `.env`, credentials, secrets, or temporary dumps (`demo_report.json`, `*.tmp`).
- Verify syntax locally before committing:
  ```bash
  python -m py_compile <changed_file.py>
  ```

### 4. Running the Test Suite Locally
Never push code that breaks tests:
```bash
# Run unit and integration tests
python -m unittest discover -s . -p "test_*.py" -v
```

### 5. Pushing to GitHub & Opening a Pull Request
Push your branch to GitHub:
```bash
git push -u origin member/<your-branch-name>
```

Then, navigate to GitHub:
1. Click **New Pull Request**.
2. **Base Branch**: Set to `integration` (⚠️ DO NOT select `main`).
3. **Compare Branch**: Select your `member/<branch-name>`.
4. Complete the Pull Request template (`.github/PULL_REQUEST_TEMPLATE.md`).
5. Verify GitHub Actions CI status check passes.
6. Request review from module owner and `@KrishnaSinghal5707`.

---

## 🛡️ Safe Merge Conflict Resolution (Zero Data-Loss)

When multiple members update related modules, merge conflicts may occur. Follow this safe, non-destructive resolution procedure:

### Step 1: Detect and Inspect Conflicts
When `git merge origin/integration` indicates a conflict:
```bash
# Check exactly which files are conflicting
git status
```
Git will list conflicted files under `Unmerged paths:`.

### Step 2: Open and Resolve Conflicted Files
Open the conflicting file in your editor. Locate the conflict markers:
```python
<<<<<<< HEAD (Your local changes)
def calculate_risk(asset):
    return asset.quantum_score * 1.5
=======
def calculate_risk(asset):
    return asset.quantum_score * 1.2
>>>>>>> origin/integration (Incoming changes)
```
- Work through the logic carefully, preserving both valid changes.
- Remove all conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`).

### Step 3: Verify and Commit
```bash
# 1. Test syntax
python -m py_compile <conflicted_file.py>

# 2. Run automated tests to prove functionality is intact
python -m unittest discover -s . -p "test_*.py" -v

# 3. Stage the resolved files
git add <conflicted_file.py>

# 4. Finalize the merge commit
git commit -m "merge: resolve integration conflicts in <conflicted_file.py>"
```

### Step 4: Safe Abort (Emergency Exit)
If a merge conflict appears complex and you need to safely return to your exact pre-merge state:
```bash
# Safely abort the merge without losing your uncommitted work
git merge --abort
```
> [!CAUTION]
> **DO NOT** run `git reset --hard` or `git checkout -f` when resolving conflicts. These commands can permanently delete uncommitted edits.

---

## 🔒 Code Review & Merge Gates
1. Every PR into `integration` requires:
   - At least 1 code review approval from the designated CODEOWNER.
   - Passing `Q-SHIELD Quality Gate` GitHub Actions CI.
2. The Project Lead (`@KrishnaSinghal5707`) is the only member authorized to open and merge the release PR from `integration` into `main`.
3. The demo shown to judges must run from `main` or an official release tag (`v1.0.0-judge-demo`).
