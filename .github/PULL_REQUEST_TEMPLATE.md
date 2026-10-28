## 📋 Pull Request Summary
<!-- Provide a concise 2-3 sentence overview of what this pull request implements or fixes. -->

## 🎯 Target Branch
- [ ] `integration` (All member feature/fix PRs MUST target `integration`)
- [ ] `main` (ONLY used for verified release candidate PRs from `integration` prepared by Project Lead)

---

## 💡 Why This Change is Needed
<!-- Describe the motivation, problem being solved, user story, or competition objective addressed by this PR. -->

---

## 📁 Files & Modules Changed
<!-- List all files and modules created, modified, or relocated in this PR. -->
- `path/to/file1.py` - Short description of changes
- `path/to/file2.py` - Short description of changes

---

## 🧪 Tests Executed & Results
<!-- Detail the exact test commands executed and their output. Tests must pass locally before opening/merging PR. -->

### Local Test Execution:
```bash
python -m unittest discover -s . -p "test_*.py" -v
```

### Results Summary:
- Total tests run: 
- Total passing: 
- Total failing: 
- Syntax compilation verified: `python -m py_compile <changed_files>`

---

## 🔒 Security & Compatibility Considerations
<!-- Describe any security impact (e.g. cryptography algorithms, handling of secrets, network timeouts) -->
- [ ] No hardcoded credentials, API keys, tokens, or private keys committed.
- [ ] No destructive file deletion or overwriting of other team members' code.
- [ ] PQC / classical track separation preserved (if modifying risk engine or rules).
- [ ] Python 3.11+ compatibility maintained.

---

## ⚠️ Known Limitations & Edge Cases
<!-- State any edge cases not yet covered, partial implementations, or dependencies on upcoming member tasks. -->

---

## 📸 Screenshots & Demo Evidence
<!-- Attach terminal output logs, screenshots of the dashboard, or evidence if applicable. -->

---

## ✅ Team Collaboration & Scope Checklist
<!-- Confirm each of the following before requesting review: -->
- [ ] **Target Branch Check**: This PR targets `integration` (not `main`).
- [ ] **Scope Isolation**: I have confirmed that unrelated member-owned files were NOT changed unnecessarily.
- [ ] **Tests Pass**: All automated tests (`unittest`) pass locally without errors.
- [ ] **Clean Working Tree**: No temporary files, `.tmp`, `__pycache__`, or scan dumps are committed.
- [ ] **Review Requested**: Assigned respective module CODEOWNER and Project Lead for review.
