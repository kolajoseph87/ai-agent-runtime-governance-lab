# Apply and Publish Chapter 2 on macOS

## 1. Confirm Chapter 1B is clean

From the existing repository:

```bash
git status
git pull origin main
```

Continue only when Git reports a clean working tree.

## 2. Copy the Chapter 2 bundle

Extract the supplied Chapter 2 ZIP to `~/Downloads/chapter2-update`, then copy it over the existing repository while preserving `.git` and `.venv`:

```bash
rsync -av \
  --exclude='.git' \
  --exclude='.venv' \
  ~/Downloads/chapter2-update/ ./
```

Chapter 2 only adds or updates files; it does not require deleting Chapter 1B files.

## 3. Run Python tests

```bash
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=python python -m pytest python -v
```

Run the live governed demonstration:

```bash
export OPENAI_API_KEY="your-key-here"
python python/governed_agent_demo.py
```

Confirm the terminal shows:

- `PERMIT` for the clean review request
- `DENY` at `input_validation` for the malicious request
- `PERMIT` for `repository-reader|repo:read`

## 4. Run .NET

```bash
cd dotnet/SecureCodingAgentBaseline
dotnet restore
dotnet build
dotnet run
cd ../..
```

Confirm that .NET produces the same three decisions.

## 5. Review security and changes

```bash
git grep -n -E 'sk-[A-Za-z0-9_-]{20,}' || true
git status
git diff --check
git diff --stat
```

Stage and inspect:

```bash
git add .
git diff --cached --check
git diff --cached --stat
git status
```

## 6. Commit and push

```bash
git commit -m "Add identity-aware governance pipeline"
git push origin main
```

The GitHub history should now show three project milestones:

1. Chapter 1A SOC baseline
2. Chapter 1B secure agentic-development baseline
3. Chapter 2 identity-aware governance pipeline
