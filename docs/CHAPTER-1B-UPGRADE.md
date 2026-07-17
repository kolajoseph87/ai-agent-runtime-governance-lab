# Apply Chapter 1B to the Existing GitHub Repository

These steps preserve the Chapter 1A commit and add Chapter 1B as a separate commit.

## 1. Back up and check the current repository

From the existing local `ai-agent-runtime-governance-lab` directory:

```bash
git status
git pull origin main
```

Do not continue until `git status` says the working tree is clean. Never copy `.env` or an API key into the repository.

## 2. Copy the Chapter 1B files

Copy the contents of the supplied Chapter 1B project folder over the contents of the existing repository. Keep the existing `.git` directory in place.

Delete the two superseded baseline paths:

```bash
git rm python/security_agent.py
git rm -r dotnet/SecurityAgentBaseline
```

The SOC example is not lost. It is retained at:

```text
examples/soc-agent/security_agent.py
```

## 3. Review the changes

```bash
git status
git diff --check
git diff --stat
```

Expected high-level changes:

- `python/secure_coding_agent.py` added
- `dotnet/SecureCodingAgentBaseline/` added
- `examples/soc-agent/security_agent.py` added
- README, roadmap, and threat model updated
- old primary SOC baseline paths removed

## 4. Test Python

```bash
source .venv/bin/activate
pip install -r requirements.txt
python python/secure_coding_agent.py
python python/risk_lookup.py
PYTHONPATH=python pytest python -v
```

Expected risk-lookup output:

```text
agentmesh-runtime
True
```

## 5. Test .NET

```bash
cd dotnet/SecureCodingAgentBaseline
dotnet restore
dotnet build
dotnet run
cd ../..
```

## 6. Scan for accidentally committed secrets

This command searches for strings shaped like OpenAI keys:

```bash
git grep -n -E 'sk-[A-Za-z0-9_-]{20,}' || true
```

Also inspect every staged change:

```bash
git add .
git diff --cached --check
git diff --cached --stat
git status
```

## 7. Commit and push

```bash
git commit -m "Refocus Chapter 1 on secure agentic development"
git push origin main
```

Verify the new commit at:

```text
https://github.com/kolajoseph87/ai-agent-runtime-governance-lab
```
