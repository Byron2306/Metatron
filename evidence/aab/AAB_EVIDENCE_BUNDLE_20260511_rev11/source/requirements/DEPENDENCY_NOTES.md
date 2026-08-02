# AAB rev11 Dependency Notes

This bundle preserves the dependency manifests needed to reproduce the AAB harness and live runner:

- `requirements-test.txt`: pytest/FastAPI test dependencies used by the adversarial test suite.
- `backend-requirements.txt`: backend runtime dependencies for the deception router and supporting services.
- `root-requirements.txt`: root repository requirement manifest, retained for provenance.
- `pytest.ini`: repository pytest configuration as present at bundle time.

The live API runner additionally requires exactly one provider key in the environment:

```bash
export OPENAI_API_KEY='...'
# or
export ANTHROPIC_API_KEY='...'
```

No provider key is stored in this evidence bundle.
