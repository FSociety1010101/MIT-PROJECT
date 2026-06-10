# Contributing to EthSAST

Thank you for your interest in contributing to EthSAST. This project is intended to support web3 security research and portfolio-quality smart contract analysis.

## How to contribute

1. Fork the repository and create a feature branch.
2. Add tests for new detection rules or bug fixes in `backend/tests/`.
3. Update documentation in `README.md` if you add new features.
4. Submit a pull request describing the change and its security impact.

## Coding standards

- Use Python 3.11+ for backend code.
- Keep backend dependencies pinned in `backend/requirements.txt`.
- Keep frontend dependencies small and use Vite with React.
- Document analysis logic clearly in comments and the README.

## Testing

- Run `python -m pytest backend/tests` for backend validation.
- Run `npm install` and `npm run build` in `frontend/` for frontend verification.

## Security considerations

- Do not commit secrets or private keys.
- Keep external parser grammar builds deterministic and reproducible.
- Report any security issues through the repository issue tracker rather than public pull requests.
