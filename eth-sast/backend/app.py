from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sast_engine import SoliditySASTEngine

app = FastAPI(
    title='EthSAST',
    description='Static analysis engine for Ethereum smart contracts',
    version='0.1.0',
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['GET', 'POST', 'OPTIONS'],
    allow_headers=['*'],
)


class AnalyzePayload(BaseModel):
    source: str


@app.post('/analyze')
def analyze(payload: AnalyzePayload):
    if not payload.source.strip():
        raise HTTPException(status_code=400, detail='Solidity source code is required')
    engine = SoliditySASTEngine(payload.source)
    findings = engine.run_detectors()
    return {
        'findings': [
            {
                'vulnerability': finding.vulnerability,
                'function': finding.function,
                'location': finding.location,
                'message': finding.message,
            }
            for finding in findings
        ]
    }
