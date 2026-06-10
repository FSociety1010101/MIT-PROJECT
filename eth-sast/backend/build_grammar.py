from pathlib import Path
from tree_sitter import Language

ROOT = Path(__file__).resolve().parent
BUILD_DIR = ROOT / 'build'
GRAMMAR_REPO = ROOT / 'tree-sitter-solidity'
LIB_PATH = BUILD_DIR / 'my-languages.so'

if __name__ == '__main__':
    BUILD_DIR.mkdir(exist_ok=True)
    if not GRAMMAR_REPO.exists():
        import subprocess
        subprocess.run([
            'git', 'clone', 'https://github.com/tree-sitter/tree-sitter-solidity.git',
            str(GRAMMAR_REPO)
        ], check=True)
    Language.build_library(
        str(LIB_PATH),
        [str(GRAMMAR_REPO)],
    )
    print('Built Solidity grammar at', LIB_PATH)
