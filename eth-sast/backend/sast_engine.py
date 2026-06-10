from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import networkx as nx
from tree_sitter import Language, Parser


@dataclass
class Finding:
    vulnerability: str
    function: str
    location: Optional[Tuple[int, int]]
    message: str


class SolidityASTParser:
    GRAMMAR_PATH = Path(__file__).resolve().parent / 'build' / 'my-languages.so'
    LANGUAGE_NAME = 'solidity'

    def __init__(self) -> None:
        self.parser = Parser()
        self.parser.set_language(self._load_language())

    @classmethod
    def _load_language(cls) -> Language:
        if not cls.GRAMMAR_PATH.exists():
            raise FileNotFoundError(
                'Solidity grammar not built. Run:\n'
                '  git clone https://github.com/tree-sitter/tree-sitter-solidity.git\n'
                '  tree-sitter build-wasm\n'
                '  python -m tree_sitter.Language.build_library \'\n'
                '    build/my-languages.so \'\n'
                '    tree-sitter-solidity'
            )
        return Language(str(cls.GRAMMAR_PATH), cls.LANGUAGE_NAME)

    def parse(self, source: str):
        return self.parser.parse(source.encode('utf-8'))

    @staticmethod
    def node_text(source: str | bytes, node: Any) -> str:
        text = source[node.start_byte:node.end_byte]
        if isinstance(text, bytes):
            return text.decode('utf-8')
        return text


@dataclass
class CFGNode:
    name: str
    node_type: str
    ast_node: Any
    source_slice: str
    line: int
    col: int
    successors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class CFGBuilder:
    def __init__(self, source: str) -> None:
        self.source = source
        self.graph = nx.DiGraph()

    def build_for_function(self, function_node: Any) -> nx.DiGraph:
        self.graph.clear()
        entry_name = self._node_name(function_node, prefix='entry')
        self.graph.add_node(entry_name, type='entry', node=function_node)
        self._walk(function_node, entry_name)
        return self.graph

    def _walk(self, node: Any, parent_name: str) -> str:
        node_type = node.type
        if node_type == 'if_statement':
            return self._handle_if(node, parent_name)
        if node_type == 'while_statement' or node_type == 'for_statement':
            return self._handle_loop(node, parent_name)
        if node_type == 'return_statement':
            return self._create_node(node, parent_name, 'return')
        if node_type in ('expression_statement', 'variable_declaration', 'assignment_expression'):
            return self._create_node(node, parent_name, 'stmt')
        for child in node.children:
            parent_name = self._walk(child, parent_name)
        return parent_name

    def _handle_if(self, node: Any, parent_name: str) -> str:
        cond = node.child_by_field_name('condition')
        then_block = node.child_by_field_name('consequence')
        else_block = node.child_by_field_name('alternative')
        cond_name = self._create_node(cond, parent_name, 'condition')
        then_end = self._walk(then_block, cond_name)
        if else_block is not None:
            else_end = self._walk(else_block, cond_name)
            merge_name = self._create_node(node, then_end, 'merge')
            self.graph.add_edge(else_end, merge_name)
            return merge_name
        return then_end

    def _handle_loop(self, node: Any, parent_name: str) -> str:
        loop_name = self._create_node(node, parent_name, 'loop')
        body = node.child_by_field_name('body')
        if body:
            end_name = self._walk(body, loop_name)
            self.graph.add_edge(end_name, loop_name)
        return loop_name

    def _create_node(self, node: Any, parent_name: str, node_type: str) -> str:
        name = self._node_name(node, prefix=node_type)
        text = SolidityASTParser.node_text(self.source, node)
        self.graph.add_node(name, type=node_type, ast_node=node, source=text)
        self.graph.add_edge(parent_name, name)
        return name

    def _node_name(self, node: Any, prefix: str) -> str:
        start = node.start_point
        return f'{prefix}_{start[0]}_{start[1]}'


class TaintAnalyzer:
    SOURCE_PATTERNS = [
        re.compile(r'\bmsg\.sender\b'),
        re.compile(r'\bmsg\.value\b'),
        re.compile(r'\btx\.origin\b'),
        re.compile(r'\bcall\.data\b'),
        re.compile(r'\bmsg\.data\b'),
    ]

    def __init__(self, source: str, function_node: Any, cfg: nx.DiGraph) -> None:
        self.source = source
        self.function_node = function_node
        self.cfg = cfg
        self.tainted_vars: Set[str] = set()
        self.findings: List[Finding] = []

    def analyze(self) -> None:
        for node_name, data in self.cfg.nodes(data=True):
            text = data.get('source', '')
            self._propagate_taint(text, data)

    def _propagate_taint(self, text: str, data: Dict[str, Any]) -> None:
        if any(p.search(text) for p in self.SOURCE_PATTERNS):
            assigned = self._extract_assigned_vars(text)
            self.tainted_vars.update(assigned)
        if self._contains_tainted_var(text) and self._is_sink(text):
            self.findings.append(Finding(
                vulnerability='TaintFlow',
                function=self._function_name(),
                location=self._node_location(data['ast_node']),
                message=f'Tainted data flows into sensitive sink: {text.strip()}',
            ))

    def _extract_assigned_vars(self, text: str) -> Set[str]:
        matches = re.findall(r'([A-Za-z0-9_]+)\s*=\s*', text)
        return set(matches)

    def _contains_tainted_var(self, text: str) -> bool:
        return any(re.search(rf'\b{re.escape(var)}\b', text) for var in self.tainted_vars)

    def _is_sink(self, text: str) -> bool:
        return bool(re.search(r'\b(call|delegatecall|send|transfer)\b', text))

    def _node_location(self, node: Any) -> Tuple[int, int]:
        return node.start_point

    def _function_name(self) -> str:
        return self.function_node.child_by_field_name('name').text if self.function_node.child_by_field_name('name') else '<constructor>'


class SoliditySASTEngine:
    def __init__(self, source: str) -> None:
        self.source = source
        self.parser = SolidityASTParser()
        self.tree = self.parser.parse(source)
        self.root_node = self.tree.root_node

    def find_function_nodes(self) -> Iterable[Any]:
        def recurse(node: Any):
            if node.type == 'function_definition':
                yield node
            for child in node.children:
                yield from recurse(child)

        yield from recurse(self.root_node)

    def run_detectors(self) -> List[Finding]:
        findings: List[Finding] = []
        for fn in self.find_function_nodes():
            cfg = CFGBuilder(self.source).build_for_function(fn)
            findings.extend(self._run_reentrancy_detector(fn, cfg))
            findings.extend(self._run_timestamp_detector(fn))
            findings.extend(self._run_unchecked_call_detector(fn))
            findings.extend(self._run_access_control_detector(fn))
            findings.extend(self._run_taint_analysis(fn, cfg))
        return findings

    def _run_reentrancy_detector(self, function_node: Any, cfg: nx.DiGraph) -> List[Finding]:
        findings: List[Finding] = []
        calls = [n for n, d in cfg.nodes(data=True) if d.get('type') == 'stmt' and re.search(r'\.(call|delegatecall|send|transfer)\(', d.get('source', ''))]
        writes = [n for n, d in cfg.nodes(data=True) if d.get('type') == 'stmt' and re.search(r'\b([A-Za-z0-9_]+)\s*=\s*.*storage|\b\w+\s*\.\s*\w+\s*=\s*', d.get('source', ''))]
        for call_node in calls:
            for write_node in writes:
                if nx.has_path(cfg, call_node, write_node):
                    findings.append(Finding(
                        vulnerability='Reentrancy',
                        function=self._fn_name(function_node),
                        location=cfg.nodes[call_node].get('ast_node').start_point,
                        message='External call may occur before a state-modifying storage update.',
                    ))
        return findings

    def _run_timestamp_detector(self, function_node: Any) -> List[Finding]:
        findings: List[Finding] = []
        text = self.source[function_node.start_byte:function_node.end_byte]
        if re.search(r'\b(block\.timestamp|now|block\.number)\b', text):
            findings.append(Finding(
                vulnerability='TimestampDependence',
                function=self._fn_name(function_node),
                location=function_node.start_point,
                message='Use of block.timestamp or block.number may allow miner-influenced logic.',
            ))
        return findings

    def _run_unchecked_call_detector(self, function_node: Any) -> List[Finding]:
        findings: List[Finding] = []
        for node in function_node.walk():
            if node.type == 'method_call_expression':
                call_text = self.parser.node_text(self.source, node)
                if re.search(r'\.(call|delegatecall|send)\(', call_text):
                    if not self._is_checked(call_text):
                        findings.append(Finding(
                            vulnerability='UncheckedReturn',
                            function=self._fn_name(function_node),
                            location=node.start_point,
                            message=f'Unchecked low-level call: {call_text.strip()}',
                        ))
        return findings

    def _run_access_control_detector(self, function_node: Any) -> List[Finding]:
        findings: List[Finding] = []
        fn_name_node = function_node.child_by_field_name('name')
        fn_name = self._fn_name(function_node)
        visibility = self._find_modifier(function_node, 'visibility')
        modifiers = self._extract_modifiers(function_node)
        if fn_name in ('initialize', 'init', 'setup') and 'onlyOwner' not in modifiers and 'auth' not in modifiers:
            findings.append(Finding(
                vulnerability='AccessControl',
                function=fn_name,
                location=function_node.start_point,
                message='Initialization or bootstrap function lacks explicit access control modifiers.',
            ))
        if self._has_state_write(function_node) and visibility == 'public' and 'onlyOwner' not in modifiers and 'auth' not in modifiers:
            findings.append(Finding(
                vulnerability='AccessControl',
                function=fn_name,
                location=function_node.start_point,
                message='Public function performs state updates without explicit access control.',
            ))
        return findings

    def _run_taint_analysis(self, function_node: Any, cfg: nx.DiGraph) -> List[Finding]:
        analyzer = TaintAnalyzer(self.source, function_node, cfg)
        analyzer.analyze()
        return analyzer.findings

    def _find_modifier(self, function_node: Any, kind: str) -> Optional[str]:
        for child in function_node.children:
            if child.type == 'visibility_modifier':
                return self.parser.node_text(self.source, child)
        return None

    def _extract_modifiers(self, function_node: Any) -> Set[str]:
        return {
            self.parser.node_text(self.source, child)
            for child in function_node.children
            if child.type == 'modifier_invocation'
        }

    def _has_state_write(self, function_node: Any) -> bool:
        text = self.source[function_node.start_byte:function_node.end_byte]
        return bool(re.search(r'\bstorage\b|\b\w+\s*=\s*.*;', text))

    def _is_checked(self, text: str) -> bool:
        return 'require(' in text or 'assert(' in text or 'if' in text

    def _fn_name(self, function_node: Any) -> str:
        name = function_node.child_by_field_name('name')
        return self.parser.node_text(self.source, name) if name else '<constructor>'


if __name__ == '__main__':
    example = Path(__file__).resolve().parent / 'sample' / 'Example.sol'
    if example.exists():
        source_code = example.read_text(encoding='utf-8')
        engine = SoliditySASTEngine(source_code)
        for finding in engine.run_detectors():
            print(f'{finding.vulnerability}: {finding.function} @ {finding.location} - {finding.message}')
    else:
        print('Place an Example.sol file in the sample/ directory to run the engine.')
