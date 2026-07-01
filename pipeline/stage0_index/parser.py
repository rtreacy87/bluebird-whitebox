"""Intra-file Java structural parser (Stage 0).

Deterministic, no LLM. Parses a single .java file with javalang and returns
plain-data symbol/call/field-access/input-source records scoped to that file
only. Per CLAUDE.md build order, cross-file resolution is explicitly out of
scope here -- any call whose target isn't a symbol parsed from THIS file is
left unresolved (resolved=False, callee_raw_name preserved), including calls
into framework/library code. Nothing in this module writes to a database;
pipeline.stage0_index.indexer does that.
"""

from dataclasses import dataclass, field
from typing import Optional

import javalang

ENTRYPOINT_ANNOTATIONS = {
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "DeleteMapping",
    "PatchMapping",
    "RequestMapping",
}

# Spring annotation name -> input_sources.kind (per schema.sql CHECK constraint)
INPUT_ANNOTATION_MAP = {
    "RequestParam": "RequestParam",
    "PathVariable": "PathVariable",
    "RequestBody": "RequestBody",
    "RequestHeader": "Header",
    "CookieValue": "Cookie",
    "SessionAttribute": "SessionAttribute",
}


class JavaParseError(Exception):
    def __init__(self, path, cause):
        super().__init__(f"failed to parse {path}: {cause}")
        self.path = path
        self.cause = cause


@dataclass
class SymbolRecord:
    local_id: int  # index into the file's symbol list, used to link parent/callee before DB insert
    kind: str  # 'class' | 'method' | 'field' | 'constructor'
    name: str
    signature: Optional[str]
    parent_local_id: Optional[int]
    line_start: Optional[int]
    line_end: Optional[int]
    is_entrypoint: bool = False


@dataclass
class CallEdgeRecord:
    caller_local_id: int
    callee_local_id: Optional[int]  # None until/unless resolved intra-file
    callee_raw_name: str
    resolved: bool
    line_no: Optional[int]


@dataclass
class FieldAccessRecord:
    symbol_local_id: int  # method/constructor doing the access
    field_name: str
    owning_class: Optional[str]
    access_type: str  # 'read' | 'write'
    line_no: Optional[int]


@dataclass
class InputSourceRecord:
    symbol_local_id: int
    kind: str
    param_name: Optional[str]
    line_no: Optional[int]


@dataclass
class ParsedFile:
    symbols: list = field(default_factory=list)
    call_edges: list = field(default_factory=list)
    field_access: list = field(default_factory=list)
    input_sources: list = field(default_factory=list)


def _annotation_name(annotation):
    # javalang Annotation.name is either a plain string or dotted -- Spring
    # annotations here are always simple names.
    return annotation.name


def _annotation_names(node):
    return [_annotation_name(a) for a in (getattr(node, "annotations", None) or [])]


def _annotation_string_value(annotation):
    """Best-effort extraction of a single string literal argument, e.g. @RequestParam("id")."""
    element = annotation.element
    if element is None:
        return None
    literal = getattr(element, "value", None)
    if isinstance(literal, str):
        return literal.strip('"')
    return None


def _type_to_str(t):
    if t is None:
        return "var"
    name = t.name
    if getattr(t, "arguments", None):
        args = ", ".join(_type_argument_to_str(a) for a in t.arguments)
        name = f"{name}<{args}>"
    dims = getattr(t, "dimensions", None) or []
    name += "[]" * len(dims)
    return name


def _type_argument_to_str(arg):
    inner_type = getattr(arg, "type", None)
    if inner_type is None:
        return "?"
    return _type_to_str(inner_type)


def _params_to_str(params):
    parts = []
    for p in params:
        parts.append(f"{_type_to_str(p.type)} {p.name}")
    return ", ".join(parts)


def _line_starts(source):
    """Character offset of the start of each 1-indexed line."""
    starts = [0]
    for i, c in enumerate(source):
        if c == "\n":
            starts.append(i + 1)
    return starts


def _offset_of_line(line_starts, line):
    idx = line - 1
    if idx < 0 or idx >= len(line_starts):
        return None
    return line_starts[idx]


def _block_end_line(source, from_offset):
    """Scan forward from from_offset to find the line where the first '{'
    encountered is closed by its matching '}', skipping string/char literals
    and comments so brace characters inside them don't desync the count."""
    n = len(source)
    i = source.find("{", from_offset)
    if i == -1:
        return None

    depth = 0
    in_str = in_char = in_line_comment = in_block_comment = False
    j = i
    while j < n:
        c = source[j]
        nxt = source[j + 1] if j + 1 < n else ""
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
        elif in_block_comment:
            if c == "*" and nxt == "/":
                in_block_comment = False
                j += 1
        elif in_str:
            if c == "\\":
                j += 1
            elif c == '"':
                in_str = False
        elif in_char:
            if c == "\\":
                j += 1
            elif c == "'":
                in_char = False
        else:
            if c == "/" and nxt == "/":
                in_line_comment = True
                j += 1
            elif c == "/" and nxt == "*":
                in_block_comment = True
                j += 1
            elif c == '"':
                in_str = True
            elif c == "'":
                in_char = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return source.count("\n", 0, j) + 1
        j += 1
    return None


class _FileParser:
    def __init__(self, source):
        self.source = source
        self.line_starts = _line_starts(source)
        self.result = ParsedFile()
        self._next_local_id = 0
        # name -> list of local_ids, for intra-file callee resolution
        self._methods_by_name = {}
        self._field_names = set()

    def _new_id(self):
        i = self._next_local_id
        self._next_local_id += 1
        return i

    def _end_line_for(self, start_line):
        if start_line is None:
            return None
        offset = _offset_of_line(self.line_starts, start_line)
        if offset is None:
            return None
        return _block_end_line(self.source, offset)

    def parse(self, tree):
        for type_decl in tree.types:
            if isinstance(type_decl, (javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration)):
                self._process_type(type_decl, parent_local_id=None)
        return self.result

    def _process_type(self, node, parent_local_id):
        class_id = self._new_id()
        start = node.position.line if node.position else None
        self.result.symbols.append(
            SymbolRecord(
                local_id=class_id,
                kind="class",
                name=node.name,
                signature=None,
                parent_local_id=parent_local_id,
                line_start=start,
                line_end=self._end_line_for(start),
            )
        )

        for member in node.body:
            if isinstance(member, javalang.tree.FieldDeclaration):
                self._process_field(member, class_id)

        for member in node.body:
            if isinstance(member, javalang.tree.MethodDeclaration):
                self._process_method(member, class_id, is_constructor=False)
            elif isinstance(member, javalang.tree.ConstructorDeclaration):
                self._process_method(member, class_id, is_constructor=True)
            elif isinstance(member, (javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration)):
                self._process_type(member, parent_local_id=class_id)

        return class_id

    def _process_field(self, node, class_id):
        for declarator in node.declarators:
            field_id = self._new_id()
            start = node.position.line if node.position else None
            self.result.symbols.append(
                SymbolRecord(
                    local_id=field_id,
                    kind="field",
                    name=declarator.name,
                    signature=_type_to_str(node.type),
                    parent_local_id=class_id,
                    line_start=start,
                    line_end=start,
                )
            )
            self._field_names.add(declarator.name)

    def _process_method(self, node, class_id, is_constructor):
        method_id = self._new_id()
        start = node.position.line if node.position else None
        annotations = _annotation_names(node)
        kind = "constructor" if is_constructor else "method"
        return_type = "void" if is_constructor else _type_to_str(node.return_type)
        signature = f"{return_type} {node.name}({_params_to_str(node.parameters)})"

        self.result.symbols.append(
            SymbolRecord(
                local_id=method_id,
                kind=kind,
                name=node.name,
                signature=signature,
                parent_local_id=class_id,
                line_start=start,
                line_end=self._end_line_for(start),
                is_entrypoint=bool(ENTRYPOINT_ANNOTATIONS & set(annotations)),
            )
        )
        self._methods_by_name.setdefault(node.name, []).append(method_id)

        self._process_input_sources(node, method_id, start)

        if node.body:
            self._process_calls(node, method_id)
            self._process_field_access(node, method_id)

    def _process_input_sources(self, method_node, method_id, method_line):
        for param in method_node.parameters:
            for annotation in param.annotations or []:
                name = _annotation_name(annotation)
                mapped_kind = INPUT_ANNOTATION_MAP.get(name)
                if mapped_kind is None:
                    continue
                explicit_name = _annotation_string_value(annotation)
                param_name = explicit_name or param.name
                self.result.input_sources.append(
                    InputSourceRecord(
                        symbol_local_id=method_id,
                        kind=mapped_kind,
                        param_name=param_name,
                        line_no=method_line,
                    )
                )

    def _process_calls(self, method_node, method_id):
        # javalang has a quirk: `foo.bar()` (no explicit "this") sets
        # MethodInvocation.qualifier to the dotted prefix directly, but an
        # explicit `this.foo.bar()` instead wraps the chain in a This node
        # whose .selectors list holds [MemberReference("foo"), MethodInvocation("bar")]
        # -- and the nested MethodInvocation's own .qualifier is None. Walking
        # This.selectors ourselves first (and excluding those invocation nodes
        # from the generic pass below) keeps qualifiers -- and therefore
        # same-class-method resolution -- correct for both forms.
        this_chain_ids = set()
        for _, this_node in method_node.filter(javalang.tree.This):
            if this_node.selectors:
                this_chain_ids |= self._process_selector_chain(["this"], this_node.selectors, method_id)

        for _, inv in method_node.filter(javalang.tree.MethodInvocation):
            if id(inv) in this_chain_ids:
                continue
            qualifier = inv.qualifier or ""
            parts = qualifier.split(".") if qualifier else []
            self._emit_call(method_id, parts, inv)
            # Plain `field.method()` (no "this.") has no separate MemberReference
            # AST node for `field` -- it's baked into the qualifier string -- so
            # this is the only place that can record the read. This_chain calls
            # are excluded here on purpose: the generic MemberReference walk in
            # _process_field_access already finds their `this.field` node.
            if parts and parts[0] in self._field_names:
                self.result.field_access.append(
                    FieldAccessRecord(
                        symbol_local_id=method_id,
                        field_name=parts[0],
                        owning_class=None,
                        access_type="read",
                        line_no=inv.position.line if inv.position else None,
                    )
                )

    def _process_selector_chain(self, prefix_parts, selectors, method_id):
        """Walk a This/MemberReference/MethodInvocation selector chain, emitting
        call_edges with correctly reconstructed qualifiers. Field reads (e.g.
        `this.jdbcTemplate`) are intentionally NOT emitted here -- the generic
        MemberReference walk in _process_field_access already finds those same
        nested nodes; emitting here too would double-count them. Returns the
        set of MethodInvocation node ids handled here so the generic
        filter-based call pass doesn't reprocess them."""
        handled_ids = set()
        parts = list(prefix_parts)
        for item in selectors:
            if isinstance(item, javalang.tree.MethodInvocation):
                self._emit_call(method_id, parts, item)
                handled_ids.add(id(item))
                parts = parts + [item.member]
            elif isinstance(item, javalang.tree.MemberReference):
                parts = parts + [item.member]
            else:
                # array access, class reference, etc. -- stop reconstructing,
                # remaining calls in the chain are still found by the generic pass
                break
        return handled_ids

    def _emit_call(self, method_id, qualifier_parts, inv):
        member = inv.member
        raw_name = ".".join(qualifier_parts + [member]) if qualifier_parts else member
        line_no = inv.position.line if inv.position else None

        callee_local_id = None
        resolved = False
        # Only a bare call, or an explicit `this.method()` with no field hop
        # in between, can be a same-class method call.
        if qualifier_parts in ([], ["this"]):
            candidates = self._methods_by_name.get(member)
            if candidates:
                # best-effort: arg-count/overload disambiguation isn't tracked
                # per-candidate, so this takes the first same-named method.
                callee_local_id = self._best_overload(candidates, len(inv.arguments or []))
                resolved = True

        self.result.call_edges.append(
            CallEdgeRecord(
                caller_local_id=method_id,
                callee_local_id=callee_local_id,
                callee_raw_name=raw_name,
                resolved=resolved,
                line_no=line_no,
            )
        )

    def _best_overload(self, candidate_ids, arg_count):
        # We don't have per-overload arg counts recorded here (methods_by_name
        # only stores ids); resolution by name alone is already the documented
        # intra-file best-effort behavior, so just take the first candidate.
        return candidate_ids[0]

    def _process_field_access(self, method_node, method_id):
        assigned_local_ids = set()

        for _, assign in method_node.filter(javalang.tree.Assignment):
            target = assign.expressionl
            field_name, line_no = self._field_ref(target)
            if field_name is None:
                continue
            assigned_local_ids.add(id(target))
            self.result.field_access.append(
                FieldAccessRecord(
                    symbol_local_id=method_id,
                    field_name=field_name,
                    owning_class=None,
                    access_type="write",
                    line_no=line_no or (assign.position.line if assign.position else None),
                )
            )

        for _, ref in method_node.filter(javalang.tree.MemberReference):
            if id(ref) in assigned_local_ids:
                continue
            field_name, line_no = self._field_ref(ref)
            if field_name is None:
                continue
            self.result.field_access.append(
                FieldAccessRecord(
                    symbol_local_id=method_id,
                    field_name=field_name,
                    owning_class=None,
                    access_type="read",
                    line_no=line_no,
                )
            )

    def _field_ref(self, node):
        if not isinstance(node, javalang.tree.MemberReference):
            return None, None
        qualifier = node.qualifier or ""
        if qualifier not in ("", "this"):
            return None, None
        if node.member not in self._field_names:
            return None, None
        line_no = node.position.line if node.position else None
        return node.member, line_no


def parse_source(path, source):
    """Parse one file's source. Returns a ParsedFile. Raises JavaParseError on failure."""
    try:
        tree = javalang.parse.parse(source)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError) as e:
        raise JavaParseError(path, e) from e
    return _FileParser(source).parse(tree)
