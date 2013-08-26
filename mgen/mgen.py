#!/usr/bin/env python3

import argparse
import collections
import functools
import re
import sys

from lxml.builder import E
from lxml import etree


print_error = functools.partial(print, file=sys.stderr)


_IDENTIFIER_RE = re.compile(r"[a-zA-Z_][a-zA-Z_0-9]*")
_ARG_SEP = re.compile(r"\s*,\s*")
_PROC_RE = re.compile(r"({ident})\(\s*(.*)\s*\)$".format(
    ident=_IDENTIFIER_RE.pattern))


class Error(Exception):
    pass


class DirectiveError(Error):

    def __init__(self, node, msg):
        super().__init__(msg)
        self.node = node
        self.msg = msg

    def __str__(self):
        return "{}:{}: {}".format(
                self.node.getroottree().docinfo.URL,
                self.node.sourceline,
                self.msg)


def _check_identifier(directive, ident):
    if not _IDENTIFIER_RE.match(ident):
        directive._raise_error("bad identifier: {!r}", ident)


def _check_duplicate(directive, container, name, desc):
    if name in container:
        directive._raise_error("duplicate {desc}: {name!r}",
            name=name, desc=desc)


class Directive(object):

    def __init__(self, comment, content):
        self.comment = comment
        self._parse_content(content)

    def _parse_content(self, content):
        raise NotImplementedError()

    def _insert_after_comment(self, nodes):
        prior = self.comment
        for node in nodes:
            prior.addnext(node)
            prior = node

    def _raise_error(self, fmt, *args, **kw):
        raise DirectiveError(
                node=self.comment,
                msg=fmt.format(*args, **kw))

    DIRECTIVE_TYPES = {}
    @classmethod
    def register(cls, name):
        def decorator(dcls):
            if name in cls.DIRECTIVE_TYPES:
                raise ValueError("{} already registered".format(name))
            cls.DIRECTIVE_TYPES[name] = dcls
            dcls.TYPE = name
        return decorator

    @classmethod
    def create(cls, comment):
        type_name, _, content = comment.text.lstrip(" !").partition(" ")
        try:
            dir_type = cls.DIRECTIVE_TYPES[type_name]
        except KeyError:
            raise DirectiveError(node=comment,
                    msg="no such directive: {!r}".format(type_name))
        return dir_type(comment, content.strip())


@Directive.register("PROC")
class ProcDirective(Directive):

    def _parse_content(self, content):
        match = _PROC_RE.match(content)
        if not match:
            self._raise_error("badly formed procedure definition: {!r}",
                    content)
        self.name, args_str = match.groups()
        if not args_str:
            self.arg_names = frozenset()
        else:
            self.arg_names = frozenset(_ARG_SEP.split(args_str))
            for arg_name in self.arg_names:
                _check_identifier(self, arg_name)

    @property
    def _call_var(self):
        return "CALL#{}".format(self.name)

    def _mangled_arg_var(self, arg_name):
        return "_CALL_{}_ARG_{}".format(self.name, arg_name)

    def _unmangled_arg_var(self, arg_name):
        return "ARG_{}".format(arg_name)

    def execute_directive(self, ctx):
        if self.name in ctx.procs:
            self._raise_error("duplicate definitions for procedure {!r}",
                    self.name)
        ctx.procs[self.name] = self

        call_var = self._call_var

        # Set up condition and debug logging for the procedure event.
        nodes = [
            E.if_variable(name=call_var, comparator="EQUALS", value="1"),
            E.set_variable(name=call_var, value="0"),
            E.log(text="Called {}".format(self.name)),
            ]
        # Copy variable values to un-mangled versions, so that they are
        # intuitive to use in formulas.
        nodes.extend(
                E.set_variable(
                    name=self._unmangled_arg_var(arg_name),
                    value=self._mangled_arg_var(arg_name))
                for arg_name in self.arg_names)
        self._insert_after_comment(nodes)

    def _check_args(self, arg_exprs):
        provided_args = arg_exprs.keys()
        unexpected_args = provided_args - self.arg_names
        if unexpected_args:
            self._raise_error("unexpected arguments: {}",
                ",".join(repr(n) for n in sorted(unexpected_args)))
        missing_args = self.arg_names - provided_args
        if missing_args:
            self._raise_error("missing arguments: {}",
                ",".join(repr(n) for n in sorted(missing_args)))

    def sched_nodes(self, arg_exprs):
        self._check_args(arg_exprs)
        nodes= [
            E.set_variable(name=self._call_var, value="1")
            ]
        nodes.extend(
                E.set_variable(name=self._mangled_arg_var(arg_name), value=arg_expr)
                for arg_name, arg_expr in arg_exprs.items())
        return nodes


class _BaseInvokeProcDirective(Directive):

    def _parse_content(self, content):
        match = _PROC_RE.match(content)
        if not match:
            self._raise_error("badly formed procedure definition: {!r}",
                content)
        self.proc_name, args_str = match.groups()
        self.arg_exprs = {}
        if args_str:
            for name_expr in _ARG_SEP.split(args_str):
                arg_name, _, arg_expr = [s.strip()
                        for s in name_expr.partition("=")]
                _check_identifier(self, arg_name)
                _check_duplicate(self, self.arg_exprs, arg_name, "argument")
                self.arg_exprs[arg_name] = arg_expr


@Directive.register("SCHED_PROC")
class DeferProcDirective(_BaseInvokeProcDirective):

    def execute_directive(self, ctx):
        try:
            proc = ctx.procs[self.proc_name]
        except KeyError:
            self._raise_error("unknown procedure: {!r}", self.proc_name)
        self._insert_after_comment(proc.sched_nodes(self.arg_exprs))


class _Context(object):

    def __init__(self):
        self.procs = {}


def process(script):
    directive_groups = collections.defaultdict(list)
    for comment in script.xpath("//comment()"):
        if comment.text.lstrip(" ").startswith("!"):
            directive = Directive.create(comment)
            directive_groups[directive.TYPE].append(directive)

    ctx = _Context()
    order = ["PROC", "SCHED_PROC"]
    for type_name in order:
        for directive in directive_groups[type_name]:
            directive.execute_directive(ctx)


def main():
    ap = argparse.ArgumentParser(description="Generate Artemis SBS mission")
    ap.add_argument("input", metavar="INPUT", type=argparse.FileType("rb"),
            help="Input file")
    ap.add_argument("output", metavar="OUTPUT", type=argparse.FileType("wb"),
            help="Output file")
    args = ap.parse_args()

    with args.input, args.output:
        script = etree.parse(args.input)
        try:
            process(script)
        except DirectiveError as exc:
            print_error(exc)
            return 1
        script.write(args.output, pretty_print=True, with_comments=True)


if __name__ == "__main__":
    main()
