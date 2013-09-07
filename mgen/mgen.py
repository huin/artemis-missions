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


class DuplicateIdentError(Error):

    def __init__(self, msg):
        super().__init__(msg)
        self.msg = msg


class UnknownIdentError(Error):

    def __init__(self, msg):
        super().__init__(msg)
        self.msg = msg


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

    # TODO: Check that the comment is within an appropriate parent.

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
        if args or kw:
            msg = fmt.format(*args, **kw)
        else:
            msg = str(fmt)
        raise DirectiveError(node=self.comment, msg=msg)

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
        try:
            ctx.register_proc(self.name, self)
        except DuplicateIdentError as exc:
            self._raise_error(exc)

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
            proc = ctx.get_proc(self.proc_name)
        except UnknownIdentError as exc:
            self._raise_error(str(exc))
        self._insert_after_comment(proc.sched_nodes(self.arg_exprs))


class _BaseStateDirective(Directive):

    def _parse_content(self, content):
        parts = content.split()
        try:
            self.sm_name = parts.pop(0)
        except IndexError:
            self._raise_error("expected state machine name identifier")
        _check_identifier(self, self.sm_name)

        if len(parts) != self._NUM_IDENTS:
            self._raise_error(
                    "expected {} identifiers after state machine name, got {}",
                    self._NUM_IDENTS, len(parts))
        self.idents = parts
        for ident in self.idents:
            _check_identifier(self, ident)

    def execute_directive(self, ctx):
        sm = ctx.get_state_machine(self.sm_name)
        self._execute_impl(ctx, sm, *self.idents)


@Directive.register("STATE_MACHINE")
class StateMachineDirective(_BaseStateDirective):

    _NUM_IDENTS = 0

    def _parse_content(self, content):
        super()._parse_content(content)
        self.state_name_to_id = {}

    def state_id(self, state_name):
        try:
            id_ = self.state_name_to_id[state_name]
        except KeyError:
            id_ = len(self.state_name_to_id) + 1
            self.state_name_to_id[state_name] = id_
        return id_

    @property
    def state_var(self):
        return "_STATE_VALUE_{}".format(self.sm_name)

    @property
    def old_state_var(self):
        return "_STATE_OLD_VALUE_{}".format(self.sm_name)

    @property
    def new_state_var(self):
        return "_STATE_NEW_VALUE_{}".format(self.sm_name)

    @property
    def transition_var(self):
        return "_STATE_CHANGING_{}".format(self.sm_name)

    def if_transitioning_node(self):
        """Returns a condition node that is true when transitioning."""
        return E.if_variable(name=self.transition_var, comparator="EQUALS", value="1")

    def execute_directive(self, ctx):
        try:
            ctx.register_state_machine(self.sm_name, self)
        except DuplicateIdentError as exc:
            self._raise_error(exc)
        # TODO: This needs to be changed so that state transition is
        # multi-stage, so that entering a state happens after leaving a state.
        self._insert_after_comment([
            # Event to complete state transition after IF_ENTERING_STATE and
            # IF_LEAVING_STATE events have been fired.
            E.event(
                # Is this state machine transitioning?
                self.if_transitioning_node(),
                # Stop transitioning.
                E.set_variable(name=self.transition_var, value="0"),
                E.set_variable(name=self.new_state_var, value="0"),
                E.set_variable(name=self.old_state_var, value="0"),
                # Update current state.
                E.set_variable(name=self.state_var, value=self.new_state_var),
                # Debug log entry.
                E.log(text="state machine [{}] transition complete".format(self.sm_name)),
                ),
            ])


@Directive.register("SWITCH_STATE")
class SwitchStateDirective(_BaseStateDirective):
    _NUM_IDENTS = 1
    def _execute_impl(self, ctx, sm, new_state_name):
        new_state_id = sm.state_id(new_state_name)
        self._insert_after_comment([
            # Start transitioning.
            E.set_variable(name=sm.transition_var, value="1"),
            # new/old states are used by IF_ENTERING_STATE and IF_LEAVING_STATE.
            # Remember new state.
            E.set_variable(name=sm.new_state_var, value=str(new_state_id)),
            # Remember old state.
            E.set_variable(name=sm.old_state_var, value=sm.state_var),
            ])


@Directive.register("IF_ENTERING_STATE")
class IfEnteringStateDirective(_BaseStateDirective):
    _NUM_IDENTS = 1
    def _execute_impl(self, ctx, sm, new_state_name):
        new_state_id = sm.state_id(new_state_name)
        self._insert_after_comment([
            E.if_variable(name=sm.new_state_var, comparator="EQUALS",
                value=str(new_state_id)),
            ])


@Directive.register("IF_LEAVING_STATE")
class IfEnteringStateDirective(_BaseStateDirective):
    _NUM_IDENTS = 1
    def _execute_impl(self, ctx, sm, old_state_name):
        sm = ctx.get_state_machine(self.sm_name)
        old_state_id = sm.state_id(old_state_name)
        self._insert_after_comment([
            E.if_variable(name=sm.old_state_var, comparator="EQUALS",
                value=str(old_state_id)),
            ])


@Directive.register("IF_CHANGING_STATE")
class IfEnteringStateDirective(_BaseStateDirective):
    _NUM_IDENTS = 0
    def _execute_impl(self, ctx, sm):
        sm = ctx.get_state_machine(self.sm_name)
        self._insert_after_comment([sm.if_transitioning_node()])


class _Context(object):

    _DICTS = dict(
            procs="procedure",
            state_machines="state machine",
            )

    def __init__(self):
        for attr in self._DICTS:
            setattr(self, attr, {})

    def _register(self, dest_attr, name, value):
        for attr, type_desc in self._DICTS.items():
            if name in getattr(self, attr):
                raise DuplicateIdentError(
                        "existing {type_desc} exists with name {name!r}".format(
                            type_desc=type_desc,
                            name=name))
        getattr(self, dest_attr)[name] = value

    def _get(self, src_attr, name):
        try:
            return getattr(self, src_attr)[name]
        except KeyError:
            raise UnknownIdentError(
                    "no {type_desc} exists with name {name!r}".format(
                        type_desc=self._DICTS[src_attr],
                        name=name))

    def get_proc(self, name):
        return self._get("procs", name)

    def get_state_machine(self, name):
        return self._get("state_machines", name)

    def register_proc(self, name, proc):
        self._register("procs", name, proc)

    def register_state_machine(self, name, state_machine):
        self._register("state_machines", name, state_machine)


def process(script):
    errors = []
    directive_groups = collections.defaultdict(list)
    for comment in script.xpath("//comment()"):
        if comment.text.lstrip(" ").startswith("!"):
            try:
                directive = Directive.create(comment)
            except DirectiveError as exc:
                errors.append(exc)
            else:
                directive_groups[directive.TYPE].append(directive)

    ctx = _Context()
    order = [
            "PROC",
            "SCHED_PROC",

            "SETUP_NAMED",
            "TEARDOWN_NAMED",

            "STATE_MACHINE",
            "SWITCH_STATE",
            "IF_ENTERING_STATE",
            "IF_LEAVING_STATE",
            "IF_CHANGING_STATE",
            "IF_IN_STATE",
            ]
    for type_name in order:
        for directive in directive_groups[type_name]:
            try:
                directive.execute_directive(ctx)
            except DirectiveError as exc:
                errors.append(exc)
    return errors


def main():
    ap = argparse.ArgumentParser(description="Generate Artemis SBS mission")
    ap.add_argument("input", metavar="INPUT", type=argparse.FileType("rb"),
            help="Input file")
    ap.add_argument("output", metavar="OUTPUT", type=argparse.FileType("wb"),
            help="Output file")
    args = ap.parse_args()

    with args.input, args.output:
        script = etree.parse(args.input)
        errors = process(script)
        script.write(args.output, pretty_print=True, with_comments=True)
        if errors:
            for error in errors:
                print_error(error)
            return 1


if __name__ == "__main__":
    main()
