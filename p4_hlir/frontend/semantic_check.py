# Copyright 2013-present Barefoot Networks, Inc. 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ast import *
from collections import defaultdict
import json
import os
import unused_removal
import blackbox_process

class ObjectTable:
    def __init__(self):
        self.objs = defaultdict(list)
        
    def add_object(self, name, ast_node):
        self.objs[name].append(ast_node)

    def get_object(self, name, ast_type):
        if name not in self.objs: return None
        objects = self.objs[name]
        for obj in objects:
            if isinstance(obj, ast_type): return obj
        return None

class SymbolTable:
    def __init__(self):
        self.scopes = []

    def enterscope(self):
        self.scopes.append(defaultdict(set))

    def exitscope(self):
        self.scopes.pop()

    def popscope(self):
        return self.scopes.pop()

    def pushscope(self, scope):
        self.scopes.append(scope)

    def add_type(self, name, type_):
        assert(len(self.scopes) > 0)
        scope = self.scopes[-1]
        scope[name].add(type_)

    def has_type(self, name, type_):
        for scope in reversed(self.scopes):
            if name in scope:
                if type_ in scope[name]: return True
        return False

    def get_types(self, name):
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

class P4SemanticChecker:
    def __init__(self):
        self._bind()

    def _bind(self):
        P4Program.check = check_P4Program
        P4BlackboxType.check = check_P4BlackboxType
        P4BlackboxInstance.check = check_P4BlackboxInstance
        P4HeaderType.check = check_P4HeaderType
        P4HeaderInstance.check = check_P4HeaderInstance
        P4HeaderInstanceRegular.check = check_P4HeaderInstanceRegular
        P4HeaderInstanceMetadata.check = check_P4HeaderInstanceMetadata
        P4FieldList.check = check_P4FieldList
        P4FieldListCalculation.check = check_P4FieldListCalculation
        P4CalculatedField.check = check_P4CalculatedField
        P4ValueSet.check = check_P4ValueSet
        P4ParserFunction.check = check_P4ParserFunction
        P4Counter.check = check_P4Counter
        P4Meter.check = check_P4Meter
        P4Register.check = check_P4Register
        P4PrimitiveAction.check = check_P4PrimitiveAction
        P4ActionFunction.check = check_P4ActionFunction
        P4Table.check = check_P4Table
        P4ActionProfile.check = check_P4ActionProfile
        P4ActionSelector.check = check_P4ActionSelector
        P4ControlFunction.check = check_P4ControlFunction

        P4TypeSpec.check = check_P4TypeSpec

        P4RefExpression.check = check_P4RefExpression
        P4FieldRefExpression.check = check_P4FieldRefExpression
        P4HeaderRefExpression.check = check_P4HeaderRefExpression
        P4RefExpression.check = check_P4RefExpression
        P4String.check = check_P4String
        P4Integer.check = check_P4Integer
        P4Bool.check = check_P4Bool
        P4TypedRefExpression.check = check_P4TypedRefExpression
        P4UserHeaderRefExpression.check = check_P4UserHeaderRefExpression
        P4UserMetadataRefExpression.check = check_P4UserMetadataRefExpression
        P4UserBlackboxRefExpression.check = check_P4UserBlackboxRefExpression

        P4BoolBinaryExpression.check = check_P4BoolBinaryExpression
        P4BoolUnaryExpression.check = check_P4BoolUnaryExpression
        P4BinaryExpression.check = check_P4BinaryExpression
        P4UnaryExpression.check = check_P4UnaryExpression
        P4ValidExpression.check = check_P4ValidExpression

        P4ParserExtract.check = check_P4ParserExtract
        P4ParserSetMetadata.check = check_P4ParserSetMetadata
        P4ParserImmediateReturn.check = check_P4ParserImmediateReturn
        P4ParserSelectReturn.check = check_P4ParserSelectReturn
        P4ParserSelectCase.check = check_P4ParserSelectCase
        P4ParserSelectDefaultCase.check = check_P4ParserSelectDefaultCase
        P4ParserParseError.check = check_P4ParserParseError

        P4CurrentExpression.check = check_P4CurrentExpression

        P4ActionCall.check = check_P4ActionCall

        P4BlackboxTypeAttribute.check = check_P4BlackboxTypeAttribute
        P4BlackboxTypeAttributeProp.check = check_P4BlackboxTypeAttributeProp
        P4BlackboxTypeMethod.check = check_P4BlackboxTypeMethod
        P4BlackboxTypeMethodAccess.check = check_P4BlackboxTypeMethodAccess

        P4BlackboxInstanceAttribute.check = check_P4BlackboxInstanceAttribute

        P4BlackboxMethodCall.check = check_P4BlackboxMethodCall

        P4TableFieldMatch.check = check_P4TableFieldMatch

        P4ControlFunctionStatement.check = check_P4ControlFunctionStatement
        P4ControlFunctionApply.check = check_P4ControlFunctionApply
        P4ControlFunctionApplyAndSelect.check = check_P4ControlFunctionApplyAndSelect
        P4ControlFunctionIfElse.check = check_P4ControlFunctionIfElse
        P4ControlFunctionCall.check = check_P4ControlFunctionCall

        P4ControlFunctionApplyActionCase.check = check_P4ControlFunctionApplyActionCase
        P4ControlFunctionApplyActionDefaultCase.check = check_P4ControlFunctionApplyActionDefaultCase
        P4ControlFunctionApplyHitMissCase.check = check_P4ControlFunctionApplyHitMissCase

        P4UpdateVerify.check = check_P4UpdateVerify

        P4ParserException.check = check_P4ParserException
        P4ParserExceptionDrop.check = check_P4ParserExceptionDrop
        P4ParserExceptionReturn.check = check_P4ParserExceptionReturn


        P4Action.detect_recursion = detect_recursion_P4Action
        P4PrimitiveAction.detect_recursion = detect_recursion_P4PrimitiveAction
        P4ActionFunction.detect_recursion = detect_recursion_P4ActionFunction
        P4ActionCall.detect_recursion = detect_recursion_P4ActionCall

        P4BlackboxMethodCall.detect_recursion = detect_recursion_P4BlackboxMethodCall

        P4FieldList.detect_recursion_field_list = detect_recursion_field_list_P4FieldList
        P4Expression.detect_recursion_field_list = detect_recursion_field_list_P4Expression
        P4RefExpression.detect_recursion_field_list = detect_recursion_field_list_P4RefExpression

        P4Program.check_action_typing = check_action_typing_P4Program
        P4Table.check_action_typing = check_action_typing_P4Table
        P4ActionProfile.check_action_typing = check_action_typing_P4ActionProfile
        P4ActionFunction.check_action_typing = check_action_typing_P4ActionFunction
        P4ActionCall.check_action_typing = check_action_typing_P4ActionCall
        P4PrimitiveAction.check_action_typing = check_action_typing_P4PrimitiveAction
        P4FieldRefExpression.check_action_typing = check_action_typing_P4FieldRefExpression
        P4HeaderRefExpression.check_action_typing = check_action_typing_P4HeaderRefExpression
        P4RefExpression.check_action_typing = check_action_typing_P4RefExpression
        P4Integer.check_action_typing = check_action_typing_P4Integer
        P4UnaryExpression.check_action_typing = check_action_typing_P4Integer
        P4BlackboxMethodCall.check_action_typing = check_action_typing_P4BlackboxMethodCall
        P4ParserFunction.check_action_typing = check_action_typing_P4ParserFunction
        P4ControlFunction.check_action_typing = check_action_typing_P4ControlFunction

        P4TreeNode.find_unused_args = find_unused_args_P4TreeNode
        P4Program.find_unused_args = find_unused_args_P4Program
        P4ActionFunction.find_unused_args = find_unused_args_P4ActionFunction
        P4ActionCall.find_unused_args = find_unused_args_P4ActionCall
        P4RefExpression.find_unused_args = find_unused_args_P4RefExpression
        P4UnaryExpression.find_unused_args = find_unused_args_P4UnaryExpression
        P4BinaryExpression.find_unused_args = find_unused_args_P4BinaryExpression

        P4TreeNode.remove_unused_args = remove_unused_args_P4TreeNode
        P4Program.remove_unused_args = remove_unused_args_P4Program
        P4ActionFunction.remove_unused_args = remove_unused_args_P4ActionFunction
        P4ActionCall.remove_unused_args = remove_unused_args_P4ActionCall


        P4Program.import_table_actions = import_table_actions_P4Program
        P4Table.import_table_actions = import_table_actions_P4Table
        P4ActionProfile.import_table_actions = import_table_actions_P4ActionProfile
        P4RefExpression.import_table_actions = import_table_actions_P4RefExpression

        P4Program.check_apply_action_cases = check_apply_action_cases_P4Program
        P4ControlFunction.check_apply_action_cases = check_apply_action_cases_P4ControlFunction
        P4BlackboxMethodCall.check_apply_action_cases = check_apply_action_cases_P4BlackboxMethodCall
        P4ControlFunctionStatement.check_apply_action_cases = check_apply_action_cases_P4ControlFunctionStatement
        P4ControlFunctionIfElse.check_apply_action_cases = check_apply_action_cases_P4ControlFunctionIfElse
        P4ControlFunctionApplyAndSelect.check_apply_action_cases = check_apply_action_cases_P4ControlFunctionApplyAndSelect
        P4ControlFunctionApplyActionCase.check_apply_action_cases = check_apply_action_cases_P4ControlFunctionApplyActionCase
        P4ControlFunctionApplyActionDefaultCase.check_apply_action_cases = check_apply_action_cases_P4ControlFunctionApplyActionDefaultCase
        P4ControlFunctionApplyHitMissCase.check_apply_action_cases = check_apply_action_cases_P4ControlFunctionApplyHitMissCase


        P4TreeNode.check_stateful_refs = check_stateful_refs_P4TreeNode
        P4Program.check_stateful_refs = check_stateful_refs_P4Program
        P4Table.check_stateful_refs = check_stateful_refs_P4Table
        P4ActionProfile.check_stateful_refs = check_stateful_refs_P4ActionProfile
        P4ActionFunction.check_stateful_refs = check_stateful_refs_P4ActionFunction
        P4ActionCall.check_stateful_refs = check_stateful_refs_P4ActionCall
        P4RefExpression.check_stateful_refs = check_stateful_refs_P4RefExpression

    def semantic_check(self, p4_program, primitives):
        header_fields = defaultdict(set)
        symbols = SymbolTable()
        objects = ObjectTable()

        self._add_std_primitives(p4_program, primitives)
        self._add_std_metadata(p4_program)

        P4TreeNode.reset_errors_cnt()
        p4_program.check(symbols, header_fields, objects)
        return P4TreeNode.get_errors_cnt()

    def _add_std_metadata(self, p4_program):
        std_t = P4HeaderType("std metadata", 1,
                             "standard_metadata_t",
                             [("ingress_port", P4Integer("",1,9), []),
                              ("packet_length", P4Integer("",1,32), []),
                              ("egress_spec", P4Integer("",1,9), []),
                              ("egress_port", P4Integer("",1,9), []),
                              ("egress_instance", P4Integer("",1,32), []),
                              ("instance_type", P4Integer("",1,32), []),
                              ("clone_spec", P4Integer("",1,32), [])],
                             None, None)
        
        std = P4HeaderInstanceMetadata("std_metadata", 1,
                                       "standard_metadata_t",
                                       "standard_metadata", [])

        p4_program.objects = [std_t, std] + p4_program.objects

    def _add_std_primitives(self, p4_program,
                            primitives):
        std_primitives = []
        for name, data in primitives.items():
            # TODO: actual file and linenumber
            properties = data["properties"]
            formals = data["args"]
            optional = []
            types = []
            for formal in formals:
                if "optional" in properties[formal]:
                    optional += [True]
                else:
                    optional += [False]
                assert("type" in properties[formal])
                type_ = properties[formal]["type"]
                allowed_types = set()
                if "int" in type_:
                    allowed_types.add(Types.int_)
                if "table_entry_data" in type_:
                    allowed_types.add(Types.int_)
                if "field" in type_:
                    allowed_types.add(Types.field)
                if "header_instance" in type_:
                    allowed_types.add(Types.header_instance)
                if "field_list" in type_:
                    allowed_types.add(Types.field_list)
                if "field_list_calculation" in type_:
                    allowed_types.add(Types.field_list_calculation)
                if "counter" in type_:
                    allowed_types.add(Types.counter)
                if "meter" in type_:
                    allowed_types.add(Types.meter)
                if "register" in type_:
                    allowed_types.add(Types.register)
                types += [allowed_types]
            p = P4PrimitiveAction(name, 1,
                                  name, data["args"],
                                  optional, types,
                                  std = True)
            std_primitives += [p]
        p4_program.objects = std_primitives + p4_program.objects


def get_type_name(obj):
    return Types.get_name(obj.get_type_())

def get_types_set_str(types):
    names = [Types.get_name(t) for t in types]
    return ", ".join(names)

def error_dup_objects(obj1, obj2):
    type_name = get_type_name(obj1)
    error_msg = "Redefinition of %s %s in file %s at line %d,"\
                " previous definition was in file %s at line %d"\
                % (type_name, obj1.name, obj2.filename, obj2.lineno,
                   obj1.filename, obj1.lineno)
    P4TreeNode.print_error(error_msg)

def import_objects(p4_objects, symbols, objects):
    for obj in p4_objects:
        if not isinstance(obj, P4NamedObject): continue
        name = obj.name
        prev = objects.get_object(name, type(obj))
        if prev:
            error_dup_objects(prev, obj)
        else:
            objects.add_object(name, obj)
            symbols.add_type(name, obj.get_type_())
        if isinstance(obj, P4HeaderInstanceRegular):
            subtype = (Types.header_instance_regular, obj.header_type)
            symbols.add_type(name, subtype)
        elif isinstance(obj, P4HeaderInstanceMetadata):
            subtype = (Types.header_instance_metadata, obj.header_type)
            symbols.add_type(name, subtype)
        elif isinstance(obj, P4BlackboxInstance):
            subtype = (Types.blackbox_instance, obj.blackbox_type)
            symbols.add_type(name, subtype)

def import_header_fields(p4_objects, header_fields):
    for obj in p4_objects:
        if not isinstance(obj, P4HeaderType): continue
        if obj.name in header_fields:
            # ignore redefinition, error will be reported later
            continue
        for field, _, _ in obj.layout:
            if field in header_fields[obj.name]:
                error_msg = "Header type %s defined in file %s at line %d"\
                            " has two fields named %s"\
                            % (obj.name, obj.filename, obj.lineno, field)
                P4TreeNode.print_error(error_msg)
            else:
                header_fields[obj.name].add(field)

# header types use header fields
def check_header_types(objects, header_fields):
    for obj in objects:
        if not isinstance(obj, P4HeaderInstance): continue
        name = obj.name
        header_type = obj.header_type
        if header_type not in header_fields:
            error_msg = "Header instance %s defined in file %s at line %d"\
                        " has unknown header type %s"\
                        % (name, obj.filename, obj.lineno, header_type)
            P4TreeNode.print_error(error_msg)


def detect_recursion_P4Action(self, objects, action):
    assert(False)

def detect_recursion_P4PrimitiveAction(self, objects, action):
    return False

def detect_recursion_P4ActionFunction(self, objects, action):
    for call in self.action_body:
        if call.detect_recursion(objects, action): return True
    return False

def detect_recursion_P4ActionCall(self, objects, action):
    if self.action.name == action: return True
    action_called = objects.get_object(self.action.name, P4Action)
    if not action_called: return False
    return action_called.detect_recursion(objects, action)

def detect_recursion_P4BlackboxMethodCall(self, objects, action):
    return False

def check_action_typing_P4Program(self, symbols, objects,
                                  trace = None):
    for obj in self.objects:
        if isinstance(obj, P4Table) or isinstance(obj, P4ControlFunction) \
           or isinstance(obj, P4ParserFunction):
            obj.check_action_typing(symbols, objects)

def check_action_typing_P4ParserFunction(self, symbols, objects, trace = None):
    for statement in self.extract_and_set_statements:
        if isinstance(statement, P4BlackboxMethodCall):
            statement.check_action_typing(symbols, objects, trace = [self.name])

def check_action_typing_P4ControlFunction(self, symbols, objects, trace = None):
    for statement in self.statements:
        if isinstance(statement, P4BlackboxMethodCall):
            statement.check_action_typing(symbols, objects, trace = [self.name])

def check_action_typing_P4Table(self, symbols, objects,
                                trace = None):
    if self.action_spec:
        for action_ref in self.action_spec:
            action = objects.get_object(action_ref.name, P4ActionFunction)
            symbols.enterscope()
            for formal in action.formals:
                symbols.add_type(formal, Types.int_)
            action.check_action_typing(symbols, objects, trace = [self.name])
            symbols.exitscope()

    if self.action_profile:
        action_profile = objects.get_object(self.action_profile.name, P4ActionProfile)
        action_profile.check_action_typing(symbols, objects, trace = [self.name])

def check_action_typing_P4ActionProfile(self, symbols, objects,
                                        trace = None):
    for action_ref in self.action_spec:
        action = objects.get_object(action_ref.name, P4ActionFunction)
        symbols.enterscope()
        for formal in action.formals:
            symbols.add_type(formal, Types.int_)
        action.check_action_typing(symbols, objects, trace = trace + [self.name])
        symbols.exitscope()

def check_action_typing_P4ActionFunction(self, symbols, objects,
                                         trace = None):
    for call in self.action_body:
        call.check_action_typing(symbols, objects, trace = trace + [self.name])

def get_trace_str(trace):
    return " -> ".join(trace)

def check_action_typing_P4ActionCall(self, symbols, objects,
                                     trace = None):
    action = objects.get_object(self.action.name, P4Action)
    types = []
    for arg in self.arg_list:
        types += [arg.check_action_typing(symbols, objects, trace = trace)]
    parent_scope = symbols.popscope()
    if type(action) is P4PrimitiveAction:
        trace = trace + [action.name]
        for idx, type_set in enumerate(types):
            expected_type_set = action.types[idx]
            if not (type_set & expected_type_set):
                error_msg = "Error when calling primitive %s (%s)"\
                            " in file %s at line %d:"\
                            " argument %d has type %s,"\
                            " but formal %s has type %s"\
                            % (action.name, get_trace_str(trace),
                               self.filename, self.lineno,
                               idx, get_types_set_str(type_set),
                               action.formals[idx], get_types_set_str(expected_type_set))
                P4TreeNode.print_error(error_msg)
                continue
            elif len(type_set & expected_type_set) > 1:
                error_msg = "Error when calling primitive %s (%s)"\
                            " in file %s at line %d:"\
                            " several candidates for argument %d,"\
                            " possible types are "\
                            % (action.name, get_trace_str(trace),
                               self.filename, self.lineno,
                               idx, get_types_set_str(type_set))
                P4TreeNode.print_error(error_msg)
                continue
                
    else:
        symbols.enterscope()
        for idx, type_set in enumerate(types):
            formal = action.formals[idx]
            for type_ in type_set: symbols.add_type(formal, type_)
        action.check_action_typing(symbols, objects, trace = trace)
        symbols.exitscope()
    symbols.pushscope(parent_scope)


def check_action_typing_P4BlackboxMethodCall(self, symbols, objects,
                                             trace = None):
    bbox_instance = objects.get_object(self.blackbox_instance.name, P4BlackboxInstance)
    assert(bbox_instance is not None)
    bbox_type = objects.get_object(bbox_instance.blackbox_type, P4BlackboxType)
    assert(bbox_type is not None)
    method = P4TreeNode.bbox_methods[bbox_type.name][self.method]
    types = []
    for arg in self.arg_list:
        types += [arg.check_action_typing(symbols, objects, trace = trace)]

    # funny name
    def type_spec_to_type_set(type_spec):
        type_ = type_spec.name
        if type_ == "header":
            subtype = attr_type_qualifiers["subtype"]
            return {(Types.header_instance_regular, subtype)}
        elif type_ == "metadata":
            subtype = attr_type_qualifiers["subtype"]
            return {(Types.header_instance_metadata, subtype)}
        elif type_ == "blackbox":
            subtype = attr_type_qualifiers["subtype"]
            return {(Types.blackbox_instance, subtype)}
        else:
            type_map = {
                "int" : {Types.int_},
                "bit" : {Types.int_, Types.field},
                "varbit" : {Types.int_, Types.field},
                "field_list" : {Types.field_list},
                "parser" : {Types.parser_function},
                "action" : {Types.action_function, Types.primitive_action},
                "table" : {Types.table},
                "control" : {Types.control_function},
                "counter" : {Types.counter},
                "meter" : {Types.meter},
                "register" : {Types.register},
                "field_list_calculation" : {Types.field_list_calculation},
                "parser_value_set" : {Types.value_set},
            }
            try:
                return type_map[type_]
            except:
                assert(0)

    parent_scope = symbols.popscope()
    trace = trace + [method.name]
    for idx, type_set in enumerate(types):
        expected_type_spec = method.param_list[idx][1]
        expected_type_set = type_spec_to_type_set(expected_type_spec)
        if not (type_set & expected_type_set):
            error_msg = "Error when calling blackbox method '%s' (%s)"\
                        " in file %s at line %d:"\
                        " argument %d has type %s, but formal '%s' has type %s"\
                        % (method.name, get_trace_str(trace),
                           self.filename, self.lineno,
                           idx, get_types_set_str(type_set),
                           method.param_list[idx][0],
                           get_types_set_str(expected_type_set))
            P4TreeNode.print_error(error_msg)
            continue
        elif len(type_set & expected_type_set) > 1:
            error_msg = "Error when calling blackbox method '%s' (%s)"\
                        " in file %s at line %d:"\
                        " several candidates for argument %d, possible types are "\
                        % (method.name, get_trace_str(trace),
                           self.filename, self.lineno,
                           idx, get_types_set_str(type_set))
            P4TreeNode.print_error(error_msg)
            continue
    symbols.pushscope(parent_scope)

def check_action_typing_P4FieldRefExpression(self, symbols, objects,
                                             trace = None):
    return {Types.field}

def check_action_typing_P4HeaderRefExpression(self, symbols, objects,
                                              trace = None):
    return {Types.header_instance}

def check_action_typing_P4RefExpression(self, symbols, objects,
                                        trace = None):
    return symbols.get_types(self.name)

def check_action_typing_P4Integer(self, symbols, objects,
                                  trace = None):
    return {Types.int_}

def check_action_typing_P4UnaryExpression(self, symbols, objects,
                                          trace = None):
    return {Types.int_}

def check_action_typing_P4PrimitiveAction(self, symbols, objects,
                                          trace = None):
    assert(False)

def check_action_typing_P4BinaryExpression(self, symbols, objects,
                                           trace = None):
    return {Types.int_}


def find_unused_args_P4TreeNode(self, removed, used_args = None):
    pass

def find_unused_args_P4Program(self, removed, used_args = None):
    for obj in self.objects:
        obj.find_unused_args(removed)

def find_unused_args_P4ActionFunction(self, removed, used_args = None):
    used_args = set()
    for call in self.action_body:
        call.find_unused_args(removed, used_args)
    new_formals = []
    for idx, formal in enumerate(self.formals):
        if formal not in used_args:
            error_msg = "Parameter %s of action %s defined"\
                        " in file %s at line %d is not being used"\
                        " and will be removed"\
                        % (formal, self.name, self.filename, self.lineno)
            P4TreeNode.print_warning(error_msg)
            removed[self.name].add(idx)
        else:
            new_formals.append(formal)
    self.formals = new_formals

def find_unused_args_P4ActionCall(self, removed, used_args = None):
    for arg in self.arg_list:
        arg.find_unused_args(removed, used_args)

def find_unused_args_P4RefExpression(self, removed, used_args = None):
    used_args.add(self.name)

def find_unused_args_P4UnaryExpression(self, removed, used_args = None):
    self.right.find_unused_args(removed, used_args)

def find_unused_args_P4BinaryExpression(self, removed, used_args = None):
    self.left.find_unused_args(removed, used_args)
    self.right.find_unused_args(removed, used_args)

def remove_unused_args_P4TreeNode(self, removed):
    pass

def remove_unused_args_P4Program(self, removed):
    for obj in self.objects:
        obj.remove_unused_args(removed)

def remove_unused_args_P4ActionFunction(self, removed):
    used_args = set()
    for call in self.action_body:
        call.remove_unused_args(removed)

def remove_unused_args_P4ActionCall(self, removed):
    if not removed[self.action.name]:
        return
    new_args = []
    for arg_idx, arg in enumerate(self.arg_list):
        if arg_idx not in removed[self.action.name]:
            new_args.append(arg)
    self.arg_list = new_args

def import_table_actions_P4Program(self, objects, table_actions, table_name = None):
    for obj in self.objects:
        if type(obj) is not P4Table: continue
        obj.import_table_actions(objects, table_actions)

def import_table_actions_P4Table(self, objects, table_actions, table_name = None):
    table_actions[self.name] = set()
    if self.action_spec:
        for action_ref in self.action_spec:
            action_ref.import_table_actions(objects, table_actions, table_name = self.name)
        
    if self.action_profile:
        action_profile = objects.get_object(self.action_profile.name, P4ActionProfile)
        action_profile.import_table_actions(objects, table_actions, table_name = self.name)

def import_table_actions_P4ActionProfile(self, objects, table_actions, table_name = None):
    for action_ref in self.action_spec:
        action_ref.import_table_actions(objects, table_actions, table_name = table_name)

def import_table_actions_P4RefExpression(self, objects, table_actions, table_name = None):
    table_actions[table_name].add(self.name)

def check_apply_action_cases_P4Program(self, table_actions, apply_table = None):
    for obj in self.objects:
        if type(obj) is not P4ControlFunction: continue
        obj.check_apply_action_cases(table_actions)

def check_apply_action_cases_P4ControlFunction(self, table_actions, apply_table = None):
    for statement in self.statements:
        statement.check_apply_action_cases(table_actions)


def check_apply_action_cases_P4BlackboxMethodCall(self, table_actions, apply_table = None):
    pass

def check_apply_action_cases_P4ControlFunctionStatement(self, table_actions, apply_table = None):
    pass

def check_apply_action_cases_P4ControlFunctionIfElse(self, table_actions, apply_table = None):
    for statement in self.if_body + self.else_body:
        statement.check_apply_action_cases(table_actions, apply_table = apply_table)

def check_apply_action_cases_P4ControlFunctionApplyAndSelect(self, table_actions, apply_table = None):
    apply_table = self.table.name
    for case in self.case_list:
        case.check_apply_action_cases(table_actions, apply_table = apply_table)
        
def check_apply_action_cases_P4ControlFunctionApplyActionCase(self, table_actions, apply_table = None):
    for action in self.action_list:
        action_name = action.name
        if action_name not in table_actions[apply_table]:
            error_msg = "Error in apply_table select block"\
                        " in file %s at line %d:"\
                        " case %s is not a valid action for table %s"\
                        % (self.filename, action.lineno,
                           action_name, apply_table)
            P4TreeNode.print_error(error_msg)

def check_apply_action_cases_P4ControlFunctionApplyActionDefaultCase(self, table_actions, apply_table = None):
    pass

def check_apply_action_cases_P4ControlFunctionApplyHitMissCase(self, table_actions, apply_table = None):
    pass

def check_has_start_parse_state(symbols):
    if not symbols.has_type("start", Types.parser_function):
        error_msg = "P4 program does not define a start parse state"
        P4TreeNode.print_error(error_msg)

def check_stateful_refs_P4TreeNode(self, symbols, objects, table = None):
    pass

def check_stateful_refs_P4Program(self, symbols, objects, table = None):
    for obj in self.objects:
        if type(obj) is not P4Table: continue
        obj.check_stateful_refs(symbols, objects)

def check_stateful_refs_P4Table(self, symbols, objects, table = None):
    if self.action_spec:
        for action_ref in self.action_spec:
            action = objects.get_object(action_ref.name, P4ActionFunction)
            action.check_stateful_refs(symbols, objects, table = self.name)
    if self.action_profile:
        action_profile = objects.get_object(self.action_profile.name, P4ActionProfile)
        action_profile.check_stateful_refs(symbols, objects, table = self.name)

def check_stateful_refs_P4ActionProfile(self, symbols, objects, table = None):
    for action_ref in self.action_spec:
        action = objects.get_object(action_ref.name, P4ActionFunction)
        action.check_stateful_refs(symbols, objects, table = table)

def check_stateful_refs_P4ActionFunction(self, symbols, objects, table = None):
    for call in self.action_body:
        call.check_stateful_refs(symbols, objects, table = table)

def check_stateful_refs_P4ActionCall(self, symbols, objects, table = None):
    for arg in self.arg_list:
        arg.check_stateful_refs(symbols, objects, table = table)

def check_stateful_refs_P4RefExpression(self, symbols, objects, table = None):
    obj_types = symbols.get_types(self.name)
    if not obj_types: return
    obj_types &= {Types.counter, Types.meter, Types.register}
    if not obj_types: return
    assert(len(obj_types) == 1)

    stateful_type = obj_types.pop()
    if stateful_type == Types.counter:
        stateful = objects.get_object(self.name, P4Counter)
    elif stateful_type == Types.meter:
        stateful = objects.get_object(self.name, P4Meter)
    elif stateful_type == Types.register:
        stateful = objects.get_object(self.name, P4Register)

    if not stateful.direct_or_static: return
    
    is_direct = stateful.direct_or_static[0] == "direct"
    is_static = stateful.direct_or_static[0] == "static"

    if stateful_type in {Types.meter, Types.counter} and is_direct:
        error_msg = "Error  in file %s at line %d:"\
                    " cannot reference direct counteror meter  %s in an action"\
                    % (self.filename, self.lineno, self.name)
        P4TreeNode.print_error(error_msg)
        return
    
    stateful_table = stateful.direct_or_static[1].name
    if is_static and table != stateful_table:
        error_msg = "Error  in file %s at line %d:"\
                    " static counter %s assigned to table %s" \
                    " cannot be referenced in an action called by table %s" \
                    % (self.filename, self.lineno, self.name, stateful_table, table)
        P4TreeNode.print_error(error_msg)
        return

def check_P4Program(self, symbols, header_fields, objects, types = None):
    import_header_fields(self.objects, header_fields)
    check_header_types(self.objects, header_fields)
    symbols.enterscope()
    import_objects(self.objects, symbols, objects)

    P4TreeNode.bbox_attribute_types = {}
    P4TreeNode.bbox_attribute_required = {}
    P4TreeNode.bbox_methods = {}
    self.find_bbox_attribute_types(P4TreeNode.bbox_attribute_types,
                                   P4TreeNode.bbox_attribute_required,
                                   P4TreeNode.bbox_methods)
    self.resolve_bbox_attributes(P4TreeNode.bbox_attribute_types)
    if self.get_errors_cnt() != 0:
        return

    P4TreeNode.bbox_attribute_locals = {}
    self.find_bbox_attribute_locals(P4TreeNode.bbox_attribute_locals)

    for obj in self.objects:
        obj.check(symbols, header_fields, objects)
    if self.get_errors_cnt() == 0:
        self.check_action_typing(symbols, objects)
    if self.get_errors_cnt() == 0:
        while True:
            removed = defaultdict(set)
            self.find_unused_args(removed)
            if not removed: break
            self.remove_unused_args(removed)
    if self.get_errors_cnt() == 0:
        self.check_stateful_refs(symbols, objects)
    if self.get_errors_cnt() == 0:
        table_actions = {}
        self.import_table_actions(objects, table_actions)
        self.check_apply_action_cases(table_actions)
    check_has_start_parse_state(symbols)
    symbols.exitscope()

    if self.get_errors_cnt() == 0:
        self.remove_unused(objects)

def check_P4BlackboxType(self, symbols, header_fields, objects, types = None):
    for member in self.members:
        member.check(symbols, header_fields, objects)

def check_P4TypeSpec(self, symbols, header_fields, objects, types = None):
    if self.name == "header" or self.name == "metadata":
        type_ = Types.header_type
        subtype = self.qualifiers["subtype"]
    elif self.name == "blackbox":
        type_ = Types.blackbox_type
        subtype = self.qualifiers["subtype"]
    else:
        return
    has_type = symbols.has_type(subtype, type_)
    if has_type: return
    error_msg = "Invalid reference to '%s' in file %s at line %d:"\
                " no %s with that name'"\
                % (subtype, self.filename, self.lineno, Types.get_name(type_))
    P4TreeNode.print_error(error_msg)

def check_P4BlackboxTypeAttributeProp(self, symbols, header_fields, objects, types = None):
    if self.name == "type":
        assert(isinstance(self.value, P4TypeSpec))
        self.value.check(symbols, header_fields, objects)

def check_P4BlackboxTypeAttribute(self, symbols, header_fields, objects, types = None):
    for prop in self.properties:
        prop.check(symbols, header_fields, objects)

def check_P4BlackboxTypeMethod(self, symbols, header_fields, objects, types = None):
    symbols.enterscope()
    for attr_name in P4TreeNode.bbox_attribute_types[self._bbox_type.name]:
        symbols.add_type(attr_name, Types.blackbox_attribute)
    for attr_access in self.attr_access:
        attr_access.check(symbols, header_fields, objects)
    symbols.exitscope()
    for param in self.param_list:
        # param is name, type_spec, qualifiers
        assert(isinstance(param[1], P4TypeSpec))
        param[1].check(symbols, header_fields, objects)

    has_optional = False
    for param in self.param_list:
        if "optional" in param[2]:
            has_optional = True
        elif has_optional:
            error_msg = "Error when declaring method '%s'"\
                        " for blackbox type '%s' in file %s at line %d:"\
                        " all parameters following first optional parameter"\
                        " must also be optional"\
                        % (self.name, self._bbox_type.name,
                           self.filename, self.lineno)

def check_P4BlackboxTypeMethodAccess(self, symbols, header_fields, objects, types = None):
    for attr in self.attrs:
        attr.check(symbols, header_fields, objects,
                   types = {Types.blackbox_attribute})

def check_P4BlackboxInstance(self, symbols, header_fields, objects, types = None):
    defined_attributes = set()
    for attr in self.attributes:
        attr._bbox_instance = self
        attr.check(symbols, header_fields, objects)
        defined_attributes.add(attr.name)

    bbox_type_name = self.blackbox_type
    missing_attributes = P4TreeNode.bbox_attribute_required[bbox_type_name] -\
                         defined_attributes
    for attr in missing_attributes:
        error_msg = "Error when declaring blackbox instance '%s'"\
                    " in file %s at line %d: attribute '%s' is required"\
                    " for blackbox instances of type '%s'"\
                    % (self.name, self.filename, self.lineno,
                       attr, bbox_type_name)
        P4TreeNode.print_error(error_msg)

def check_P4BlackboxInstanceAttribute(self, symbols, header_fields, objects, types = None):
    bbox_type = objects.get_object(self._bbox_instance.blackbox_type, P4BlackboxType)
    assert(bbox_type is not None)
    bbox_locals = P4TreeNode.bbox_attribute_locals[bbox_type.name]
    my_locals = bbox_locals[self.name]
    symbols.enterscope()
    for local in my_locals:
        symbols.add_type(local, Types.local)
    self.value.check(
        symbols, header_fields, objects,
        types={Types.field, Types.int_, Types.string_, Types.local}
    )
    symbols.exitscope()

def check_P4TypedRefExpression(self, symbols, header_fields, objects, types = None):
    type_ = Types.get_type(self.type_)
    # call P4RefExpression.check
    return super(P4TypedRefExpression, self).check(symbols, header_fields, objects, {type_})

def check_P4UserHeaderRefExpression(self, symbols, header_fields, objects, types = None):
    type_ = (Types.header_instance_regular, self.header_type)
    has_type = symbols.has_type(self.name, type_)
    if has_type: return
    error_msg = "Invalid reference to %s in file %s at line %d:"\
                " expected a reference to a header instance of type %s"\
                % (self.name, self.filename, self.lineno, self.header_type)
    P4TreeNode.print_error(error_msg)

def check_P4UserMetadataRefExpression(self, symbols, header_fields, objects, types = None):
    type_ = (Types.header_instance_metadata, self.header_type)
    
    has_type = symbols.has_type(self.name, type_)
    if has_type: return
    error_msg = "Invalid reference to %s in file %s at line %d:"\
                " expected a reference to a metadata instance of type %s"\
                % (self.name, self.filename, self.lineno, self.header_type)
    P4TreeNode.print_error(error_msg)

def check_P4UserBlackboxRefExpression(self, symbols, header_fields, objects, types = None):
    # TODO
    pass

def check_P4HeaderType(self, symbols, header_fields, objects, types = None):
    visited = set()
    stars = 0
    total_length = 0
    for field, width, atrributes in self.layout:
        if field in visited:
            error_msg = "Header type %s defined in file %s at line %d"\
                        " has 2 fields named %s"\
                        % (self.name, self.filename, self.lineno, field)
            P4TreeNode.print_error(error_msg)
            continue
        else:
            visited.add(field)

        if width == "*": stars += 1
        else: total_length += width.i

    if stars > 1:
        error_msg = "Header type %s defined in file %s at line %d"\
                    " has more than one field with width *"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    if stars and not self.length:
        error_msg = "Header type %s defined in file %s at line %d"\
                    " has a * field but no explicit header length"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    if self.length:
        length_symbols = SymbolTable()
        length_symbols.enterscope()
        for field, width, atrributes in self.layout:
            # TODO: this is not good enough
            if width != "*":
                length_symbols.add_type(field, Types.field)
        self.length.check(length_symbols, header_fields, objects, {Types.int_, Types.field})
        length_symbols.exitscope()

    if stars and not self.max_length:
        error_msg = "Header type %s defined in file %s at line %d"\
                    " has a * field but no explicit max header length"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    if self.max_length and 8 * self.max_length.i < total_length:
        error_msg = "Header type %s defined in file %s at line %d"\
                    " has an invalid max_length attribute"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

def check_P4HeaderInstance(self, symbols, header_fields, objects, types = None):
    pass

def check_P4HeaderInstanceRegular(self, symbols, header_fields, objects, types = None):
    # we already know that the header type is right
    pass

def check_P4HeaderInstanceMetadata(self, symbols, header_fields, objects, types = None):
    # we already know that the header type is right
    for field, value in self.initializer:
        if field not in header_fields[self.header_type]:
            error_msg = "Invalid reference to field %s"\
                        " in initializer for metadata header %s"\
                        " in file %s at line %d:"\
                        " header type %s has no field %s"\
                        % (field, self.name, self.filename, self.lineno, field)
            P4TreeNode.print_error(error_msg)

def check_P4FieldList(self, symbols, header_fields, objects, types = None):
    for entry in self.entries:
        entry.check(symbols, header_fields, objects,
                    {Types.header_instance,
                     Types.field,
                     Types.field_list,
                     Types.int_,
                     Types.string_}) # payload
    self.detect_recursion_field_list(objects, self.name)
                               
def check_P4FieldListCalculation(self, symbols, header_fields, objects, types = None):
    for entry in self.input_list:
        entry.check(symbols, header_fields, objects, {Types.field_list})

def detect_recursion_field_list_P4FieldList(self, objects, field_list):
    for entry in self.entries:
        if entry.detect_recursion_field_list(objects, field_list):
            return True
    return False

def detect_recursion_field_list_P4Expression(self, objects, field_list):
    return False

def detect_recursion_field_list_P4RefExpression(self, objects, field_list):
    obj = objects.get_object(self.name, P4FieldList)
    if not obj: return False
    if self.name == field_list:
        error_msg = "Detected recursive reference to field list %s"\
                    " in file %s at line %d:"\
                    % (field_list, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return True
    return obj.detect_recursion_field_list(objects, field_list)

def check_P4CalculatedField(self, symbols, header_fields, objects, types = None):
    self.field_ref.check(symbols, header_fields, objects, {Types.field})
    for update_verify_spec in self.update_verify_list:
        update_verify_spec.check(symbols, header_fields, objects)
    if self._pragmas:
        error_msg = "Compiler pragmas have been attached to calculated field %s"\
                    " in file %s at line %d, they will be discarded"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_warning(error_msg)

def check_P4UpdateVerify(self, symbols, header_fields, objects, types = None):
    self.field_list_calculation.check(symbols, header_fields, objects,
                                      {Types.field_list_calculation})
    if self.if_cond:
        self.if_cond.check(symbols, header_fields, objects)

def check_P4ValueSet(self, symbols, header_fields, objects, types = None):
    # nothing to do ... for now
    pass

def check_P4Counter(self, symbols, header_fields, objects, types = None):
    has_direct = self.direct_or_static is not None and self.direct_or_static[0] == "direct"
    if not has_direct and self.instance_count is None:
        error_msg = "Error in counter %s defined in file %s at line %d:"\
                    " counter must be either direct-mapped or given an instance count"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
    if has_direct and self.instance_count is not None:
        error_msg = "Error in counter %s defined in file %s at line %d:"\
                    " counter cannot be direct-mapped and have an instance count"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    if self.direct_or_static is not None:
        _, table = self.direct_or_static
        table.check(symbols, header_fields, objects, {Types.table})

def check_P4Meter(self, symbols, header_fields, objects, types = None):
    if self.direct_or_static is not None:
        _, table = self.direct_or_static
        table.check(symbols, header_fields, objects, {Types.table})
    if self.result is not None:
        self.result.check(symbols, header_fields, objects, {Types.field})

def check_P4Register(self, symbols, header_fields, objects, types = None):
    has_direct = self.direct_or_static is not None and self.direct_or_static[0] == "direct"
    if not has_direct and self.instance_count is None:
        error_msg = "Error in register %s defined in file %s at line %d:"\
                    " register must be either direct-mapped or given an instance count"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
    if has_direct and self.instance_count is not None:
        error_msg = "Error in register %s defined in file %s at line %d:"\
                    " register cannot be direct-mapped and have an instance count"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    if self.direct_or_static is not None:
        _, table = self.direct_or_static
        table.check(symbols, header_fields, objects, {Types.table})

    if self.width and self.layout:
        error_msg = "Error in register %s defined in file %s at line %d:"\
                    " register cannot have both a width and a layout"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    if self.width:
        self.width.check(symbols, header_fields, objects,
                         {Types.int_, Types.header_type})
    if self.layout:
        self.layout.check(symbols, header_fields, objects,
                          {Types.int_, Types.header_type})


def check_P4PrimitiveAction(self, symbols, header_fields, objects, types = None):
    # assume formals, optional and types have same length at this point
    has_optional = False
    for opt in self.optional:
        if opt: has_optional = True
        elif has_optional:
            error_msg = "Error in action %s defined in file %s at line %d:"\
                        " all parameters following an optional parameter"\
                        " must be optional as well"\
                        % (self.name, self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)

# in this first pass, we just check the name and number of args, will flatten
# afterwards
def check_P4ActionFunction(self, symbols, header_fields, objects, types = None):
    # check for duplicates
    param_set = set()
    for p in self.formals:
        if p in param_set:
            error_msg = "Duplicate parameter %s for action %s"\
                        " defined in file %s at line %d"\
                        % (p, self.name, self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)
        param_set.add(p)

    symbols.enterscope()
    for formal in self.formals:
        symbols.add_type(formal, Types.int_)
    for call in self.action_body:
        call.check(symbols, header_fields, objects)
    symbols.exitscope()

    if self.detect_recursion(objects, self.name):
        error_msg = "Action function %s defined in file %s at line %d"\
                    " is called recursively"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

def check_P4ActionCall(self, symbols, header_fields, objects, types = None):
    if not self.action.check(symbols, header_fields, objects,
                             {Types.action_function,
                              Types.primitive_action}):
        return
    action = objects.get_object(self.action.name, P4Action)
                                          
    num_formals = len(action.formals)
    num_args = len(self.arg_list)
    required = action.required_args
    if num_formals == required and num_formals != num_args:
        error_msg = "Action %s expected %d arguments but got %d"\
                    " in file %s at line %d"\
                    % (self.action.name, num_formals, num_args,
                       self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
    elif num_args < required:
        error_msg = "Action %s expected at least %d arguments but only got %d"\
                    " in file %s at line %d"\
                    % (self.action.name, num_formals, num_args,
                       self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
    elif num_args > num_formals:
        error_msg = "Action %s can only accept %d arguments but got %d"\
                    " in file %s at line %d"\
                    % (self.action.name, num_formals, num_args,
                       self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

    for arg in self.arg_list:
        arg.check(
            symbols, header_fields, objects,
            # TODO: can this be improved
            # this is a list of all the types that can be accepted by an action
            # we have a more refined type checking later
            {
                Types.int_, Types.field, Types.header_instance,
                Types.field_list, Types.field_list_calculation,
                Types.counter, Types.meter, Types.register
            }
        )

def check_P4BlackboxMethodCall(self, symbols, header_fields, objects, types = None):
    if not self.blackbox_instance.check(symbols, header_fields, objects,
                                        {Types.blackbox_instance}):
        return
    bbox_instance = objects.get_object(self.blackbox_instance.name, P4BlackboxInstance)
    assert(bbox_instance is not None)
    bbox_type = objects.get_object(bbox_instance.blackbox_type, P4BlackboxType)
    assert(bbox_type is not None)

    if self.method not in P4TreeNode.bbox_methods[bbox_type.name]:
        error_msg = "Invalid call to method '%s' on blackbox instance '%s'"\
                    " in file %s at line %d:"\
                    " this is not a valid method for blackbox type '%s'"\
                    % (self.method, self.blackbox_instance.name,
                       self.filename, self.lineno, bbox_type.name)
        P4TreeNode.print_error(error_msg)
        return
    method = P4TreeNode.bbox_methods[bbox_type.name][self.method]

    num_params = len(method.param_list)
    num_args = len(self.arg_list)
    required = num_params
    for param in method.param_list:
        if "optional" in param[2]:
            required -= 1

    if num_params == required and num_params != num_args:
        error_msg = "Blackbox method '%s' expected %d arguments but got %d"\
                    " in file %s at line %d"\
                    % (self.method, num_params, num_args,
                       self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
    elif num_args < required:
        error_msg = "Blackbox method '%s' expected at least %d arguments but only got %d"\
                    " in file %s at line %d"\
                    % (self.method, num_params, num_args,
                       self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
    elif num_args > num_params:
        error_msg = "Blackbox method '%s' can only accept %d arguments but got %d"\
                    " in file %s at line %d"\
                    % (self.method, num_params, num_args,
                       self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

def check_P4Table(self, symbols, header_fields, objects, types = None):
    if self.size is None and self.min_size is not None and self.max_size is not None:
        if self.max_size.i < self.min_size.i:
            error_msg = "In the definition of table %s in file %s at line %d:"\
                        " max_size cannot be smaller than min_size"\
                        % (self.name, self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)

    # TODO: size and others defined

    # TODO: more checks
    
    for field_match in self.reads:
        field_match.check(symbols, header_fields, objects)

    if self.action_spec:
        for action_and_next in self.action_spec:
            action_and_next.check(symbols, header_fields, objects,
                                  {Types.action_function})

    if self.action_profile:
        self.action_profile.check(symbols, header_fields, objects,
                                  {Types.action_profile})        

def check_P4TableFieldMatch(self, symbols, header_fields, objects, types = None):
    field = self.field_or_masked[0]
    if self.match_type in {"exact", "ternary", "range", "lpm"}:
        field.check(symbols, header_fields, objects, {Types.field})
    elif self.match_type in {"valid"}:
        field.check(symbols, header_fields, objects,
                    {Types.header_instance, Types.field})
    else:
        error_msg = "Unknown match type %s in file %s at line %d"\
                    % (self.match_type, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

def check_P4ActionProfile(self, symbols, header_fields, objects, types = None):
    for action_and_next in self.action_spec:
        action_and_next.check(symbols, header_fields, objects,
                              {Types.action_function})

    if self.selector:
        self.selector.check(symbols, header_fields, objects,
                            {Types.action_selector})

def check_P4ActionSelector(self, symbols, header_fields, objects, types = None):
    self.selection_key.check(symbols, header_fields, objects,
                             {Types.field_list_calculation})
        

# TODO: prevent recursive calls, call to ingress & egress, call the same
# function twice 
def check_P4ControlFunction(self, symbols, header_fields, objects, types = None):
    for statement in self.statements:
        statement.check(symbols, header_fields, objects)

def check_P4ControlFunctionStatement(self, symbols, header_fields, objects, types = None):
    pass

def check_P4ControlFunctionApply(self, symbols, header_fields, objects, types = None):
    self.table.check(symbols, header_fields, objects, {Types.table})

def check_P4ControlFunctionApplyAndSelect(self, symbols, header_fields, objects, types = None):
    self.table.check(symbols, header_fields, objects, {Types.table})
    hit_miss_case = False
    action_case = False
    for apply_case in self.case_list:
        if isinstance(apply_case, P4ControlFunctionApplyActionCase):
            action_case = True
        elif isinstance(apply_case, P4ControlFunctionApplyActionDefaultCase):
            action_case = True
        elif isinstance(apply_case, P4ControlFunctionApplyHitMissCase):
            hit_miss_case = True
        else:
            assert(False)
        apply_case.check(symbols, header_fields, objects)

    if action_case and hit_miss_case:
        error_msg = "Error in apply_table select block"\
                    " in file %s at line %d:"\
                    " cannot mix hit-miss cases and action cases"\
                    % (self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)

def check_P4ControlFunctionApplyActionCase(self, symbols, header_fields, objects, types = None):
    for action in self.action_list:
        action.check(symbols, header_fields, objects, {Types.action_function})
    for statement in self.statements:
        statement.check(symbols, header_fields, objects)

def check_P4ControlFunctionApplyActionDefaultCase(self, symbols, header_fields, objects, types = None):
    for statement in self.statements:
        statement.check(symbols, header_fields, objects)

def check_P4ControlFunctionApplyHitMissCase(self, symbols, header_fields, objects, types = None):
    for statement in self.statements:
        statement.check(symbols, header_fields, objects)

def check_P4ControlFunctionIfElse(self, symbols, header_fields, objects, types = None):
    self.cond.check(symbols, header_fields, objects)
    for statement in self.if_body:
        statement.check(symbols, header_fields, objects)
    for statement in self.else_body:
        statement.check(symbols, header_fields, objects)

def check_P4ControlFunctionCall(self, symbols, header_fields, objects, types = None):
    self.name.check(symbols, header_fields, objects, {Types.control_function})

def check_P4RefExpression(self, symbols, header_fields, objects, types = None):
    obj_types = symbols.get_types(self.name)
    if not obj_types:
        error_msg = "Invalid reference to %s in file %s at line %d:"\
                    " object was not defined"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return False
    elif not (obj_types & types):
        error_msg = "Invalid reference to %s in file %s at line %d:"\
                    " invalid type for object, expected one of {%s}"\
                    " but got %s"\
                    % (self.name, self.filename, self.lineno,
                       get_types_set_str(types), get_types_set_str(obj_types))
        P4TreeNode.print_error(error_msg)
        return False
    elif len(obj_types & types) > 1:
        error_msg = "Invalid reference to %s in file %s at line %d:"\
                    " more than one matching object with type %s"\
                    % (self.name, self.filename, self.lineno, get_types_set_str(types))
        P4TreeNode.print_error(error_msg)
        return False
    type_ = (obj_types & types).pop()
    # this is super cheap, I need to improve handling of tag stack references
    if type_ == Types.header_instance:
        header_instance = objects.get_object(self.name, P4HeaderInstanceRegular)
        if header_instance and header_instance.size:
            # dirty hack. We remove the error message and mark the ref with the
            # "_array_ref" attribute. When this attribute is present, the P4
            # dumper will replace the stack reference by an instance reference
            # (the instance at index 0). This is to make push() and pop() work
            # quickly 
            self._array_ref = True
        #     error_msg = "Invalid reference to header instance %s"\
        #                 " in file %s at line %d:"\
        #                 " header instance is a tag stack but reference"\
        #                 " does not specify an index"\
        #                 % (self.name, self.filename, self.lineno)
        #     P4TreeNode.print_error(error_msg)
        #     return False
    return True

last_extracted = None

def check_P4FieldRefExpression(self, symbols, header_fields, objects, types = None):
    # TODO
    global last_extracted
    assert (Types.field in types)
    if type(self.header_ref) is str:
        assert(self.header_ref == "latest")
        header = last_extracted
        if not header:
            error_msg = "Invalid reference to latest in file %s at line %d:"\
                        " no headers were extracted in this parser function"\
                        % (self.filename, self.lineno)
            P4TreeNode.print_error(error_msg)
            return False
        header_ref = objects.get_object(last_extracted, P4HeaderInstance)
        header_type = objects.get_object(header_ref.header_type, P4HeaderType)
    else:
        if not self.header_ref.check(symbols, header_fields, objects,
                                     {Types.header_instance}):
            return False
        
        header_ref = objects.get_object(self.header_ref.name, P4HeaderInstance)
        header_type = objects.get_object(header_ref.header_type, P4HeaderType)

    if self.field not in header_fields[header_type.name]:
        error_msg = "Invalid reference to field %s in file %s at line %d:"\
                    " header type %s has no field %s"\
                    % (self.field, self.filename, self.lineno,
                       header_type.name, self.field)
        P4TreeNode.print_error(error_msg)
        return False
    return True

def check_P4HeaderRefExpression(self, symbols, header_fields, objects, types = None):
    # TODO: improve
    is_header_instance = symbols.has_type(self.name, Types.header_instance)
    if not is_header_instance:
        error_msg = "Invalid reference to header instance %s"\
                    " in file %s at line %d:"\
                    " no header instance with this name was declared"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return False
    header_instance = objects.get_object(self.name, P4HeaderInstance)
    if self.idx and not header_instance.size:
        error_msg = "Invalid reference to header instance %s"\
                    " in file %s at line %d:"\
                    " header instance is not a tag stack"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return False
    elif self.idx and\
            type(self.idx) is P4Integer and self.idx.i >= header_instance.size.i:
        error_msg = "Invalid reference to header instance %s"\
                    " in file %s at line %d:"\
                    " index accessed is larger than size"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return False
    return True

def check_P4String(self, symbols, header_fields, objects, types = None):
    assert(Types.string_ in types)
    pass

def check_P4Integer(self, symbols, header_fields, objects, types = None):
    assert(Types.int_ in types)
    pass

def check_P4Bool(self, symbols, header_fields, objects, types = None):
    assert(Types.bool_ in types)
    pass

def check_P4ParserFunction(self, symbols, header_fields, objects, types = None):
    global last_extracted
    last_extracted = None
    for statement in self.extract_and_set_statements:
        statement.check(symbols, header_fields, objects)
    self.return_statement.check(symbols, header_fields, objects)

def check_P4ParserExtract(self, symbols, header_fields, objects, types = None):
    global last_extracted
    self.header_ref.check(symbols, header_fields, objects,
                          {Types.header_instance})
    last_extracted = self.header_ref.name

def check_P4ParserSetMetadata(self, symbols, header_fields, objects, types = None):
    self.field_ref.check(symbols, header_fields, objects, {Types.field})
    self.expr.check(symbols, header_fields, objects, {Types.int_, Types.field})

def check_P4ParserImmediateReturn(self, symbols, header_fields, objects, types = None):
    self.name.check(symbols, header_fields, objects,
                    {Types.parser_function, Types.control_function})

def check_P4ParserSelectReturn(self, symbols, header_fields, objects, types = None):
    for field in self.select:
        field.check(symbols, header_fields, objects, {Types.field, Types.int_})
    for case in self.cases:
        case.check(symbols, header_fields, objects)

def check_P4ParserSelectCase(self, symbols, header_fields, objects, types = None):
    for value_and_mask in self.values:
        value_and_mask[0].check(symbols, header_fields, objects,
                                {Types.int_, Types.value_set})
    self.return_.check(symbols, header_fields, objects,
                       {Types.parser_function, Types.control_function})

# enforce only one default per select ?
def check_P4ParserSelectDefaultCase(self, symbols, header_fields, objects, types = None):
    self.return_.check(symbols, header_fields, objects,
                       {Types.parser_function, Types.control_function})

def check_P4ParserParseError(self, symbols, header_fields, objects, types = None):
    self.parse_error.check(symbols, header_fields, objects,
                           {Types.parser_exception})

def check_P4CurrentExpression(self, symbols, header_fields, objects, types = None):
    pass

def check_P4BoolBinaryExpression(self, symbols, header_fields, objects, types = None):
    self.left.check(symbols, header_fields, objects, {Types.bool_})
    self.right.check(symbols, header_fields, objects, {Types.bool_})

def check_P4BoolUnaryExpression(self, symbols, header_fields, objects, types = None):
    self.right.check(symbols, header_fields, objects, {Types.bool_})

def check_P4ValidExpression(self, symbols, header_fields, objects, types = None):
    self.header_ref.check(symbols, header_fields, objects, {Types.header_instance})

def check_P4BinaryExpression(self, symbols, header_fields, objects, types = None):
    self.left.check(symbols, header_fields, objects,
                    {Types.field, Types.int_, Types.local})
    self.right.check(symbols, header_fields, objects,
                     {Types.field, Types.int_, Types.local})

def check_P4UnaryExpression(self, symbols, header_fields, objects, types = None):
    self.right.check(symbols, header_fields, objects,
                     {Types.field, Types.int_, Types.local})


def check_P4ParserException(self, symbols, header_fields, objects, types = None):
    for set_statement in self.set_statements:
        set_statement.check(symbols, header_fields, objects)
    self.return_or_drop.check(symbols, header_fields, objects)
        
def check_P4ParserExceptionDrop(self, symbols, header_fields, objects, types = None):
    pass

def check_P4ParserExceptionReturn(self, symbols, header_fields, objects, types = None):
    self.control_function.check(symbols, header_fields, objects, {Types.control_function})
