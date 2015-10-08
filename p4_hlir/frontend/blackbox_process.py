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
from parser import P4Parser

def find_bbox_attribute_types_P4TreeNode(self, bbox_attribute_types):
    pass

def find_bbox_attribute_types_P4BlackboxTypeAttribute(self, bbox_attribute_types):
    if self.name in bbox_attribute_types:
        error_msg = "Redefinition of blackbox attribute '%s'"\
                    " in file %s at line %d"\
                    % (self.name, self.filename, self.lineno)
        P4TreeNode.print_error(error_msg)
        return
    properties = {}
    for prop in self.properties:
        if prop.name in properties:
            error_msg = "Redefinition of property '%s'"\
                        " for blackbox attribute '%s' in file %s at line %d"\
                        % (prop.name, self.name, prop.filename, prop.lineno)
            P4TreeNode.print_error(error_msg)
            return
        properties[prop.name] = prop
        prop._bbox_type_attr = self

    if "type" not in properties:
        error_msg = "Blackbox attribute '%s' defined in file %s at line %d"\
                    " has no 'type' property"\
                    % (self.name, prop.filename, prop.lineno)
        P4TreeNode.print_error(error_msg)
        return

    bbox_attribute_types[self.name] = properties["type"].value

def find_bbox_attribute_types_P4BlackboxType(self, bbox_attribute_types):
    assert(self.name not in bbox_attribute_types)
    bbox_attribute_types[self.name] = {}
    attr_types = bbox_attribute_types[self.name]
    for member in self.members:
        member.find_bbox_attribute_types(attr_types)
        member._bbox_type = self

P4TreeNode.find_bbox_attribute_types = find_bbox_attribute_types_P4TreeNode
P4BlackboxType.find_bbox_attribute_types = find_bbox_attribute_types_P4BlackboxType
P4BlackboxTypeAttribute.find_bbox_attribute_types = find_bbox_attribute_types_P4BlackboxTypeAttribute

def find_bbox_attribute_types_P4Program(self, bbox_attribute_types):
    for obj in self.objects:
        obj.find_bbox_attribute_types(bbox_attribute_types)

P4Program.find_bbox_attribute_types = find_bbox_attribute_types_P4Program


def resolve_bbox_attributes_P4TreeNode(self, bbox_attribute_types):
    pass

def resolve_bbox_attribute(self, type_spec):
    attr_type = type_spec.name
    attr_type_qualifiers = type_spec.qualifiers

    def resolve_expression(attr):
        if attr.lineno != None:
            value = ("#line %i\n" % attr.lineno) + attr.value
        p4_objects, errors_cnt = P4Parser(
            start='general_exp', silent=True
        ).parse(value, filename=attr.filename)
        if errors_cnt > 0:
            error_msg = "Error in file %s at line %d:"\
                        " invalid syntax for attribute '%s' of type expression"\
                        % (attr.filename, attr.lineno, attr.name)
            P4TreeNode.print_error(error_msg)
            return None
        assert(type(p4_objects) is P4BinaryExpression)
        return p4_objects

    def resolve_bitstring(attr):
        try:
            # TODO: use parser instead?
            # Is is wise to allow integer constants here?
            ast_int = P4Integer(attr.filename, attr.lineno, int(attr.value, 0))
            error_msg = "In file %s at line %d:"\
                        " Prefer type 'int' to 'bit<>' for integer constants"\
                        % (attr.filename, attr.lineno)
            P4TreeNode.print_warning(error_msg)
            return ast_int
        except:
            pass

        if attr.lineno != None:
            value = ("#line %i\n" % attr.lineno) + attr.value
        p4_objects, errors_cnt = P4Parser(
            start='field_ref', silent=True
        ).parse(value, filename=attr.filename)
        if errors_cnt > 0:
            error_msg = "Error in file %s at line %d:"\
                        " invalid syntax for attribute '%s' of type %s"\
                        % (attr.filename, attr.lineno, attr.name, attr_type)
            P4TreeNode.print_error(error_msg)
            return None
        assert(type(p4_objects) is P4FieldRefExpression)
        return p4_objects

    new_attr_value = None
    if attr_type == "string":
        new_attr_value = P4String(self.filename, self.lineno, self.value)
    elif attr_type == "block":
        new_attr_value = P4String(self.filename, self.lineno, self.value)
    elif attr_type == "int":
        new_attr_value = P4Integer(self.filename, self.lineno, int(self.value, 0))
    elif attr_type == "expression":
        new_attr_value = resolve_expression(self)
    elif attr_type == "bit" or attr_type == "varbit":
        new_attr_value = resolve_bitstring(self)
    elif attr_type == "header":
        subtype = attr_type_qualifiers["subtype"]
        new_attr_value = P4UserHeaderRefExpression(self.filename, self.lineno,
                                                   self.value.strip(), subtype)
    elif attr_type == "metadata":
        subtype = attr_type_qualifiers["subtype"]
        new_attr_value = P4UserMetadataRefExpression(self.filename, self.lineno,
                                                     self.value.strip(), subtype)
    elif attr_type == "blackbox":
        subtype = attr_type_qualifiers["subtype"]
        new_attr_value = P4UserBlackboxRefExpression(self.filename, self.lineno,
                                                     self.value.strip(), subtype)
    else:
        new_attr_value = P4TypedRefExpression(self.filename, self.lineno,
                                              self.value.strip(), attr_type)

    if new_attr_value is None:
        return None
    self.value = new_attr_value
    return self

P4BlackboxInstanceAttribute.resolve_bbox_attribute = resolve_bbox_attribute

def resolve_bbox_attributes_P4BlackboxInstance(self, bbox_attribute_types):
    bbox_type = self.blackbox_type
    if bbox_type not in bbox_attribute_types:
        error_msg = "Error in file %s at line %d when declaring"\
                    " blackbox instance '%s': '%s' does not refer"\
                    " to a valid blackbox type"\
                    % (self.filename, self.lineno, self.name, bbox_type)
        P4TreeNode.print_error(error_msg)
        return

    attr_types = bbox_attribute_types[bbox_type]
    new_attributes = []
    for attr in self.attributes:

        if attr.name not in attr_types:
            error_msg = "Error in file %s at line %d when declaring"\
                        " blackbox instance '%s': '%s' is not a"\
                        " to a valid attribute for blackbox type %s"\
                        % (attr.filename, attr.lineno,
                           self.name, attr.name, bbox_type)
            P4TreeNode.print_error(error_msg)
            continue

        new_attr = attr.resolve_bbox_attribute(attr_types[attr.name])
        if new_attr is None:
            continue
        new_attributes.append(new_attr)

    self.attributes = new_attributes


P4TreeNode.resolve_bbox_attributes = resolve_bbox_attributes_P4TreeNode
P4BlackboxInstance.resolve_bbox_attributes = resolve_bbox_attributes_P4BlackboxInstance

def resolve_bbox_attributes_P4Program(self, bbox_attribute_types):
    for obj in self.objects:
        obj.resolve_bbox_attributes(bbox_attribute_types)

P4Program.resolve_bbox_attributes = resolve_bbox_attributes_P4Program

def find_bbox_attribute_locals_P4BlackboxType(self, bbox_attr_locals):
    assert(self.name not in bbox_attr_locals)
    bbox_attr_locals[self.name] = {}
    for member in self.members:
        member.find_bbox_attribute_locals(bbox_attr_locals[self.name])

def find_bbox_attribute_locals_P4BlackboxTypeAttribute(self, bbox_attr_locals):
    assert(self.name not in bbox_attr_locals)
    bbox_attr_locals[self.name] = []
    for prop in self.properties:
        prop.find_bbox_attribute_locals(bbox_attr_locals[self.name])

def find_bbox_attribute_locals_P4BlackboxTypeMethod(self, bbox_attr_locals):
    pass

def find_bbox_attribute_locals_P4BlackboxTypeAttributeProp(self, bbox_attr_locals):
    if self.name == "locals":
        assert(type(self.value) is list)
        for local in self.value:
            local.find_bbox_attribute_locals(bbox_attr_locals)

def find_bbox_attribute_locals_P4RefExpression(self, bbox_attr_locals):
    bbox_attr_locals.append(self.name)

def find_bbox_attribute_locals_P4TreeNode(self, bbox_attr_locals):
    pass

def find_bbox_attribute_locals_P4Program(self, bbox_attr_locals):
    for obj in self.objects:
        obj.find_bbox_attribute_locals(bbox_attr_locals)

P4BlackboxType.find_bbox_attribute_locals = find_bbox_attribute_locals_P4BlackboxType
P4BlackboxTypeAttribute.find_bbox_attribute_locals = find_bbox_attribute_locals_P4BlackboxTypeAttribute
P4BlackboxTypeMethod.find_bbox_attribute_locals = find_bbox_attribute_locals_P4BlackboxTypeMethod
P4BlackboxTypeAttributeProp.find_bbox_attribute_locals = find_bbox_attribute_locals_P4BlackboxTypeAttributeProp
P4RefExpression.find_bbox_attribute_locals = find_bbox_attribute_locals_P4RefExpression
P4TreeNode.find_bbox_attribute_locals = find_bbox_attribute_locals_P4TreeNode
P4Program.find_bbox_attribute_locals = find_bbox_attribute_locals_P4Program
