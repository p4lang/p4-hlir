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

def find_bbox_attribute_types_P4BlackboxType(self, bbox_attribute_types):
    assert(self.name not in bbox_attribute_types)
    attr_types = {}
    for member in self.members:
        if member[0] != "attribute":
            continue
        attr_name = member[1]
        if attr_name in attr_types:
            # TODO
            pass
        for prop in member[2]:
            # TODO: better check
            if prop[0] != "type":
                continue
            type_name = prop[1].name
            attr_types[attr_name] = prop[1]

    bbox_attribute_types[self.name] = attr_types

P4TreeNode.find_bbox_attribute_types = find_bbox_attribute_types_P4TreeNode
P4BlackboxType.find_bbox_attribute_types = find_bbox_attribute_types_P4BlackboxType

def find_bbox_attribute_types_P4Program(self, bbox_attribute_types):
    for obj in self.objects:
        obj.find_bbox_attribute_types(bbox_attribute_types)

P4Program.find_bbox_attribute_types = find_bbox_attribute_types_P4Program


def resolve_bbox_attributes_P4TreeNode(self, bbox_attribute_types):
    pass

def resolve_bbox_attributes_P4BlackboxInstance(self, bbox_attribute_types):
    bbox_type = self.blackbox_type
    assert(bbox_type in bbox_attribute_types) # TODO
    attr_types = bbox_attribute_types[bbox_type]
    for idx, (attr_name, attr_value ) in enumerate(self.attributes):
        attr_type = attr_types[attr_name].name
        attr_type_qualifiers = attr_types[attr_name].qualifiers
        
        if attr_type == "string":
            attr_value = P4String(self.filename, self.lineno, attr_value)
            self.attributes[idx] = (attr_name, attr_value)
        elif attr_type == "block":
            assert(0)
            pass # TODO
        elif attr_type == "int":
            attr_value = P4Integer(self.filename, self.lineno, int(attr_value, 0))
            self.attributes[idx] = (attr_name, attr_value)
        elif attr_type == "expression":
            if self.lineno != None:
                value = ("#line %i\n" % self.lineno) + attr_value
            p4_objects, errors_cnt = P4Parser(
                start='general_exp',
                silent=True
            ).parse(
                value,
                filename=self.filename
            )
            if errors_cnt > 0:
                assert(0)
            assert(type(p4_objects) is P4BinaryExpression)
            self.attributes[idx] = (attr_name, p4_objects)
        elif attr_type == "bit" or attr_type == "varbit":
            # is that what I want to do?
            if self.lineno != None:
                value = ("#line %i\n" % self.lineno) + attr_value
            p4_objects, errors_cnt = P4Parser(
                start='field_ref',
                silent=True
            ).parse(
                value,
                filename=self.filename
            )
            if errors_cnt > 0:
                assert(0)
            assert(type(p4_objects) is P4FieldRefExpression)
            self.attributes[idx] = (attr_name, p4_objects)
        elif attr_type == "header":
            subtype = attr_type_qualifiers["subtype"]
            attr_value = P4UserHeaderRefExpression(self.filename, self.lineno,
                                                   attr_value.strip(), subtype)
            self.attributes[idx] = (attr_name, attr_value)
        elif attr_type == "metadata":
            subtype = attr_type_qualifiers["subtype"]
            attr_value = P4UserMetadataRefExpression(self.filename, self.lineno,
                                                     attr_value.strip(), subtype)
            self.attributes[idx] = (attr_name, attr_value)
        elif attr_type == "blackbox":
            subtype = attr_type_qualifiers["subtype"]
            attr_value = P4UserBlackboxRefExpression(self.filename, self.lineno,
                                                     attr_value.strip(), subtype)
            self.attributes[idx] = (attr_name, attr_value)
        else:
            attr_value = P4TypedRefExpression(self.filename, self.lineno,
                                              attr_value.strip(), attr_type)
            self.attributes[idx] = (attr_name, attr_value)
            

P4TreeNode.resolve_bbox_attributes = resolve_bbox_attributes_P4TreeNode
P4BlackboxInstance.resolve_bbox_attributes = resolve_bbox_attributes_P4BlackboxInstance

def resolve_bbox_attributes_P4Program(self, bbox_attribute_types):
    for obj in self.objects:
        obj.resolve_bbox_attributes(bbox_attribute_types)

P4Program.resolve_bbox_attributes = resolve_bbox_attributes_P4Program
