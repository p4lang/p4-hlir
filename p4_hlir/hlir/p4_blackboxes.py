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

from p4_core import *
from p4_sized_integer import p4_sized_integer
from p4_headers import p4_field
from p4_imperatives import p4_table_entry_data, p4_action, p4_signature_ref

from p4_hlir.util.OrderedSet import OrderedSet
from collections import OrderedDict, defaultdict

class p4_attribute (object):
    def __init__ (self, name, parent, optional=False, value_type=None, expr_locals=None):
        self.name = name
        self.parent = parent
        self.optional = optional
        self.value_type = value_type
        self.expr_locals = expr_locals

    def __str__(self):
        return self.parent.name + "." + self.name

class p4_method (p4_action):
    def __init__ (self, hlir, name, parent, params=None, instantiated=False):
        self.name = name
        self.parent = parent

        self.params = params

        self.signature = []
        self.signature_widths = []

        self.call_sequence = []
        self.flat_call_sequence = []

        self.signature_flags = OrderedDict()

        if instantiated:
            hlir.p4_actions[self.parent.name+"."+self.name] = self

        self._pragmas = OrderedSet()

    def validate_arguments(self, hlir, args):
        if self.required_params <= len(args) <= len(self.signature):
            for arg_idx, arg in enumerate(args):
                param_name = self.signature[arg_idx]
                param_types = self.signature_flags[self.signature[arg_idx]]["type"]
                if type(arg) not in param_types:
                    expected_type=", ".join(t.__name__ for t in param_types)
                    if len(param_types) == 1:
                        expected_type = "type "+expected_type
                    else:
                        expected_type = "types {"+expected_type+"}"
                    raise p4_compiler_msg(
                        "Incorrect type for method '%s' parameter '%s'  (got %s, expected %s)" % (
                            str(self), param_name, type(arg).__name__, expected_type
                        )
                    )
        else:
            if self.required_params == len(self.signature):
                req_param_str = str(self.required_params)
            else:
                req_param_str = "between "+str(self.required_params)+" and "+str(len(self.signature))
            raise p4_compiler_msg(
                "Incorrect number of arguments passed to '"+str(self)+"' (got %i, expected %s)" % (len(call_args), req_param_str),
            )

    def build(self, hlir):
        self.required_params = len(self.params)

        optional_params = False
        for param in self.params:
            if "optional" in param[2]:
                optional_params = True
                self.required_params -= 1
            else:
                if optional_params:
                    raise p4_compiler_msg(
                        "In method '%s', all parameters following first "
                        "optional parameter must also be optional" % str(self),
                        self.parent.filename, self.parent.lineno
                    )

        for param in self.params:
            self.signature.append(param[0])
            self.signature_widths.append(None)

            flags = OrderedDict()

            flags["type"] = OrderedSet()
            param_type = hlir._type_spec_to_hlir(param[1])
            flags["type"].add(param_type)

            # TODO: we don't always want to allow numeric data to be definable
            #       by the control plane - find a way to distinguish
            if param_type is p4_field or param_type is int:
                flags["type"].add(p4_table_entry_data)

            if "in" in param[2]:
                flags["direction"] = P4_READ
            elif "out" in param[2]:
                flags["direction"] = P4_WRITE
            else:
                flags["direction"] = P4_READ_WRITE

            if "optional" in param[2]:
                flags["optional"] = True

            self.signature_flags[param[0]] = flags

    def __str__(self):
        return self.parent.name + "." + self.name + "()"

class p4_blackbox_type (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "attributes", "methods"]
    allowed_attributes = required_attributes + ["doc"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)

        if not self.valid_obj:
            return

        # Process attributes
        self.required_attributes = OrderedSet()
        attribute_dict = OrderedDict()
        for attribute in self.attributes:
            if attribute[0] in attribute_dict:
                raise p4_compiler_msg (
                    "Blackbox attribute '"+str(attr)+"' defined multiple times within blackbox type.",
                    self.filename, self.lineno
                )
            else:
                attr = p4_attribute(name=attribute[0], parent=self)

                specified_props = set()
                for prop in attribute[1]:
                    if prop[0] in specified_props:
                        raise p4_compiler_msg (
                            "Blackbox attribute '"+str(attr)+"' specifies property '"+prop[0]+"' multiple times within blackbox type.",
                            self.filename, self.lineno
                        )
                    else:
                        specified_props.add(prop[0])
                        if prop[0] == "optional":
                            attr.optional = True
                        elif prop[0] == "type":
                            # TODO: more formally represnt types
                            attr.value_type = prop[1]
                        elif prop[0] == "expression_local_variables":
                            attr.expr_locals = prop[1]
                        else:
                            raise p4_compiler_msg (
                                "Blackbox attribute '"+str(attr)+"' specifies unknown property '"+prop[0]+"' within blackbox type.",
                                self.filename, self.lineno
                            )

                if not attr.optional:
                    self.required_attributes.add(attr.name)

                if "type" not in specified_props:
                    raise p4_compiler_msg (
                        "Blackbox attribute '"+str(attr)+"' does not have a specified type within blackbox type.",
                        self.filename, self.lineno
                    )
                attribute_dict[attr.name] = attr
        self.attributes = attribute_dict

        # Process methods
        method_dict = OrderedDict()
        for method in self.methods:
            if method[0] in method_dict:
                raise p4_compiler_msg (
                    "Blackbox method '"+str(attr)+"' defined multiple times within blackbox type.",
                    self.filename, self.lineno
                )
            else:
                new_method = p4_method(hlir=hlir, name=method[0], parent=self, params=method[1])

                method_dict[new_method.name] = new_method
        self.methods = method_dict

        hlir.p4_blackbox_types[self.name] = self


    def build (self, hlir):
        for method in self.methods.values():
            method.build(hlir)


class p4_blackbox_instance (p4_object):
    """
    TODO
    """
    required_attributes = ["name", "blackbox_type", "attributes"]
    allowed_attributes = required_attributes + ["doc"]

    def __init__ (self, hlir, name, **kwargs):
        p4_object.__init__(self, hlir, name, **kwargs)

        if not self.valid_obj:
            return

        hlir.p4_blackbox_instances[self.name] = self

        self.methods = OrderedDict()

    def build (self, hlir):
        if self.blackbox_type not in hlir.p4_blackbox_types:
            raise p4_compiler_msg (
                "Blackbox instance '%s' is of undeclared "
                "type '%s'" % (self.name, self.blackbox_type),
                self.filename, self.lineno
            )
        else:
            self.blackbox_type = hlir.p4_blackbox_types[self.blackbox_type]

        for method in self.blackbox_type.methods.values():
            self.methods[method.name] = p4_method(
                hlir,
                method.name,
                self,
                params = method.params,
                instantiated = True
            )

        processed_attributes = OrderedDict()
        for attr_name, attr_value in self.attributes:
            if attr_name not in self.blackbox_type.attributes:
                raise p4_compiler_msg (
                    "Blackbox type '%s' does not contain an attribute "
                    "named '%s'" % (self.blackbox_type.name, attr_name),
                    self.filename, self.lineno
                )
            if attr_name in processed_attributes:
                raise p4_compiler_msg (
                    "Multiple declarations of attribute '%s' in blackbox "
                    "instance '%s'" % (attr_name, self.name),
                    self.filename, self.lineno
                )

            processed_attributes[attr_name] = hlir._resolve_object(
                self.blackbox_type.attributes[attr_name].value_type,
                attr_value
            )
        self.attributes = processed_attributes

        missing_attributes = self.blackbox_type.required_attributes - OrderedSet(self.attributes.keys())
        if len(missing_attributes) != 0:
            raise p4_compiler_msg (
                "Blackbox instance '%s' is missing required attributes: %s" % (
                    self.name, ", ".join("'%s'" % attr for attr in missing_attributes)
                ),
                self.filename, self.lineno
            )

