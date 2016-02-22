#!/usr/bin/python

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

# from distutils.core import setup
from setuptools import setup


setup(
    name = 'p4_hlir',
    version = '0.9.30',
    install_requires=['ply'],
    packages=['p4_hlir','p4_hlir/hlir', 'p4_hlir/frontend',
              'p4_hlir/util', 'p4_hlir/graphs'],
    package_data = {
        'p4_hlir/frontend' : ['*.json'],
    },
    scripts = ['bin/p4-validate', 'bin/p4-shell', 'bin/p4-graphs'],
    author = 'Antonin BAS',
    author_email = 'antonin@barefootnetworks.com',
    description = 'p4_hlir: frontend for the P4 compiler',
    license = '',
    url = 'http://www.barefootnetworks.com/',
)
