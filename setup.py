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
    name = 'p4_hlir_v1_1',
    version = '1.1.3',
    install_requires=['ply'],
    packages=['p4_hlir_v1_1','p4_hlir_v1_1/hlir', 'p4_hlir_v1_1/frontend',
              'p4_hlir_v1_1/util', 'p4_hlir_v1_1/graphs'],
    package_data = {
        'p4_hlir_v1_1/frontend' : ['*.json'],
    },
    entry_points = {
        'console_scripts': [
            'p4-1.1-validate=p4_hlir_v1_1.p4_validate:main',
            'p4-1.1-shell=p4_hlir_v1_1.p4_shell:main',
            'p4-1.1-graphs=p4_hlir_v1_1.p4_graphs:main',
        ],
    },
    author = 'Antonin BAS',
    author_email = 'antonin@barefootnetworks.com',
    description = 'p4_hlir_v1_1: frontend for the P4 v1.1 compiler',
    license = '',
    url = 'http://www.barefootnetworks.com/',
)
