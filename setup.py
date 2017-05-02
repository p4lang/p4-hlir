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

from setuptools import setup
from setuptools.command.install import install
from setuptools.command.install_scripts import install_scripts
import p4_hlir
import os
import re

SETUP_PY_PATH = os.path.dirname(__file__)

scripts = ['p4-validate', 'p4-graphs', 'p4-shell']

install_lib = None
old_install = None

class CustomInstall(install):
    def run(self):
        # in this step we simply retrieve the installation path that we need to
        # append to the PYTHONPATH dynamically
        global install_lib
        global old_install
        assert(install_lib is None)
        # we use the platform-dependent install path computed by setuptools
        install_lib = os.path.abspath(self.install_lib)
        # if a root was specified we remove it from the install path
        if self.root is not None:
            assert(install_lib.startswith(self.root))
            install_lib = install_lib[len(self.root):]
        old_install = (self.old_and_unmanageable or self.single_version_externally_managed)
        # using install.run(self) causes setuptools to ignore install_requires
        # for a complete explanation, refer to
        # https://stackoverflow.com/questions/21915469/python-setuptools-install-requires-is-ignored-when-overriding-cmdclass
        # install.run(self)
        if old_install:
            install.run(self)
        else:
            install.do_egg_install(self)

class CustomInstallScripts(install_scripts):
    def run(self):
        # in this second step we edit the scripts in place in the build
        # directory to add install_lib to the PYTHONPATH; the modified scripts
        # will be copied to the installation directory by setuptools
        assert(install_lib is not None)

        def process_one(path):
            with open(path, "r") as fin:
                # add the directory to the PYHTONPATH before the first import
                p = re.compile('(^(?!#).*import.*)', re.MULTILINE)
                text = fin.read()
                new_text = p.sub(r'import sys\n'
                                 'sys.path.append("{}")\n'
                                 '\g<1>'.format(install_lib),
                                 text, count=1)
            with open(path, "w") as fout:
                fout.write(new_text)

        if old_install:
            for s in scripts:
                process_one(os.path.join(self.build_dir, s))

        install_scripts.run(self)

setup(
    name = 'p4_hlir',
    version = '0.9.51',
    install_requires=['ply < 3.10'],
    packages=['p4_hlir','p4_hlir/hlir', 'p4_hlir/frontend',
              'p4_hlir/util', 'p4_hlir/graphs'],
    package_data = {
        'p4_hlir/frontend' : ['*.json'],
    },
    scripts = [os.path.join("bin", s) for s in scripts],
    author = 'Antonin BAS',
    author_email = 'antonin@barefootnetworks.com',
    description = 'p4_hlir: frontend for the P4 compiler',
    license = '',
    url = 'http://www.barefootnetworks.com/',
    cmdclass={'install': CustomInstall,
              'install_scripts': CustomInstallScripts},
)
