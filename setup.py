# -*- coding: utf-8 -*-

import sys

import setuptools


install_requires = ['eventlet',
                    'plyvel',
                    'six',
                    'walkdir']


if sys.version_info < (3, 3):
    install_requires.append('contextlib2')


setuptools.setup(
    name="syncthang",
    version="0.1.0",
    license='MIT',
    url="https://github.com/jkoelker/syncthang",

    author="Jason Kölker",
    author_email="jason@koelker.net",

    description="A Syncthing compatible master server",
    long_description=open('README.rst').read(),

    packages=setuptools.find_packages(),
    install_requires=install_requires,

    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
    ],
)
