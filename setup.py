import setuptools

setuptools.setup(
    name='PyPTables',
    version='1.0.4',
    author='Jamie Cockburn',
    author_email='jamie_cockburn@hotmail.co.uk',
    packages=setuptools.find_packages(),
    url='https://github.com/daggaz/python-pyptables',
    license='LICENSE.txt',
    description='Python package for generating Linux iptables configurations.',
    long_description=open('README.rst').read(),
    keywords='iptables, firewall',
    install_requires=[
        "six",
        "nose",
        "coverage",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking :: Firewalls",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: POSIX :: Linux",
    ],
)
