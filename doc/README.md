# How to build documentation

This document explains how to build Intel® Cryptography Primitives Library documentation locally.

## Prerequisites
To build the offline version of the documentation, the following tools must be installed:
- [Python](https://www.python.org/) 3.7.0 or higher
- [Sphinx](https://pypi.org/project/Sphinx/) 8.2.1 or higher
- [sphinx-book-theme](https://pypi.org/project/sphinx-book-theme/) 1.1.4 or higher

> **NOTE:** To avoid incompatibility between `sphinx_book_theme` and `Sphinx` versions, use [`requirements.txt`](requirements.txt) file to install guaranteed compatible combination of components.

``` bash
pip3 install -r <crypto_library>/doc/requirements.txt
```

## Build documentation

To generate HTML output of the documentation, use the following commands:

``` bash
cd <crypto_library>/doc/source/
make html
```

That's it! After the generation process is completed, open the ``<crypto_library>/doc/source/_build/html/index.html`` file.
