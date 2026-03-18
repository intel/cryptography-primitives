.. _operation-modes:

Operation Modes
===============


The Custom Library Tool (CLT) has two operation modes:


- **Build mode** (``--generate=none`` or no ``--generate`` option): The tool automatically sets the environment and
  builds a dynamic/shared library.

- **Generation mode**: The tool generates and saves a custom build
  script using one of two dispatchers:

  - **Dynamic dispatcher** (``--generate``, ``--generate=dynamic``): Library initialization happens
    before a call of any custom dispatcher function:

    - Manually when generating a custom dispatcher script without
      building a custom library.

    - In dynamic/shared library initialization function (generated
      automatically by CLT) when building a custom library.

  - **Static dispatcher** (``--generate=static``): Enables custom dispatcher functions to
    initialize a library (if it hasn't been initialized yet) before
    the call of the dispatched function.
