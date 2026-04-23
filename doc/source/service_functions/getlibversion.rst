.. _getlibversion:



GetLibVersion
=============


Returns information about the active version of the Intel® Cryptography Primitives Library software.


Syntax
------


const CryptoLibraryVersion\* cryptoGetLibVersion(void);


Include Files
-------------


``ippcp.h``


Description
-----------


This function returns a pointer to a static data structure
CryptoLibraryVersion that contains information about the current version of
the Intel® Cryptography Primitives Library software. There is no need for you to
release memory referenced by the returned pointer because it points to a
static variable. The following fields of the CryptoLibraryVersion structure
are available:


.. list-table::
   :header-rows: 0

   * - major
     - is the major number of the current library version.
   * - minor
     - is the minor number of the current library version.
   * - patch
     - is the patch number of the current library version.
   * - targetCpu
     - is the library code path.
   * - name
     - is the name of the current library version.
   * - buildDate
     - is the actual build date
   * - strVersion
     - is the string with the summary information about the current library version.



For example, if the library version is "1.0.0", library name is
"ippcp.lib", and build date is "Sep 14 2024", then the fields in this
structure are set as follows:


major = 1, minor = 0, patch = 0, targetCpu = "k1", name = "Intel® Cryptography Primitives Library (k1)",
buildDate = "Sep 14 2024", strVersion = "Intel® Cryptography Primitives Library (k1) (ver: 1.0.0 (12.0) build: Sep 13 2024)"


Example
-------


The code example below shows how to use the function cryptoGetLibVersion.


.. code-block:: cpp


   void libinfo(void) { const CryptoLibraryVersion* lib = cryptoGetLibVersion();


.. code-block:: cpp


   printf("%s %d.%d.%d\n", lib->name, lib->major, lib->minor, lib->patch);
   // or you can print the library version string
   printf("%s\n", lib->strVersion);

.. code-block:: cpp


   }


.. code-block:: cpp


Output:


``ippcp_l.lib 7.0 build 205.68``

