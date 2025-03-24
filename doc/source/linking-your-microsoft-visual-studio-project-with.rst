.. _linking-visual-studio-project-with-crypto-primitives-library:

Linking Your Microsoft\* Visual Studio\* Project with Intel® Cryptography Primitives Library
============================================================================================


To link your Microsoft\* Visual Studio\* IDE project with Intel® Cryptography
Primitives Library, follow these steps:


#. Set the Path for the Intel® Cryptography Primitives Library header and library files
   in Microsoft\* Visual Studio\* IDE:


   a. Right click your project, then select **Properties** >
      **Configuration Properties** > **VC++ Directories**.
   b. Select the **<Edit...>** option in drop down list of **Include
      Directories**, click the **New Line** button to add a new line and
      select the :file:`include` subdirectory of the
      :file:`<{install directory}>` folder. For example, the default
      Intel® Cryptography Primitives Library header file directory is located at
      :samp:`{<install directory>}\\include`.
   c. Select the **<Edit...>** option in drop down list of **Library
      Directories**, click the **New Line** button to add a new line and
      select the lib subdirectory of the
      :file:`<{install directory}>` folder. For example, in the
      Component Directory Layout, the default Intel® Cryptography Primitives Library
      directory is located at
      :samp:`{<install directory>}\\lib\\{<arch>}`, where
      :file:`<arch>` is :file:`intel64`. In the Unified Directory
      Layout, the default 64-bit directory is
      :samp:`{<install directory>}\\lib\\`. For more
      information on the directory layout, see :ref:`Finding
      Intel® Cryptography Primitives Library on Your System
      <finding-crypto-primitives-library-on-your-system>`.


#. Link the Intel® Cryptography Primitives Library into your project:


   a. Right click your project, then select **Properties** >
      **Configuration Properties** > **Linker** > **Input**.
   b. Select the **<Edit...>** option in drop down list of **Additional
      Dependencies** and enter the filename of the Intel® Cryptography Primitives Library
      you wish to use. For example, enter :file:`ippcp.lib`
      for dynamic linking or :file:`ippcpmt.lib` for static linking.


#. **Optional:** Add the Intel® Cryptography Primitives Library dynamic library to your
   executable environment (for DLL). You can add the path to the Intel® Cryptography
   Primitives Library dynamic-link library to your :samp:`PATH` environment
   variable permanently by following these steps:


   a. Open the **Start** menu and click the **Control Panel** icon in
      the **Windows System** group.
   b. Select **Large icons** in the **View by:** drop-down list, then
      find and click **System**.
   c. Click **Advanced system settings** in the column on the left side
      of the window.
   d. Select the **Advanced** tab and click the **Environment
      Variables...** button.
   e. Select the **Path** variable in the list of user or system
      variables and click **Edit...**.
   f. Append the path to the contents of the **Variable value** field
      and click **OK**. Component Directory Layout
      path :samp:`{<install directory>}\\redist\\{<arch>}`.
      Unified Directory Layout path for
      64-bit: :samp:`{<install directory>}\\bin\\`.


   Alternatively, to launch the Microsoft\* Visual Studio\* IDE from a
   preconfigured command line environment:


   a. Run ``{{vars.bat}}`` from the directory
      :samp:`{<install directory>}\\env\\` in a command window.
   b. Start :file:`<{Microsoft Visual Studio}>\\IDE\\devenv.exe` in the same
      command window.

