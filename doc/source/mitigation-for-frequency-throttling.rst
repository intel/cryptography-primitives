.. _mitigation_frequency_throttling_channel_attack:

Mitigation for Frequency Throttling Side-Channel Attack
=======================================================

More information about the attack can be found in
`Frequency Throttling Side Channel Software Guidance for Cryptography Implementations <https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/frequency-throttling-side-channel-guidance.html>`_
and in the published paper: Chen Liu, Abhishek Chakraborty, Nikhil Chawla, Neer Roggel. 2022. Frequency Throttling Side-Channel Attack. https://arxiv.org/pdf/2206.07012.pdf

The Intel® Cryptography Primitives Library mitigation was implemented for AES Encryption and Decryption in ECB (``ippsAESDecryptECB``, ``ippsAESEncryptECB``) and GCM (``ippsAES_GCMDecrypt``, ``ippsAES_GCMEncrypt``) modes, and for AES CMAC (``ippsAES_CMACUpdate``) mode.
Developed mitigation is based on random noise injections for every fixed amount of processing data. There are three new APIs that should be used to enable the mitigation for AES.
The main difference between these APIs is that they work with different types of AES context - IppsAESSpec, IppsAES_GCMState, IppsAES_CMACState.

The general usage flow is ``GetSize -> Init -> SetupNoise -> Processing``. For example:

* **AES ECB mode**:

  * ippsAESGetSize()
  * ippsAESInit()
  * ippsAESSetupNoise()
  * ippsAESEncryptECB() / ippsAESDecryptECB()

* **AES GCM mode:**

  * ippsAES_GCMGetSize()
  * ippsAES_GCMInit()
  * ippsAES_GCMSetupNoise()

* **AES CMAC mode:**

  * ippsAES_CMACGetSize()
  * ippsAES_CMACInit()
  * ippsAES_CMACSetupNoise()

Mitigation can be enabled only explicitly by calling the corresponding ``SetupNoise`` function with a non-zero parameter ``noiseLevel`` (amount of noise injected).

The necessary level of noise depends on many factors, such as processor, code implementation, power limit setting by the attacker, etc. So during the development, a relatively safe default noise value was selected as the minimum; it covers most of the system’s configurations. The level varying by SetupNoise APIs just increases this pre-defined level.
Since these APIs already guarantee a good level of security, any of the supported levels(1-4) can be used, and the choice may be made based on the accepted performance gap.

Accordingly, to disable mitigation in the flow, the ``SetupNoise`` function should be called with noiseLevel equal to 0.

Calling ``ippsAESInit``, ``ippsAES_GCMInit``, ``ippsAES_CMACInit`` functions also reset mitigation parameters stored in the context, it also can be used to disable mitigation if it is enabled earlier.
Mitigation is available when Intel® AES New Instructions (Intel® AES-NI) or Vector AES Instructions (VAES) instructions present on the current CPU.


.. toctree::
   :maxdepth: 1

   ippsaessetupnoise
   ippsaes_gcmsetupnoise
   ippsaes_cmacsetupnoise
