;=========================================================================
; Copyright (C) 2024 Intel Corporation
;
; Licensed under the Apache License,  Version 2.0 (the "License");
; you may not use this file except in compliance with the License.
; You may obtain a copy of the License at
;
; 	http://www.apache.org/licenses/LICENSE-2.0
;
; Unless required by applicable law  or agreed  to  in  writing,  software
; distributed under  the License  is  distributed  on  an  "AS IS"  BASIS,
; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
; See the License for the  specific  language  governing  permissions  and
; limitations under the License.
;=========================================================================


; Non-executable stacks are desirable for security reasons.
; Recent Linux linkers will mark the stack as non-executable
; if and only if all the object files participating in the link
; step declare a properly configured empty "marker" section
; called `.note.GNU-stack`.

; Consider including this file into all the `*.asm` files.


%ifndef __NOEXEC_STACK_INC__
%define __NOEXEC_STACK_INC__ 1

; noexec stack
%ifdef LINUX32
  %ifndef OSX32
section .note.GNU-stack noalloc noexec nowrite progbits
  %endif
%endif

; noexec stack
%ifdef LINUX32E
  %ifndef OSXEM64T
    %ifndef _ARCH_KNC
section .note.GNU-stack noalloc noexec nowrite progbits
    %endif
  %endif
%endif

%endif ; __NOEXEC_STACK_INC__
;;;;;;;;;;;;;;;;;;;;;;;;;; End of file "noexec_stack.inc" ;;;;;;;;;;;;;;;;;;;;;;;;;;
