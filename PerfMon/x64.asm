EXTERN SystemCallbackPrint : PROC 

.CODE 
AsmSysCallStub PROC
	call SystemCallbackPrint	 
	ret
AsmSysCallStub ENDP


END