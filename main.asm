INCLUDE Irvine32.inc

;###################################################################################;#
.DATA

	ChoiceStr BYTE "Enter 1 for main encryption, 2 for main decryption, 3 for bonus encryption, 4 for bonus decryption, 0 for exit...", 0
	wrongMsg BYTE "You entered invalid choice!!!", 0
	Done BYTE "Congratulations!", 0

;######################### Main Encryption Data ##############################	
	Key BYTE 50 DUP(?), 0                           ; The key
	mainKeyCount DWORD 0                            ; The length of key

	Letters BYTE "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 0    ; The alphapetical letters
	concKey BYTE 100 dup(?), 0                      ; String takes the key+letters
	concCount DWORD 0                               ; The length of concatenated key
	keyDistinct BYTE 25 dup(?), 0                   ; The 25's string without j's or spaces and distinct

	oMsg BYTE 1000 DUP(?), 0                        ; The original message
	mainOMsgCount DWORD 0                           ; The length of original message
	oMsgNew BYTE 1000 dup(?), 0                     ; The original message after removing the spaces
	
	Q BYTE ?                                        ; For comparing the last char for stopping condition in DistinctString PROC	
	
	Letter BYTE ?                                   ; Current letter
	Letter1_I BYTE 0                                ; Position I for letter 1
	Letter1_J BYTE 0                                ; Position J for letter 1
	Letter2_I BYTE 0                                ; Position I for letter 2
	Letter2_J BYTE 0                                ; Position J for letter 2
	letterCount BYTE 0                              ; Index of letter
	
	TheSize BYTE 5                                  ; Array size
	
	eMsg BYTE 1000 dup(?), 0                        ; The encrypted msg
	eMsgCount DWORD 0                               ; The length of encrypted message

	oFileName byte "Original Message.txt", 0
	eFileName byte "Encrypted Message.txt", 0
	dFileName byte "Decrypted Message.txt", 0
	oBonusFileName byte "Original Bonus Message.txt", 0
	eBonusFileName byte "Encrypted Bonus Message.txt", 0
	dBonusFileName byte "Decrypted Bonus Message.txt", 0

	buffer BYTE 1050 DUP(?), 0
	fileHandle HANDLE ?
	buffer_size byte ?

;######################### Main Decryption Data ##############################	
	strKey byte "Enter the key: ", 0

;######################### Bonus Data #############################
	KeyIndex byte 0
	PlainTextIndex byte 0 
	Space byte ' '
	keyCount DWORD 0
	PlainTextCount byte 0
	
;################################################################################################;#

.code
main PROC

	TheChoice:
		MOV edx, OFFSET ChoiceStr
		CALL WriteString
		CALL CRLF

		CALL ReadDec

	TheExit:
		CMP eax, 0
		JNE MainEncryption
		exit

	MainEncryption:
		CMP eax, 1
		JNE MainDecryption
		CALL MainEncryptionStart
		JMP endProj

	MainDecryption:
		CMP eax, 2
		JNE BonusEncryption
		CALL MainDecryptionStart
		JMP endProj

	BonusEncryption:
		CMP eax, 3
		JNE BonusDecryption
		CALL BonusEncryptionStart
		JMP endProj

	BonusDecryption:
		CMP eax, 4
		JNE WrongChoice
		CALL BonusDecryptionStart
		JMP endProj

	WrongChoice:
		MOV edx, OFFSET wrongMsg
		CALL WriteString
		CALL CRLF

	endProj:
		; Congratulations Message
		MOV edx, OFFSET Done
		CALL WriteString
		CALL CRLF

	exit
main ENDP

;######################### Main Encryption Code ##############################	
;
;----------------------------------------------------------
; The main of Playfair Ciphering encryption
;----------------------------------------------------------
MainEncryptionStart PROC

		MOV edx, OFFSET oFilename
		CALL getFile

		MOV edi, OFFSET key
		MOV esi, OFFSET oMsg
		call SeparateBuffer
		MOV mainKeyCount, ebp
		MOV mainOMsgCount, ebx

		CALL FinalKey
		
		MOV edi, OFFSET oMsg
		MOV ecx, mainOMsgCount
		CALL ConvertJI

		MOV edi, OFFSET oMsg
		MOV esi, OFFSET oMsgNew
		MOV ecx, mainOMsgCount
		CALL RemoveSpaces

		MOV edx , OFFSET oMsgNew
		MOV ecx , mainOMsgCount
		CALL UpperCase

		CALL GetLetters

		MOV esi, OFFSET eMsg
		MOV ecx, eMsgCount
		MOV buffer_size, cl
		MOV edx, OFFSET eFilename
		CALL setFile

	RET
MainEncryptionStart ENDP

;
;----------------------------------------------------------
; Opens the file and gets its content and size
; Recieves: EDX Contains the filename (input)
; Returns: buffer_size and buffer
;----------------------------------------------------------
getFile PROC
		
		CALL OpenInputFile
		MOV fileHandle, eax

		MOV edx, OFFSET buffer
		MOV ecx, 1050
		CALL ReadFromFile
		MOV buffer_size, al

	close_file:
		MOV eax, fileHandle
		CALL CloseFile
		
	RET
getFile ENDP

;
;----------------------------------------------------------
; Creates a new file with new string
; Recieves: EDX Contains the filename
;	ESI Contains the string to be written
;	Buffer_Size Contains the length of the string
;----------------------------------------------------------
setFile PROC

		CALL CreateOutputFile
		MOV fileHandle, eax
		
		MOV edx, OFFSET buffer
		MOVZX ecx, buffer_size

	putToBuffer:
		MOV al, [esi]
		MOV [edx], al
		INC esi
		INC edx
	LOOP putToBuffer

		MOV eax, fileHandle
		MOV edx, OFFSET buffer
		MOVZX ecx, buffer_size
		CALL WriteToFile
		CALL CloseFile

	RET
setFile ENDP

;
;----------------------------------------------------------
; Separates the buffer into two strings
; Recieves: EDI Refers to the first string
;	ESI Refers to the second string
; Returns: EBP Contains the length of first string
;	EBX Contains the length of second string
;----------------------------------------------------------
SeparateBuffer PROC
		MOV edx, OFFSET buffer
		MOVZX ecx, buffer_size
		MOV ebp, 0

	keyLoop:
		MOV al, [edx]
		INC edx
		CMP al, 10
		JE finishKey

		CMP al, 13
		JE finishKey

		MOV [edi], al
		INC edi
		INC ebp

		next:
	LOOP keyLoop

	finishKey:
		MOVZX ebx, buffer_size
		SUB ebx, ebp
		SUB ebx, 2
		MOV ecx, ebx
		INC edx

	oMsgLoop:
		MOV al, [edx]
		MOV [esi], al
		INC esi
		INC edx
	LOOP oMsgLoop

	RET
SeparateBuffer ENDP

;
;----------------------------------------------------------
; Turns the simple key into final key for the algorithm
; Returns: 1D Array consists of 25 letter
;----------------------------------------------------------
FinalKey PROC
		CALL ConcatenateStrings

		MOV edx , OFFSET concKey
		MOV ecx , concCount
		CALL UpperCase

		MOV edi, OFFSET concKey
		MOV ecx, concCount
		CALL ConvertJI
		CALL DistinctString 
	RET
FinalKey ENDP

;
;----------------------------------------------------------
; Takes two strings (key and letters) and 
; Returned them concatenated in another string
; ESI points to concKey
; EDI points to the string needs to be concatenated (key then letters)
; ECX for the loops
;----------------------------------------------------------
ConcatenateStrings PROC

		MOV esi, OFFSET concKey
		MOV edi, OFFSET key
		MOV ecx, mainKeyCount
		MOV concCount, 0

		keyLoop:
			MOV al, [edi]
			MOV [esi], al
			INC edi
			INC esi
			INC concCount
		LOOP keyLoop

		MOV edi, OFFSET letters
		MOV ecx, LENGTHOF letters

		lettersLoop:
			MOV al, [edi]
			MOV [esi], al
			INC edi
			INC esi
			INC concCount
		LOOP lettersLoop
	RET
ConcatenateStrings ENDP

;
;----------------------------------------------------------
; Takes a string and converts J's into I's
; Returned the converted string in the original one
;----------------------------------------------------------
ConvertJI PROC
		
	contLoop:
		MOV al, [edi]
		CMP al, 'j'
		jne ifJ
		
		MOV al, 'I'
		MOV [edi], al
		JMP cont

	ifJ:
		CMP al, 'J'
		jne cont

		MOV al, 'I'
		MOV [edi], al

	cont:
		INC edi
	LOOP contLoop
		
	RET
ConvertJI ENDP

;
;----------------------------------------------------------
; Removes all spaces from original message string (oMsg)
; Returned the updated string in another one (oMsgNew)
; Creates original message's counter (oMsgCounter)
;----------------------------------------------------------
RemoveSpaces PROC

	MOV mainOMsgCount, 0
	RSLoop:
		MOV al, [edi]
		CMP al, ' '
		JE cont

		MOV [esi], al
		INC esi
		INC mainOMsgCount

	cont:
		INC edi
	LOOP RSLoop

	RET
RemoveSpaces ENDP

;
;----------------------------------------------------------
; Returns the key without spaces and distinct
; String returned in keyDistinct
; EDI points to the original key
; EDX points to the distinct key
; ECX stops the loop
;----------------------------------------------------------
DistinctString PROC

		MOV edi, OFFSET concKey
		MOV edx, OFFSET keyDistinct
		MOV ecx, concCount
		INC ecx

	cmpLoop:
		CMP ecx, 0
		JE endLoop

		MOV al, [edi]
		CMP al, ' '
		JE isDistinct

		MOV al, [edx]
		CMP al, Q
		JE putChar

		CMP al, [edi]
		JNE cont

	isDistinct:
		INC edi
		DEC ecx
		MOV edx, OFFSET keyDistinct
		JMP cmpLoop

	cont:
		INC edx
		JMP cmpLoop
	
	putChar:
		MOV al, [edi]
		MOV [edx], al
		INC edi
		DEC ecx
		MOV edx, OFFSET keyDistinct
		JMP cmpLoop
	
	endLoop:

	RET
DistinctString ENDP

;
;----------------------------------------------------------
; Converts every character in a string to its upper case
; Returns the updated string in the same one
;----------------------------------------------------------
UpperCase PROC USES edi edx ecx eax

	UCLoop:
		MOV al, [edx]
		CMP al, Space
		JE dont
		AND BYTE PTR[edx], 11011111b

		dont:
			INC edx 
	LOOP UCLoop

	RET
UpperCase ENDP

;
;----------------------------------------------------------
; Loops on the original message
; And gets every two characters respectively
; Puts X between two identical characters
; How 2D array plays :')
; 0  1  2  3  4
; 5  6  7  8  9
; 10 11 12 13 14
; 15 16 17 18 19
; 20 21 22 23 24
; Row = Number/5
; Column = Remainder
;----------------------------------------------------------
GetLetters PROC

		MOV edi, OFFSET oMsgNew
		MOV ecx, mainOMsgCount
		
	whileLoop:
		MOV al, [edi]
		MOV letter, al
		INC edi

		CALL GetPositions
		MOV Letter1_I, al
		MOV Letter1_J, ah
		
		CMP ecx, 1
		JE addX

		MOV al, [edi]
		CMP al, letter
		JNE intX
	
	addX:
		MOV al, 'X'
		DEC edi
		INC ecx

	intX:
		MOV letter, al
		INC edi
		CALL GetPositions
		MOV Letter2_I, al
		MOV Letter2_J, ah

		dec ecx
		CALL Rules
	LOOP whileLoop
	
	RET
GetLetters ENDP

;
;----------------------------------------------------------
; Identify character's coordinates.
;----------------------------------------------------------
GetPositions PROC Uses ecx
		
		MOV esi, OFFSET keyDistinct
		MOV ecx, 25
		MOV letterCount, 0

	LetterLoop:
		MOV al, [esi]
		CMP al, letter
		JE getLetter
		INC esi
		INC letterCount
	LOOP LetterLoop

	getLetter:
		MOV edx, 0
		MOVZX ax, letterCount
		DIV TheSize
		
	RET
GetPositions ENDP

;
;----------------------------------------------------------
; Determines which rule to be implemented (Column, Row, Rectangle)
; Then set the letters to be encrypted
;----------------------------------------------------------
Rules PROC Uses esi ecx edi
	
	SameColumn:
		MOV al, letter1_J
		CMP al, letter2_J
		JNE SameRow
	
		CALL ColumnRule
		JMP endRules

	SameRow:
		MOV al, letter1_I
		CMP al, letter2_I
		JNE Rectangle

		CALL RowRule
		JMP endRules

	Rectangle:
		MOV bl, letter2_J
		MOV dl, letter1_J
		MOV letter1_J, bl
		MOV letter2_J, dl
		CALL SetLetters

	endRules:

	RET
Rules ENDP

;
;----------------------------------------------------------
; Implementing the column rule
;----------------------------------------------------------
ColumnRule PROC
		; Letter 1
		MOV al, letter1_I
		CMP al, 4
		JNE changeRow1

	ChangeRow1ToZero:
		MOV letter1_I, 0
		JMP Letter2Row

	ChangeRow1:
		INC letter1_I

	Letter2Row:    ; Letter 2
		MOV al, letter2_I
		CMP al, 4
		JNE changeRow2

	ChangeRow2ToZero:
		MOV letter2_I, 0
		CALL SetLetters
		JMP next

	ChangeRow2:
		INC letter2_I
		CALL SetLetters

	next:
	RET
ColumnRule ENDP

;
;----------------------------------------------------------
; Implementing the row rule
;----------------------------------------------------------
RowRule PROC
		; Letter 1
		MOV al, letter1_J
		CMP al, 4
		JNE changeColumn1

	ChangeColumn1ToZero:
		MOV letter1_J, 0
		JMP Letter2Column

	ChangeColumn1:
		INC letter1_J

	; Letter 2
	Letter2Column:    
		MOV al, letter2_J
		CMP al, 4
		JNE changeColumn2

	ChangeColumn2ToZero:
		MOV letter2_J, 0
		CALL SetLetters
		JMP next

	ChangeColumn2:
		INC letter2_J
		CALL SetLetters

	next:
	RET
RowRule ENDP

;
;----------------------------------------------------------
; Set the letters after implementing the rule
; Put the encrypted letters in eMsg array
;----------------------------------------------------------
SetLetters PROC Uses esi edi eax ebx

		MOV edi, OFFSET eMsg
		MOV esi, OFFSET keyDistinct

		MOV al, letter1_I
		MUL TheSize
 		ADD al, letter1_J
		MOVZX ebx, al
		ADD esi, ebx
		MOV al, [esi]        ; The encrypted letter
		MOV ebx, eMsgCount
		ADD edi, ebx
		MOV [edi], al        ; Put the result
		INC eMsgCount        ; The result Counter

		MOV edi, OFFSET eMsg
		MOV esi, OFFSET keyDistinct

		MOV al, letter2_I
		MUL TheSize
		ADD al, letter2_J
		MOVZX ebx, al
		ADD esi, ebx
		MOV al, [esi]        ; The encrypted letter
		MOV ebx, eMsgCount
		ADD edi, ebx
		MOV [edi], al        ; Put the result
		INC eMsgCount        ; The result Counter

	RET
SetLetters ENDP

;######################### Main Decryption Code ##############################	
;
;----------------------------------------------------------
; The main of Playfair Ciphering decryption
;----------------------------------------------------------
MainDecryptionStart PROC
		MOV edx, OFFSET strKey
		CALL WriteString 

		MOV edx, OFFSET key
		MOV ecx, LENGTHOF key
		CALL ReadString 
		MOV mainKeyCount, eax

		CALL FinalKey
		
		MOV edx, OFFSET eFilename
		CALL getFile

		MOV esi, OFFSET eMsg
		MOV edx, OFFSET buffer
		MOVZX ecx, buffer_size
		MOV eMsgCount, ecx
		
	changeLoop:
		MOV al, [edx]
		MOV [esi], al
		INC edx
		INC esi
	LOOP changeLoop
	
		CALL GetLettersEncrypted

		MOV esi, OFFSET oMsg
		MOV ecx, mainOMsgCount
		MOV buffer_size, cl
		MOV edx, OFFSET dFilename
		CALL setFile

	RET
MainDecryptionStart ENDP

;
;----------------------------------------------------------
; Loops on the encrypted message
; And gets every two characters respectively
; How 2D array plays :')
; 0  1  2  3  4
; 5  6  7  8  9
; 10 11 12 13 14
; 15 16 17 18 19
; 20 21 22 23 24
; Row = Number/5
; Column = Remainder
;----------------------------------------------------------
GetLettersEncrypted PROC

		MOV edi, OFFSET eMsg
		MOV ecx, eMsgCount

	whileLoop:
		MOV al, [edi]
		MOV letter, al
		INC edi
		CALL GetPositions
		MOV Letter1_I, al
		MOV Letter1_J, ah

		MOV al, [edi]
		MOV letter, al
		INC edi
		CALL GetPositions
		MOV Letter2_I, al
		MOV Letter2_J, ah
		DEC ecx
		CALL DecryptionRules
	LOOP whileLoop	

	RET
GetLettersEncrypted ENDP

;
;----------------------------------------------------------
; Determines which rule to be implemented (Column, Row, Rectangle)
; Then set the letters to be decrypted
;----------------------------------------------------------
DecryptionRules PROC Uses esi ecx edi
	
	SameColumn:
		MOV al, letter1_J
		CMP al, letter2_J
		JNE SameRow
	
		CALL DecryptionColumnRule
		JMP endRules

	SameRow:
		MOV al, letter1_I
		CMP al, letter2_I
		JNE Rectangle

		CALL DecryptionRowRule
		JMP endRules

	Rectangle:
		MOV bl, letter2_J
		MOV dl, letter1_J
		MOV letter1_J, bl
		MOV letter2_J, dl
		CALL SetLettersDecrypted

	endRules:

	RET
DecryptionRules ENDP

;
;----------------------------------------------------------
; Implementing the decryption column rule
;----------------------------------------------------------
DecryptionColumnRule PROC
	; Letter 1
		MOV al, letter1_I
		CMP al, 0
		JNE changeRow1

	ChangeRow1ToZero:
		MOV letter1_I, 4
		JMP Letter2Row

	ChangeRow1:
		DEC letter1_I
	
	Letter2Row:    ; Letter 2
		MOV al, letter2_I
		CMP al, 0
		JNE changeRow2

	ChangeRow2ToZero:
		MOV letter2_I, 4
		CALL SetLettersDecrypted
		JMP next

	ChangeRow2:
		dec letter2_I
		CALL SetLettersDecrypted

	next:

	RET
DecryptionColumnRule endp

;
;----------------------------------------------------------
; Implementing the decryption row rule
;----------------------------------------------------------
DecryptionRowRule PROC
	; Letter 1
		MOV al, letter1_J
		CMP al, 0
		JNE changeColumn1

	ChangeColumn1ToZero:
		MOV letter1_J, 4
		JMP Letter2Column

	ChangeColumn1:
		dec letter1_J

	; Letter 2
	Letter2Column:    
		MOV al, letter2_J
		CMP al, 0
		JNE changeColumn2

	ChangeColumn2ToZero:
		MOV letter2_J, 4
		CALL SetLettersDecrypted
		JMP next

	ChangeColumn2:
		dec letter2_J
		CALL SetLettersDecrypted

	next:
	RET
DecryptionRowRule endp

;
;----------------------------------------------------------
; Set the letters after implementing the rule
; Put the decrypted letters in oMsg array
;----------------------------------------------------------
SetLettersDecrypted PROC Uses esi edi eax ebx

		MOV edi, OFFSET oMsg
		MOV esi, OFFSET keyDistinct

		MOV al, letter1_I
		MUL TheSize
		ADD al, letter1_J
		MOVZX ebx, al
		ADD esi, ebx
		MOV al, [esi]
		MOV ebx, mainOMsgCount 
		ADD edi, ebx
		MOV [edi], al        ; Put the result == letter 
		INC mainOMsgCount                ; The result Counter

		MOV edi, OFFSET oMsg
		MOV esi, OFFSET keyDistinct

		MOV al, letter2_I
		MUL TheSize
		ADD al, letter2_J
		MOVZX ebx, al
		ADD esi, ebx
		MOV al, [esi]        ; The dencrypted letter
		MOV ebx, mainOMsgCount
		ADD edi, ebx
		MOV [edi], al        ; Put the result
		INC mainOMsgCount                ; The result Counter

	RET
SetLettersDecrypted ENDP

;################################################################################################;#
          ;######################### Bonus Encryption Code ##############################	
;
;----------------------------------------------------------
; The main of Vingere encryption
;----------------------------------------------------------
BonusEncryptionStart PROC
		
		MOV edx, OFFSET oBonusFilename
		CALL getFile

		MOV edi, OFFSET key
		MOV esi, OFFSET oMsg
		CALL SeparateBuffer
		MOV mainKeyCount, ebp
		MOV mainOMsgCount, ebx

		MOV edx, OFFSET key
		MOV ecx, mainKeyCount
		CALL UpperCase

		MOV edx, OFFSET oMsg
		MOV ecx, mainOMsgCount
		CALL UpperCase

		MOV edx, OFFSET oMsg
		MOV edi, OFFSET key
		MOV ecx, mainOMsgCount

	Convert:  
		MOV al, [edx]
		CMP al, Space
		JNZ L3
		CALL PutSpace
		INC edx
		JMP L4 

	L3:
		CALL FindIndex
		MOV PlainTextIndex, bl  
		INC edx
		INC PlainTextCount
  
		MOV al, [edi]
		CALL FindIndex
		MOV KeyIndex, bl 
		INC edi 

		MOV ebp, mainKeyCount
		DEC ebp
		CMP KeyCount, ebp
		JNZ Con
		MOV KeyCount, 0
		MOV edi, OFFSET key
		JMP Con2

	Con:
		INC KeyCount 
	
	Con2:
		MOVZX ax, PlainTextIndex
		MOVZX bx, KeyIndex
		ADD ax, bx
		MOV bl, 26
		DIV bl
		CALL FindChar
	
	L4:
	LOOP Convert
	
		MOV esi, OFFSET eMsg
		MOV ecx, mainOMsgCount
		DEC ecx
		MOV buffer_size, cl
		MOV edx, OFFSET eBonusFilename
		CALL setFile

	RET
BonusEncryptionStart ENDP

;
;----------------------------------------------------------
; Searches for the position of the letter
; Recieves: AL Contains the letter
; Returns: BL Contains the position of the letter
;----------------------------------------------------------
FindIndex PROC USES ecx edx edi 
		MOV ecx, 26
		MOV ebx, OFFSET Letters 
		MOV letterCount, 0

	L1:
	    CMP al, [ebx]
		JZ L2
		INC ebx 
		INC letterCount
	LOOP L1

	L2:
	   MOV bl, letterCount
	RET
FindIndex ENDP

;
;----------------------------------------------------------
; Searches for the letter in alphabetical order
; Recieves: AH Contains the index
; Returns: The letter in the result's array
;----------------------------------------------------------
FindChar PROC USES ecx edx edi
		MOV ecx, 25 
		MOV letterCount, 0
		MOV ebx, OFFSET Letters 	
	L1:
	    CMP ah, letterCount
		JZ L2
		INC letterCount
		INC ebx
	LOOP L1

    L2:
		MOV eax, eMsgCount
		MOV dl, [ebx]
		MOV ebx, OFFSET eMsg
		MOV [ebx + eax], dl
		INC eMsgCount

	RET
FindChar ENDP

;
;----------------------------------------------------------
; Puts the space in the result message
;----------------------------------------------------------
PutSpace PROC USES ecx edx edi 
    
		MOV eax, eMsgCount
		MOV dl, Space
		MOV ebx, OFFSET eMsg
		MOV [ebx + eax], dl
		INC eMsgCount

	RET
PutSpace ENDP

;######################### Bonus Decryption Code ##############################	
;
;----------------------------------------------------------
; The main of Vingere decryption
;----------------------------------------------------------
BonusDecryptionStart PROC
		MOV edx, OFFSET strKey
		CALL WriteString 

		MOV edx, OFFSET key
		MOV ecx, LENGTHOF strKey
		CALL ReadString 
		MOV mainKeyCount, eax
		
		MOV edx, OFFSET key
		MOV ecx, mainKeyCount
		CALL UpperCase
		MOV edx, OFFSET eBonusFilename
		CALL getFile

		MOV esi, OFFSET oMsg
		MOV edx, OFFSET buffer
		MOVZX ecx, buffer_size
		MOV mainOMsgCount, ecx

	changeLoop:
		MOV al, [edx]
		MOV [esi], al
		INC edx
		INC esi
	LOOP changeLoop

		MOV edx, OFFSET oMsg         
		MOV edi, OFFSET key             
		MOV ecx, mainOMsgCount

		MOV ebp, mainKeyCount
		DEC ebp

	Convert:  
		MOV al, [edx]
		CMP al, Space                      
		JNZ L3
		CALL PutSpace				

		INC edx
		DEC ecx
		JMP Convert
  
	L3:
		CALL FindIndex               
		MOV PlainTextIndex, bl
		INC edx                        
		INC PlainTextCount
		MOV al, [edi] 
		CALL FindIndex					
		MOV KeyIndex, bl 
		INC edi 
		CMP KeyCount, ebp
		JNZ Con                           
		MOV KeyCount, 0
		MOV edi, OFFSET key
		JMP Con2

	Con:
		INC KeyCount
  
	Con2:
		MOVZX ax, PlainTextIndex
		MOVZX bx, KeyIndex
		SUB ax, bx
		CMP ax, 0                 
		JL less
  
	already:
		MOV bl, 26
		DIV bl
		JMP nx
  
	less:
		ADD ax, 26                          
		MOV ah, al
	
	nx:
		CALL FindChar
	LOOP Convert

		MOV esi, OFFSET eMsg
		MOV ecx, mainOMsgCount
		MOV buffer_size, cl
		MOV edx, OFFSET dBonusFilename
		CALL setFile
	RET
BonusDecryptionStart ENDP
;################################################################################################;#
END main