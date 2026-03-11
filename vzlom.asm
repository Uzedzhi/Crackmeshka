.model tiny
.code
org 100h
locals @@

; start just calls main
; it is needed so we can use @@ labels 
; inside the Main proc
Start:  call Main

; --------------------------VZLOM ZHOPI-------------------------
; this program will ask you to type in the password, which is
; hard coded in the code below. If password you type matches
; the password stated in the code, program prints
; 'Access Granted'
; if not it prints 'Access Denied'
; there are two vulnerabilities, coded specially for the opponent to hack
;   1)  password and the guess user types in the command line is hashed very easily
;       so you can see in turbodebugger, how hash function works(sums all ascii codes)
;       and just exploit it, to type incorrect password, but its hash will be equal to 
;       the correct one.
;   2)  buffer can overflow easily, as there are no checks to prevent it
;       so you can fill the password buffer with garbage and then rewrite function 
;       below it. Coincedentally, that exact function is responsible
;       for checking if you have correctly or incorrectly guessed the password
;       and prints corresponding string
; --------------------------------------------------------------
Main proc
        mov dx, offset AskUserPassword
        mov ah, 09h
        int 21h
        ; we will be using dos standart interrupt function(code is 21h)
        ; but with argument 01h in ax.
        ; 01 func in dos waits for an argument in the command line from the user
        ; and then places it in the al regex
        mov ah, 01h

        xor di, di ; di is our len of str
        @@LoopGetPass:
            ; call 01h dos interrupt func
            ; al will be ascii code of pressed key
            int 21h

            ; if pressed key is enter
            ; then leave the program
            cmp al, 0dh
            je @@LoopExit

            ; moving to the buffer pressed key
            ; so buffer contains users password
            ; and then incrementing our len(di)
            mov Buffer[di], al
            inc di
            jmp @@LoopGetPass
        @@LoopExit:
        
        ; bx = len of users password
        mov bx, di

        ; si = address of str we want to calculate hash for
        mov si, offset Buffer
        call GetHashInCx

        ; now in cx we have have of 
        ; users password
        ; and we save that hash to ax
        ; to later compare it to Correct Password Hash
        mov ax, cx

        ; getting hash of Correct Password
        mov bx, PasswordLen
        mov si, offset Password
        call GetHashInCx
        ; now in cx is Correct Password Hash

        xor bx, bx
        ; we are comparing those passwords
        ; and if they are equal, in bx is placed 1(Correct Guess)
        ; else in bx is 0(Incorrect Guess)
        cmp ax, cx
        jne @@SkipBxInc
        inc bx
        @@SkipBxInc:

        ; print if we gain access or if it is denied
        call StringPrint

        ; std dos interrupt func with 4c00h exits the program
        mov ax, 4c00h ; DIIIIE
        int 21h
endp

; ==================================DATA SEGMENT==================================

; strings when we ask user to type password, and
; when we print whether we gain access or deny it
AskUserPassword     db 'Please type your password: $'
CorrectPassword     db 'Access Granted$'
IncorrectPassword   db 'Access denied$'

; hard coded password and its len
Password            db 'CanYouGuess$'
PasswordLen         dw 11d

; buffer which can overflow 
; it is supposed to contain the password,
; which user typed in console
Buffer              db 15 dup('$')

; ==============================END OF DATA SEGMENT===============================

;----------------------------------------------
; prints whether users password was a correct guess or no
; IN:		bx 		= 1 if password is correct, 0 if incorrect
; OUT:		prints string to the console
; Destroys:	dx, ax
;----------------------------------------------
StringPrint proc
    ; if bx = 0(incorrect) when print IncorrectPassword string
    ; else print CorrectPassword string
    test bx, bx
    je @@Incorrect

    mov dx, offset CorrectPassword
    jmp @@Exit

    @@Incorrect:
    mov dx, offset IncorrectPassword
    jmp @@Exit

    @@Exit:

    ; in dx is the address of the string we chose to print.
    ; when we call 09h dos interrupt func, which
    ; takes string address in dx, ending in '$' and prints
    ; it to the console
	mov ah, 09h	; print str
	int 21h
	ret
endp


; -------------------------------------------------
; returns hash of ds:[si] string to the cx regex
; IN:       ds:[si] - str
;           bx - the len of the str
; OUT:      cx - hash of str
; DESTR:    CX, SI, BX
; -------------------------------------------------
GetHashInCx proc
    ; cx = 0 - future hash of our str
    xor cx, cx
    xor dx, dx

    @@Loop:
        ; adds to cl ascii code of char in str
        mov dl, ds:[si]
        add cx, dx
        ; when move on to the next char
        inc si

        ; if bx is 0 it means we scanned
        ; every char in str
        ; and we can exit the Loop
        dec bx
        jz @@ExitLoop

        ; else just repeat the process
        ; with the next char
        jmp @@Loop
    @@ExitLoop:
    ret
endp

end             Start