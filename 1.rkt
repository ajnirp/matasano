;#lang racket

(require srfi/14)
; so that we have char-set:ascii and char-set->list

; zip two lists together
(define (zip xs ys)
  (cond [(empty? xs) '()]
        [(empty? ys) '()]
        [else (cons (cons (car xs) (car ys)) (zip (cdr xs) (cdr ys)))]))

; bitwise or of two characters, each of which is either #\0 or #\1
(define (bitwise-xor pair) (if (eq? (car pair) (cdr pair)) #\0 #\1))

; pad a list ls with zeroes until its length is divisible by k
; returns a list of characters
(define (pad-list ls k)
  (let* [(rem (remainder (length ls) k))
         ; pad-len = number of zeroes to put to the left of the string
         (pad-len (if (zero? rem) 0 (- k rem)))
         (padding (make-list pad-len #\0))]
    (append padding ls)))

; pad a string s with zeroes until its length is divisible by k
; returns a list of characters
(define-syntax-rule (pad s k)
  (pad-list (string->list s) k))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; http://cryptopals.com/sets/1/challenges/1/ ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (hex->bin string)
  (let [(ls (string->list string))]
    (string-join (map (λ (c) (hash-ref hexchar->binstring c)) ls) "")))

(define (bin->b64 string)
  (define (bin->b64-helper ls)
    (if (empty? ls)
        '()
        (let [(first-6 (take ls 6))
              (remaining (drop ls 6))]
          (cons (binstring->b64char first-6)
                (bin->b64-helper remaining)))))
  (list->string (bin->b64-helper (pad string 6))))

(define (hex->b64 string)
  (bin->b64 (hex->bin string)))

(define (binstring->b64char ls)
  (let [(n (string->number (list->string ls) 2))]
    (cond [(and (<= 0 n) (<= n 25)) (integer->char (+ n 65))]
          [(and (<= 26 n) (<= n 51)) (integer->char (+ n 71))]
          [(and (<= 52 n) (<= n 62)) (integer->char (- n 4))]
          [(= n 62) #\+]
          [(= n 63) #\/])))

(define hexchar->binstring
  (hash #\0 "0000" #\1 "0001" #\2 "0010" #\3 "0011" #\4 "0100" #\5 "0101" #\6 "0110" #\7 "0111" #\8 "1000" #\9 "1001" #\a "1010" #\b "1011" #\c "1100" #\d "1101" #\e "1110" #\f "1111"))

#|
(equal? "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        (hex->b64 "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
|#

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; http://cryptopals.com/sets/1/challenges/2/ ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (bin->hex string)
  (define (bin->hex-helper ls)
    (if (empty? ls)
        '()
        (let [(first-4 (take ls 4))
              (remaining (drop ls 4))]
          (cons (binstring->hexchar first-4)
                (bin->hex-helper remaining)))))
  (list->string (bin->hex-helper (pad string 4))))

(define (binstring->hexchar ls)
  (string-ref (number->string (string->number (list->string ls) 2) 16) 0))

; fixed xor of two hex buffers
; returns another hex buffer
(define (fixed-xor buf1 buf2)
  (bin->hex
    (list->string
      (fixed-xor-bin (string->list (hex->bin buf1))
                     (string->list (hex->bin buf2))))))

; fixed xor of two bin lists (of #\0's and #\1's)
; returns another bin list (of #\0's and #\1's)
(define (fixed-xor-bin bin1 bin2)
  (map bitwise-xor (zip bin1 bin2)))

#|
(equal? (fixed-xor "1c0111001f010100061a024b53535009181c"
                   "686974207468652062756c6c277320657965")
        "746865206b696420646f6e277420706c6179")
|#

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; http://cryptopals.com/sets/1/challenges/3/ ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; convert an ASCII char to a list of 8 bits, each bit written as either #\0 or #\1
(define (ascii-char->bin c)
  (pad (number->string (char->integer c) 2) 8))

; convert an ASCII string to a list of bits, each bit written as either #\0 or #\1
; each group of 8 bits represents one ASCII char
(define (ascii->bin s)
  (apply append (map ascii-char->bin (string->list s))))

; list of ASCII characters from 0 to 127
(define the-ascii-chars (reverse (char-set->list char-set:ascii)))

; s = a hex buffer, c = an ASCII character
; returns a pair (c . (f c)) where (f c) is what you get after you take a fixed-length xor
; of the binary representation of c repeated to match the length of the binary representation of s
; and decode it as an ASCII string
(define (single-character-xor s c)
  (let* [(hex-s (pad (hex->bin s) 8)) ; s converted to a list and padded with #\0's
         (len-by-8 (/ (length hex-s) 8)) ; length of this list divided by 8
         (c-bin-repeated (ascii->bin (make-string len-by-8 c)))]
    (list->string (bin->ascii-ls (fixed-xor-bin hex-s c-bin-repeated)))))

; returns a list of pairs
; each pair is (x . (f x)) where (f x) is what you get after you take a fixed-length xor
; of the binary representation of x repeated to match the length of the binary representation of s
; and decode it as an ASCII string
; x ranges over all ASCII chars
(define (single-character-xor-all s)
  (map (lambda (c) (single-character-xor s c)) the-ascii-chars))

(define (bin->ascii-ls ls)
  (if (empty? ls)
      '()
      (let [(first-8 (take ls 8))
            (remaining (drop ls 8))]
        (cons (integer->char (string->number (list->string first-8) 2))
              (bin->ascii-ls remaining)))))

(define (bin->ascii s)
  (list->string (bin->ascii-ls (pad s 8))))

; (define (decode encoded-hex-string key)
;   (let [(all-decodings (single-character-xor encoded-hex-string))]
;     (cdr (list-ref all-decodings (char->integer key)))))

#|
(let* [(encoded-hex-string "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
       (decoding (single-character-xor encoded-hex-string #\X))]
  (equal? decoding "Cooking MC's like a pound of bacon"))
|#

; todo - instead of decoding by inspection, actually do character frequency scoring

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; http://cryptopals.com/sets/1/challenges/4/ ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

