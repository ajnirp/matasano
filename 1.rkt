#lang racket

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

(equal? "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        (hex->b64 "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; http://cryptopals.com/sets/1/challenges/2/ ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (bin->hex-ls ls)
  (if (empty? ls)
      '()
      (let [(first-4 (take ls 4))
            (remaining (drop ls 4))]
        (cons (binstring->hexchar first-4)
              (bin->hex-ls remaining)))))

(define (bin->hex string)
  (list->string (bin->hex-ls (pad string 4))))

(define (binstring->hexchar ls)
  (string-ref (number->string (string->number (list->string ls) 2) 16) 0))

; fixed xor of two hex buffers
; returns another hex buffer
(define (fixed-xor buf1 buf2)
  (bin->hex
   (list->string
    (fixed-xor-ls (string->list (hex->bin buf1))
                  (string->list (hex->bin buf2))))))

; fixed xor of two bin lists (of #\0's and #\1's)
; returns another bin list (of #\0's and #\1's)
(define (fixed-xor-ls bin1 bin2)
  (map bitwise-xor (zip bin1 bin2)))

(equal? (fixed-xor "1c0111001f010100061a024b53535009181c"
                   "686974207468652062756c6c277320657965")
        "746865206b696420646f6e277420706c6179")

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
    (list->string (bin->ascii-ls (fixed-xor-ls hex-s c-bin-repeated)))))

(define (bin->ascii-ls ls)
  (if (empty? ls)
      '()
      (let [(first-8 (take ls 8))
            (remaining (drop ls 8))]
        (cons (integer->char (string->number (list->string first-8) 2))
              (bin->ascii-ls remaining)))))

(define (bin->ascii s)
  (list->string (bin->ascii-ls (pad s 8))))

; return a vector of counts of the following characters in
; the string s: etaoin shrdlu
(define (occurrences s)
  (define (occurrences-helper ls counts)
    (if (empty? ls)
        counts
        (begin
          (cond [(eq? (car ls) #\e) (vector-set! counts 0 (+ 1 (vector-ref counts 0)))]
                [(eq? (car ls) #\t) (vector-set! counts 1 (+ 1 (vector-ref counts 1)))]
                [(eq? (car ls) #\a) (vector-set! counts 2 (+ 1 (vector-ref counts 2)))]
                [(eq? (car ls) #\o) (vector-set! counts 3 (+ 1 (vector-ref counts 3)))]
                [(eq? (car ls) #\i) (vector-set! counts 4 (+ 1 (vector-ref counts 4)))]
                [(eq? (car ls) #\n) (vector-set! counts 5 (+ 1 (vector-ref counts 5)))]
                [(eq? (car ls) #\s) (vector-set! counts 6 (+ 1 (vector-ref counts 6)))]
                [(eq? (car ls) #\h) (vector-set! counts 7 (+ 1 (vector-ref counts 7)))]
                [(eq? (car ls) #\r) (vector-set! counts 8 (+ 1 (vector-ref counts 8)))]
                [(eq? (car ls) #\d) (vector-set! counts 9 (+ 1 (vector-ref counts 9)))]
                [(eq? (car ls) #\l) (vector-set! counts 10 (+ 1 (vector-ref counts 10)))]
                [(eq? (car ls) #\u) (vector-set! counts 11 (+ 1 (vector-ref counts 11)))])
          (occurrences-helper (cdr ls) counts))))
  (occurrences-helper (string->list s) (make-vector 12 0)))

; score a string based on its character frequencies
(define (naive-score s)
  (let [(naive-scoring (build-vector 12 (λ (x) (/ (- 12 x) 2))))
        (frequencies (occurrences s))]
    (foldl + 0 (vector->list (vector-map * naive-scoring frequencies)))))

; pick the highest scoring string from a bunch of strings
; f is the scoring function, ls is the list of (c . (single-character-xor s c))
; where c ranges over all the ascii chars
(define (highest-scorer ls f)
  (car (sort ls (λ (x y) (> (f (cdr x)) (f (cdr y)))))))

; this function will find the best decoding for a string
; first argument is a list of pairs
; each pair is (c . (scx c)) where (scx c) is the fixed-length xor
; of the binary representation of c repeated to match the length of
; the binary representation of s and decode it as an ASCII string.
; c ranges over all ASCII chars. second argument is a scoring function
(define (decode-single-char-xor s)
  (highest-scorer
   (map (lambda (c) (cons c (single-character-xor s c))) the-ascii-chars)
   naive-score))

(decode-single-char-xor "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; http://cryptopals.com/sets/1/challenges/4/ ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (read-lines input-port lines)
  (let [(line (read-line input-port))]
    (if (eq? line eof)
        lines
        (read-lines input-port (cons line lines)))))

(define (find-encoded-string filename)
  (let* [(hex-strings
          (call-with-input-file filename
            (λ (input-port) (read-lines input-port '()))))
         (decodings (map decode-single-char-xor hex-strings))]
    (highest-scorer decodings naive-score)))

;(find-encoded-string "4.txt")

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; http://cryptopals.com/sets/1/challenges/5/ ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define burning-em "Burning 'em, if you ain't quick and nimble")
(define crazy-cymbal "I go crazy when I hear a cymbal")

; take a key represented by an ASCII string, and convert it to a list
; of bits such that the length of the bit list is len
; in theory, this may not always be possible e.g. if the key is 24 bits long
; and the requested length is 100
; however, in practice, the requested length will always be a multiple of 8
; since the requested length itself will be eight times the length of
; an ASCII string which the key has to encrypt
(define (repeating-key-xor s k)
  (let* [(len-s (string-length s))
         (len-k (string-length k))
         (repeated-key (build-list len-s (λ (idx) (string-ref k (remainder idx len-k)))))
         (rep-key-bin (apply append (map ascii-char->bin repeated-key)))
         (string-bin (ascii->bin s))
         (xor-bin (fixed-xor-ls rep-key-bin string-bin))]
    (list->string (bin->hex-ls xor-bin))))

(equal? "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        (repeating-key-xor "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal" "ICE"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; http://cryptopals.com/sets/1/challenges/6/ ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; returns the number of bits
(define (hamming-distance-ls ls1 ls2)
  (define (hd-ls-helper ls1 ls2 differing-bits)
    (cond [(empty? ls1) differing-bits]
          [(empty? ls2) differing-bits]
          [(eq? (car ls1) (car ls2)) (hd-ls-helper (cdr ls1) (cdr ls2) differing-bits)]
          [else (hd-ls-helper (cdr ls1) (cdr ls2) (+ 1 differing-bits))]))
  (hd-ls-helper ls1 ls2 0))

(define (hamming-distance s1 s2)
  (hamming-distance-ls (ascii->bin s1) (ascii->bin s2)))

; test for hamming distance
; (= 37 (hamming-distance "this is a test" "wokka wokka!!!"))