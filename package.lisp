(defpackage snif
  (:use :common-lisp :sb-alien)
  (:shadow :common-lisp listen close flush)
  (:export channel
           make-channel
           flush
           listen
           close
           read-frame
           write-frame
           with-channel
           promisc-mode
           set-promisc-mode
           list-all-protocols
           sniffing))
(in-package :snif)

(defvar *muffle-compiler-note* '(sb-ext:muffle-conditions sb-ext:compiler-note))

(defvar *native-endian* 
  (if (eq sb-c:*backend-byte-order* :big-endian) :big :little))
